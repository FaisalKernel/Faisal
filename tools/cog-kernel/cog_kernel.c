// SPDX-License-Identifier: GPL-2.0
/*
 * FAISAL CogOS control-plane module.
 *
 * This is an experimental kernel control plane for bounded atom metadata.
 * Semantic reasoning, embeddings, model execution, and authority remain in
 * userspace. Kernel floating point is forbidden, so STI/LTI use fixed-point
 * milli-units instead of float.
 */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/refcount.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/shrinker.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define COG_DEVICE_NAME "cog_kernel"
#define COG_CLASS_NAME "cog_kernel"
#define COG_HASH_BITS 20
#define COG_NAME_MAX 256
#define COG_STI_MAX 1000000U
#define COG_LTI_MAX 1000000U
#define COG_DEFAULT_STI 1000U
#define COG_DEFAULT_LTI 1000U
#define COG_FOCUS_BOOST 10000U
#define COG_TICK_MS 10U
#define COG_MIN_ATOM_NAME 1

/* The ABI uses fixed-point milli-units: 10000 represents the requested +10.0. */
enum cog_atom_type {
	COG_ATOM_CONCEPT = 1,
	COG_ATOM_RELATION = 2,
	COG_ATOM_SENSORIMOTOR = 3,
	COG_ATOM_TYPE_MAX = COG_ATOM_SENSORIMOTOR,
};

struct cog_atom {
	u64 uuid;
	u32 type;
	char name[COG_NAME_MAX];
	u32 sti_milli;
	u32 lti_milli;
	struct hlist_node hash_node;
	struct rcu_head rcu;
	refcount_t refs;
	bool linked;
};

struct cog_learn_args {
	__u32 type;
	__u32 reserved;
	__u64 uuid;
	__u32 sti_milli;
	__u32 lti_milli;
	char name[COG_NAME_MAX];
};

struct cog_think_args {
	__u64 uuid;
	__u32 type;
	__u32 sti_milli;
	__u32 lti_milli;
	__u32 reserved;
	char name[COG_NAME_MAX];
};

struct cog_focus_args {
	__u64 uuid;
	__u32 sti_milli;
	__u32 reserved;
};

#define COG_IOC_MAGIC 0xCF
#define COG_LEARN _IOWR(COG_IOC_MAGIC, 0x01, struct cog_learn_args)
#define COG_THINK _IOWR(COG_IOC_MAGIC, 0x02, struct cog_think_args)
#define COG_FOCUS _IOWR(COG_IOC_MAGIC, 0x03, struct cog_focus_args)

static DEFINE_HASHTABLE(cog_atom_table, COG_HASH_BITS);
static DEFINE_SPINLOCK(cog_atom_lock);
static struct kmem_cache *cog_atom_cache;
static struct shrinker *cog_atom_shrinker;
static struct task_struct *cog_scheduler;
static atomic_long_t cog_atom_count = ATOMIC_LONG_INIT(0);
static dev_t cog_dev;
static struct cdev cog_cdev;
static struct class *cog_class;
static struct device *cog_device;
static bool attention_drift = true;
module_param(attention_drift, bool, 0644);
MODULE_PARM_DESC(attention_drift, "Enable bounded fixed-point attention drift (default true)");

static void cog_atom_rcu_free(struct rcu_head *rcu)
{
	struct cog_atom *atom = container_of(rcu, struct cog_atom, rcu);

	kmem_cache_free(cog_atom_cache, atom);
}

static void cog_atom_put(struct cog_atom *atom)
{
	if (atom && refcount_dec_and_test(&atom->refs))
		call_rcu(&atom->rcu, cog_atom_rcu_free);
}

static struct cog_atom *cog_atom_find(u64 uuid)
{
	struct cog_atom *atom;

	if (!uuid)
		return NULL;
	rcu_read_lock();
	hash_for_each_possible_rcu(cog_atom_table, atom, hash_node, uuid) {
		if (atom->uuid != uuid || !READ_ONCE(atom->linked))
			continue;
		if (refcount_inc_not_zero(&atom->refs)) {
			rcu_read_unlock();
			return atom;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static bool cog_valid_type(u32 type)
{
	return type >= COG_ATOM_CONCEPT && type <= COG_ATOM_TYPE_MAX;
}

static bool cog_valid_name(const char *name)
{
	size_t len;

	len = strnlen(name, COG_NAME_MAX);
	return len >= COG_MIN_ATOM_NAME && len < COG_NAME_MAX;
}

static u64 cog_new_uuid(void)
{
	u64 uuid;

	do {
		uuid = get_random_u64();
	} while (!uuid);
	return uuid;
}

static int __must_check cog_atom_insert(struct cog_atom *atom)
{
	unsigned long flags;
	struct cog_atom *existing;

	if (!atom || !atom->uuid || !cog_valid_type(atom->type) ||
	    !cog_valid_name(atom->name))
		return -EINVAL;
	spin_lock_irqsave(&cog_atom_lock, flags);
	hash_for_each_possible(cog_atom_table, existing, hash_node, atom->uuid) {
		if (existing->uuid == atom->uuid) {
			spin_unlock_irqrestore(&cog_atom_lock, flags);
			return -EEXIST;
		}
	}
	atom->linked = true;
	hash_add_rcu(cog_atom_table, &atom->hash_node, atom->uuid);
	atomic_long_inc(&cog_atom_count);
	spin_unlock_irqrestore(&cog_atom_lock, flags);
	return 0;
}

static void cog_atom_unlink_locked(struct cog_atom *atom)
{
	if (!atom || !atom->linked)
		return;
	atom->linked = false;
	hash_del_rcu(&atom->hash_node);
	atomic_long_dec(&cog_atom_count);
	cog_atom_put(atom);
}

static unsigned long cog_shrinker_count(struct shrinker *shrinker,
					struct shrink_control *sc)
{
	return max_t(long, atomic_long_read(&cog_atom_count), 0);
}

static unsigned long cog_shrinker_scan(struct shrinker *shrinker,
					struct shrink_control *sc)
{
	unsigned long flags;
	unsigned long freed = 0;
	unsigned long target = sc->nr_to_scan;

	if (!target)
		return 0;
	spin_lock_irqsave(&cog_atom_lock, flags);
	while (freed < target && atomic_long_read(&cog_atom_count) > 0) {
		struct cog_atom *atom;
		struct cog_atom *victim = NULL;
		unsigned int bucket;

		hash_for_each(cog_atom_table, bucket, atom, hash_node) {
			if (!atom->linked)
				continue;
			if (!victim || atom->sti_milli < victim->sti_milli)
				victim = atom;
		}
		if (!victim)
			break;
		cog_atom_unlink_locked(victim);
		freed++;
	}
	spin_unlock_irqrestore(&cog_atom_lock, flags);
	return freed;
}

static void cog_update_attention(void)
{
	unsigned long flags;
	struct cog_atom *atom;
	unsigned int bucket;

	if (!attention_drift)
		return;
	spin_lock_irqsave(&cog_atom_lock, flags);
	hash_for_each(cog_atom_table, bucket, atom, hash_node) {
		u32 delta = get_random_u32_below(3);

		if (get_random_u32() & 1U) {
			if (atom->sti_milli > delta)
				atom->sti_milli -= delta;
		} else if (atom->sti_milli < COG_STI_MAX - delta) {
			atom->sti_milli += delta;
		}
	}
	spin_unlock_irqrestore(&cog_atom_lock, flags);
}

static int cog_scheduler_fn(void *unused)
{
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(msecs_to_jiffies(COG_TICK_MS));
		if (kthread_should_stop())
			break;
		cog_update_attention();
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

static int cog_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	return 0;
}

static int cog_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

static long cog_ioctl_learn(unsigned long arg)
{
	struct cog_learn_args request;
	struct cog_atom *atom;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.reserved || !cog_valid_type(request.type))
		return -EINVAL;
	request.name[COG_NAME_MAX - 1] = '\0';
	if (!cog_valid_name(request.name))
		return -EINVAL;
	atom = kmem_cache_zalloc(cog_atom_cache, GFP_KERNEL);
	if (!atom)
		return -ENOMEM;
	atom->uuid = cog_new_uuid();
	atom->type = request.type;
	atom->sti_milli = COG_DEFAULT_STI;
	atom->lti_milli = COG_DEFAULT_LTI;
	strscpy(atom->name, request.name, sizeof(atom->name));
	refcount_set(&atom->refs, 1);
	ret = cog_atom_insert(atom);
	if (ret) {
		kmem_cache_free(cog_atom_cache, atom);
		return ret;
	}
	request.uuid = atom->uuid;
	request.sti_milli = atom->sti_milli;
	request.lti_milli = atom->lti_milli;
	if (copy_to_user((void __user *)arg, &request, sizeof(request))) {
		unsigned long flags;

		spin_lock_irqsave(&cog_atom_lock, flags);
		cog_atom_unlink_locked(atom);
		spin_unlock_irqrestore(&cog_atom_lock, flags);
		return -EFAULT;
	}
	return 0;
}

static long cog_ioctl_think(unsigned long arg)
{
	struct cog_think_args request;
	struct cog_atom *atom;
	unsigned long flags;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.reserved)
		return -EINVAL;
	atom = cog_atom_find(request.uuid);
	if (!atom)
		return -ENOENT;
	spin_lock_irqsave(&cog_atom_lock, flags);
	request.type = atom->type;
	request.sti_milli = atom->sti_milli;
	request.lti_milli = atom->lti_milli;
	strscpy(request.name, atom->name, sizeof(request.name));
	spin_unlock_irqrestore(&cog_atom_lock, flags);
	cog_atom_put(atom);
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static long cog_ioctl_focus(unsigned long arg)
{
	struct cog_focus_args request;
	struct cog_atom *atom;
	unsigned long flags;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.reserved)
		return -EINVAL;
	atom = cog_atom_find(request.uuid);
	if (!atom)
		return -ENOENT;
	spin_lock_irqsave(&cog_atom_lock, flags);
	if (atom->sti_milli > COG_STI_MAX - COG_FOCUS_BOOST)
		atom->sti_milli = COG_STI_MAX;
	else
		atom->sti_milli += COG_FOCUS_BOOST;
	request.sti_milli = atom->sti_milli;
	spin_unlock_irqrestore(&cog_atom_lock, flags);
	cog_atom_put(atom);
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static long cog_unlocked_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	if (_IOC_TYPE(cmd) != COG_IOC_MAGIC || _IOC_NR(cmd) < 0x01 ||
	    _IOC_NR(cmd) > 0x03 || _IOC_SIZE(cmd) == 0)
		return -ENOTTY;
	switch (cmd) {
	case COG_LEARN:
		return cog_ioctl_learn(arg);
	case COG_THINK:
		return cog_ioctl_think(arg);
	case COG_FOCUS:
		return cog_ioctl_focus(arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations cog_fops = {
	.owner = THIS_MODULE,
	.open = cog_open,
	.release = cog_release,
	.unlocked_ioctl = cog_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = cog_unlocked_ioctl,
#endif
};

static int __must_check cog_init_store(void)
{
	cog_atom_cache = kmem_cache_create("cog_atom", sizeof(struct cog_atom),
					   0, SLAB_ACCOUNT, NULL);
	if (!cog_atom_cache)
		return -ENOMEM;
	cog_atom_shrinker = shrinker_alloc(0, "faisal-cog");
	if (!cog_atom_shrinker) {
		kmem_cache_destroy(cog_atom_cache);
		cog_atom_cache = NULL;
		return -ENOMEM;
	}
	cog_atom_shrinker->count_objects = cog_shrinker_count;
	cog_atom_shrinker->scan_objects = cog_shrinker_scan;
	cog_atom_shrinker->seeks = DEFAULT_SEEKS;
	shrinker_register(cog_atom_shrinker);
	return 0;
}

static void cog_destroy_store(void)
{
	struct cog_atom *atom;
	struct hlist_node *tmp;
	unsigned long flags;
	unsigned int bucket;

	if (cog_atom_shrinker) {
		shrinker_free(cog_atom_shrinker);
		cog_atom_shrinker = NULL;
	}
	spin_lock_irqsave(&cog_atom_lock, flags);
	hash_for_each_safe(cog_atom_table, bucket, tmp, atom, hash_node)
		cog_atom_unlink_locked(atom);
	spin_unlock_irqrestore(&cog_atom_lock, flags);
	rcu_barrier();
	if (cog_atom_cache) {
		kmem_cache_destroy(cog_atom_cache);
		cog_atom_cache = NULL;
	}
}

static int __init cog_kernel_init(void)
{
	int ret;

	ret = cog_init_store();
	if (ret)
		goto err_store;
	ret = alloc_chrdev_region(&cog_dev, 0, 1, COG_DEVICE_NAME);
	if (ret)
		goto err_device;
	cdev_init(&cog_cdev, &cog_fops);
	cog_cdev.owner = THIS_MODULE;
	ret = cdev_add(&cog_cdev, cog_dev, 1);
	if (ret)
		goto err_chrdev;
	cog_class = class_create(COG_CLASS_NAME);
	if (IS_ERR(cog_class)) {
		ret = PTR_ERR(cog_class);
		cog_class = NULL;
		goto err_cdev;
	}
	cog_device = device_create(cog_class, NULL, cog_dev, NULL, COG_DEVICE_NAME);
	if (IS_ERR(cog_device)) {
		ret = PTR_ERR(cog_device);
		cog_device = NULL;
		goto err_class;
	}
	cog_scheduler = kthread_run(cog_scheduler_fn, NULL, "cog_scheduler");
	if (IS_ERR(cog_scheduler)) {
		ret = PTR_ERR(cog_scheduler);
		cog_scheduler = NULL;
		goto err_device_node;
	}
	sched_set_fifo(cog_scheduler);
	pr_info("FAISAL CogOS module loaded major=%u minor=%u\n",
		MAJOR(cog_dev), MINOR(cog_dev));
	return 0;
err_device_node:
	device_destroy(cog_class, cog_dev);
err_class:
	class_destroy(cog_class);
	cog_class = NULL;
err_cdev:
	cdev_del(&cog_cdev);
err_chrdev:
	unregister_chrdev_region(cog_dev, 1);
err_device:
	cog_destroy_store();
err_store:
	return ret;
}

static void __exit cog_kernel_exit(void)
{
	if (cog_scheduler) {
		kthread_stop(cog_scheduler);
		cog_scheduler = NULL;
	}
	if (cog_device)
		device_destroy(cog_class, cog_dev);
	if (cog_class)
		class_destroy(cog_class);
	cdev_del(&cog_cdev);
	unregister_chrdev_region(cog_dev, 1);
	cog_destroy_store();
	pr_info("FAISAL CogOS module unloaded\n");
}

module_init(cog_kernel_init);
module_exit(cog_kernel_exit);

MODULE_AUTHOR("FAISAL Project");
MODULE_DESCRIPTION("Experimental FAISAL CogOS bounded atom control plane");
MODULE_LICENSE("GPL");
