// SPDX-License-Identifier: GPL-2.0
#include <linux/agi_lifecycle_rv.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>

#define FAISAL_RV_STRESS_WORKERS 2
#define FAISAL_RV_STRESS_REPORTS 32

static struct task_struct *faisal_rv_stress_tasks[FAISAL_RV_STRESS_WORKERS];
static atomic_t faisal_rv_stress_active;
static DECLARE_COMPLETION(faisal_rv_stress_done);

static int faisal_rv_stress_thread(void *data)
{
	unsigned int i;

	for (i = 0; i < FAISAL_RV_STRESS_REPORTS; i++) {
		agi_lc_rv_report("stall", -EIO);
		cond_resched();
	}
	if (atomic_dec_and_test(&faisal_rv_stress_active))
		complete(&faisal_rv_stress_done);
	return 0;
}

static int __init faisal_rv_bridge_stress_init(void)
{
	unsigned int i;

	atomic_set(&faisal_rv_stress_active, FAISAL_RV_STRESS_WORKERS);
	for (i = 0; i < FAISAL_RV_STRESS_WORKERS; i++) {
		faisal_rv_stress_tasks[i] = kthread_run(faisal_rv_stress_thread,
						      NULL,
						      "faisal-rv-%u", i);
		if (IS_ERR(faisal_rv_stress_tasks[i])) {
			int rc = PTR_ERR(faisal_rv_stress_tasks[i]);

			faisal_rv_stress_tasks[i] = NULL;
			while (i--)
				kthread_stop(faisal_rv_stress_tasks[i]);
			return rc;
		}
	}

	wait_for_completion(&faisal_rv_stress_done);
	return 0;
}

static void __exit faisal_rv_bridge_stress_exit(void)
{
}

module_init(faisal_rv_bridge_stress_init);
module_exit(faisal_rv_bridge_stress_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FAISAL M89 test-only concurrent RV bridge report stimulus");
