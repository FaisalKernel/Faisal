// SPDX-License-Identifier: GPL-2.0
/*
 * FAISAL lifecycle session device.
 *
 * The kernel records attribution and lifecycle state; model reasoning and
 * semantic memory remain in userspace.
 */
#include <crypto/hash.h>
#include <crypto/sha2.h>
#include <linux/agi_lifecycle.h>
#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
#include <linux/agi_lifecycle_rv.h>
#endif
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cgroup_namespace.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/sched/isolation.h>
#include <linux/faisal.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/utsname.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/numa.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/pm_qos.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/types.h>
#include <uapi/linux/sched/types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#define AGI_LC_RING_SIZE 64
#define AGI_LC_MESSAGE_SLOTS 32
#define AGI_LC_CHECKPOINT_RECORDS 64
#define AGI_LC_AGENT_RECORDS 64
#define AGI_LC_MEMORY_REGIONS 64
#define AGI_LC_MEMORY_SHARES 8
#define AGI_LC_MEMORY_REGION_MAX_BYTES (1ULL << 40)
#define AGI_LC_EXPERIENCE_RECORDS 64
#define AGI_LC_ARTIFACT_RECORDS 64
#define AGI_LC_ACCEL_DEVICES 32
#define AGI_LC_CAPABILITY_RECORDS 128
#define AGI_LC_PROVENANCE_RECORDS AGI_LC_PROVENANCE_RECORD_MAX
#define AGI_LC_IPC_CHANNELS AGI_LC_IPC_CHANNEL_MAX
#define AGI_LC_CANCEL_REQUESTS 64
#define AGI_LC_CONTEXT_RECORDS 16
#define AGI_LC_GRAPH_NODES AGI_LC_GRAPH_MAX_NODES
#define AGI_LC_NET_POLICY_RECORDS 32
#define AGI_LC_KNOWLEDGE_RECORDS_LOCAL AGI_LC_KNOWLEDGE_RECORDS
#define AGI_LC_BROWSER_SESSIONS_LOCAL AGI_LC_BROWSER_MAX_SESSIONS
#define AGI_LC_PERSISTENT_MEMORY_RECORDS_LOCAL AGI_LC_MEMORY_RECORDS
#define AGI_LC_TRANSPORT_RECORDS 32
#define AGI_LC_EXECUTION_DOMAIN_RECORDS 16
#define AGI_LC_GRAPH_TELEMETRY_RECORDS 64
#define AGI_LC_POWER_POLICY_RECORDS 16
#define AGI_LC_PROVENANCE_BINDING_RECORDS 64
#define AGI_LC_INTENT_LEASE_RECORDS 64
#define AGI_LC_AUTONOMY_RECORDS 32

struct agi_lc_lease_record {
	bool active;
	u32 resource;
	u64 lease_id;
	u64 owner_agent;
	u64 expires_ns;
};

struct agi_lc_intent_lease_record {
	bool valid;
	bool revoked;
	struct agi_lc_intent_lease lease;
};

struct agi_lc_autonomy_record {
	bool valid;
	bool closed;
	u64 owner_session;
	struct agi_lc_autonomy_control control;
};

struct agi_lc_accel_record {
	bool valid;
	struct agi_lc_accel_device device;
	u64 accounted_memory_bytes;
};

struct agi_lc_agent_record {
	bool valid;
	u64 agent_id;
	u64 parent_agent;
	pid_t owner_tgid;
	pid_t creator_pid;
	pid_t creator_tgid;
	pid_t parent_pid;
	pid_t parent_tgid;
	u32 creator_uid;
	u32 creator_euid;
	u32 priority;
	u32 state;
	u32 dependency_count;
	u32 unblock_credit;
	u64 deadline_ns;
	u32 latency_sensitive;
	u32 util_min;
	u32 util_max;
	bool resource_demand_valid;
	struct agi_lc_resource_demand resource_demand;
	bool accel_workload_valid;
	struct agi_lc_accel_workload accel_workload;
};

struct agi_lc_light_agent_record {
	bool valid;
	u64 agent_id;
	u64 parent_agent;
	u64 capability;
	pid_t creator_pid;
	pid_t creator_tgid;
	pid_t parent_pid;
	pid_t parent_tgid;
	u32 creator_uid;
	u32 creator_euid;
	u32 role;
	u32 state;
	u32 workload;
	u32 priority;
	u32 resource_mask;
	u64 event_mask;
	u64 generation;
	u64 messages_sent;
	u64 messages_received;
	u64 dropped_messages;
	u64 events_delivered;
	u64 last_event_sequence;
	u32 msg_head;
	u32 msg_tail;
	u32 msg_count;
	struct agi_lc_light_message messages[AGI_LC_LIGHT_AGENT_MAILBOX_SLOTS];
};

struct agi_lc_provenance_record {
	bool valid;
	struct agi_lc_provenance provenance;
};

struct agi_lc_ipc_message_record {
	bool valid;
	struct agi_lc_ipc_message message;
};

struct agi_lc_ipc_channel_record {
	bool valid;
	bool closed;
	u64 channel_id;
	u64 capability;
	u64 source_agent;
	u64 source_capability;
	u64 target_agent;
	u64 target_capability;
	u32 max_queue;
	u32 head;
	u32 count;
	u64 generation;
	u64 messages_sent;
	u64 messages_received;
	u64 messages_cancelled;
	u64 messages_dropped;
	struct agi_lc_ipc_message_record messages[AGI_LC_IPC_QUEUE_MAX];
};

struct agi_lc_cancel_record {
	bool valid;
	struct agi_lc_cancel_control control;
};

struct agi_lc_graph_node_record { bool valid; struct agi_lc_graph_node node; };
struct agi_lc_compute_context_record {
bool valid;
struct agi_lc_compute_context context;
u64 tasks[AGI_LC_CONTEXT_MAX_TASKS];
u64 regions[AGI_LC_CONTEXT_MAX_REGIONS];
u64 region_capabilities[AGI_LC_CONTEXT_MAX_REGIONS];
u32 region_access[AGI_LC_CONTEXT_MAX_REGIONS];
};
struct agi_lc_network_policy_record {
	bool valid;
	struct agi_lc_network_policy policy;
};

struct agi_lc_knowledge_record {
	bool valid;
	struct agi_lc_verified_knowledge knowledge;
};

struct agi_lc_browser_record {
	bool valid;
	struct agi_lc_browser_session browser;
};
struct agi_lc_persistent_memory_record {
	bool valid;
	struct agi_lc_persistent_memory memory;
};

struct agi_lc_capability_record {
	bool valid;
	struct agi_lc_capability_grant grant;
};

struct agi_lc_transport_record {
	bool valid;
	struct agi_lc_tensor_transport transport;
};

struct agi_lc_execution_domain_record {
	bool valid;
	struct agi_lc_execution_domain domain;
};
struct agi_lc_graph_telemetry_record {
	bool valid;
	struct agi_lc_graph_telemetry telemetry;
};
struct agi_lc_power_policy_record {
	bool valid;
	bool cpu_qos_active;
	struct pm_qos_request cpu_latency_qos;
	struct agi_lc_power_policy policy;
};
struct agi_lc_provenance_binding_record {
	bool valid;
	u64 owner_agent;
	struct agi_lc_provenance_binding binding;
};

struct agi_lc_memory_share_record {
	bool active;
	u64 target_agent;
	u32 access;
	u64 capability;
};

struct agi_lc_memory_record {
	bool valid;
	bool revoked;
	u64 region_id;
	u64 session_id;
	u64 owner_lineage;
	u64 owner_agent;
	pid_t owner_tgid;
	struct file *file;
	u32 flags;
	u32 access;
	u64 size_bytes;
	u64 generation;
	u64 snapshot_sequence;
	u8 snapshot_digest[AGI_LC_DIGEST_SIZE];
	u64 capability;
	bool tensor_valid;
	struct agi_lc_tensor_policy tensor;
	bool adaptive_memory_valid;
	struct agi_lc_adaptive_memory_policy adaptive_memory;
	struct agi_lc_memory_share_record shares[AGI_LC_MEMORY_SHARES];
};

struct agi_lc_experience_slot {
	bool valid;
	struct agi_lc_experience_record record;
};

struct agi_lc_checkpoint_record {
	bool valid;
	u64 checkpoint_id;

	u64 checkpoint_sequence;
	u64 parent_sequence;
	u32 phase;
	u64 event_mask;
	u64 cpu_budget_ns;
	u64 memory_limit_pages;
	u8 state_digest[AGI_LC_DIGEST_SIZE];
	bool manifest_valid;
	u32 scope_flags;
	u32 resource_policy;
	u64 lineage_id;
	u64 agent_id;
	u32 recovery_state;
	u64 recovery_sequence;
	struct agi_lc_checkpoint_manifest manifest;
};

static DEFINE_MUTEX(agi_lc_checkpoint_lock);
static DEFINE_MUTEX(agi_lc_accel_lock);
static struct agi_lc_accel_record agi_lc_accel_devices[AGI_LC_ACCEL_DEVICES];
static atomic64_t agi_lc_next_accel_device = ATOMIC64_INIT(0);
static struct agi_lc_checkpoint_record
	agi_lc_checkpoint_records[AGI_LC_CHECKPOINT_RECORDS];

#define AGI_LC_TEMPORAL_RECORDS_LOCAL 64
#define AGI_LC_REFLECTION_RECORDS_LOCAL 128

struct agi_lc_temporal_record {
	bool valid;
	struct agi_lc_temporal temporal;
};

struct agi_lc_reflection_record {
	bool valid;
	struct agi_lc_reflection reflection;
};

struct agi_lc_session {
			struct mutex ioctl_lock;
#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
		struct list_head rv_node;
		bool rv_registered;
#endif

struct mutex context_lock;
struct mutex graph_lock;
	spinlock_t queue_lock;
	wait_queue_head_t read_wait;
	wait_queue_head_t gate_wait;
	wait_queue_head_t msg_wait;
	wait_queue_head_t light_wait;
	wait_queue_head_t ipc_wait;

	struct agi_lc_record records[AGI_LC_RING_SIZE];
	struct agi_lc_attribution attributions[AGI_LC_RING_SIZE];
	struct agi_lc_message messages[AGI_LC_MESSAGE_SLOTS];
	struct agi_lc_experience_slot experiences[AGI_LC_EXPERIENCE_RECORDS];
	struct agi_lc_transport_record transports[AGI_LC_TRANSPORT_RECORDS];
	struct agi_lc_execution_domain_record execution_domains[AGI_LC_EXECUTION_DOMAIN_RECORDS];

	u32 head;
	u32 tail;
	u32 count;
	u32 msg_head;
	u32 msg_tail;
	u32 msg_count;
	u32 experience_head;
	u32 experience_count;
	u64 experience_dropped;

	u64 next_sequence;
	u64 change_generation;
	u64 failure_count;
	u64 last_failure_sequence;
	u64 session_id;
			bool sandbox_bound;
		bool tenant_budget_valid;
		struct agi_lc_tenant_budget tenant_budget;
		struct cgroup *tenant_cgroup;
		u64 tenant_cgroup_id;
		u64 tenant_cgroup_parent_id;
		u64 tenant_cgroup_generation;
		bool tenant_cpu_policy_valid;
		struct agi_lc_tenant_cpu_policy tenant_cpu_policy;
		u32 sandbox_flags;

	u32 sandbox_state;
	u64 sandbox_binding_id;
	u64 sandbox_generation;
	struct agi_lc_sandbox_binding sandbox_binding;
	u64 dropped_records;
	pid_t owner_pid;
	pid_t owner_tgid;
	bool revoked;
	bool gate_open;
	u64 event_mask;
	u64 world_class_mask;
	u64 world_lineage_id;
	u64 world_agent_id;
	u32 world_min_priority;
	u32 world_queue_policy;
	bool world_enabled;
	u64 world_delivered;
	u64 world_filtered;
	u64 world_dropped;
	u64 world_last_loss_sequence;
	bool world_resync_required;
	u64 world_ack_sequence;
	u64 world_resync_sequence;
	bool checkpoint_valid;
	u64 checkpoint_id;
	u64 checkpoint_sequence;
	u64 checkpoint_parent_sequence;
	u64 checkpoint_cpu_budget_ns;
	u64 checkpoint_memory_limit_pages;
	u32 checkpoint_phase;
	u8 checkpoint_digest[AGI_LC_DIGEST_SIZE];
	bool checkpoint_manifest_valid;
	struct agi_lc_checkpoint_manifest checkpoint_manifest;
	u32 recovery_state;
	u64 recovery_sequence;
	u64 recovery_checkpoint_id;
	u64 recovery_checkpoint_sequence;
	bool recovery_invalidated;
	u32 verification_state;
	u64 verification_checkpoint_id;
	u64 verification_checkpoint_sequence;
	u64 verification_parent_sequence;
	u8 verification_digest[AGI_LC_DIGEST_SIZE];
			struct agi_lc_lease_record leases[AGI_LC_LEASE_MAX];
		struct agi_lc_intent_lease_record intent_leases[AGI_LC_INTENT_LEASE_RECORDS];
		struct agi_lc_agent_record agents[AGI_LC_AGENT_RECORDS];

struct agi_lc_compute_context_record contexts[AGI_LC_CONTEXT_RECORDS];
	u64 next_context_id;
struct agi_lc_graph_node_record graph_nodes[AGI_LC_GRAPH_NODES];
	struct agi_lc_graph_telemetry_record graph_telemetry[AGI_LC_GRAPH_TELEMETRY_RECORDS];
	struct agi_lc_power_policy_record power_policies[AGI_LC_POWER_POLICY_RECORDS];
	struct agi_lc_provenance_binding_record provenance_bindings[AGI_LC_PROVENANCE_BINDING_RECORDS];
	struct agi_lc_capability_record capabilities[AGI_LC_CAPABILITY_RECORDS];
	struct agi_lc_provenance_record provenance[AGI_LC_PROVENANCE_RECORDS];
	struct agi_lc_ipc_channel_record *ipc_channels;
	struct agi_lc_cancel_record cancel_requests[AGI_LC_CANCEL_REQUESTS];
	struct agi_lc_network_policy_record network_policies[AGI_LC_NET_POLICY_RECORDS];
	struct agi_lc_knowledge_record knowledge_records[AGI_LC_KNOWLEDGE_RECORDS_LOCAL];
	struct agi_lc_browser_record browser_records[AGI_LC_BROWSER_SESSIONS_LOCAL];
	struct agi_lc_persistent_memory_record persistent_memory_records[AGI_LC_PERSISTENT_MEMORY_RECORDS_LOCAL];
	struct agi_lc_temporal_record temporal_records[AGI_LC_TEMPORAL_RECORDS_LOCAL];
	struct agi_lc_reflection_record reflection_records[AGI_LC_REFLECTION_RECORDS_LOCAL];
	struct agi_lc_light_agent_record *light_agents;
	u32 light_agent_count;
	u64 light_next_id;
	u64 capability_next_id;
	u64 provenance_next_id;
	u64 transport_next_id;
	u64 execution_domain_next_id;
	u64 graph_telemetry_next_id;
	u64 power_policy_next_id;
	u64 provenance_binding_next_id;
	u64 ipc_next_id;
	u64 ipc_next_message_id;
	u64 cancel_next_id;
	u64 network_policy_next_id;
	u64 knowledge_next_id;
	u64 browser_next_id;
	u64 persistent_memory_next_id;
	u64 temporal_next_id;
	u64 reflection_next_id;
	bool observability_enabled;
	u64 observability_event_mask;
	u32 observability_sample_period;
	u32 observability_sample_index;
	u32 observability_flags;
	u64 observability_emitted;
	u64 observability_filtered;
	u64 observability_sampled;
	u64 observability_dropped;
	u64 observability_last_sequence;
	u64 observability_generation;

};

static atomic64_t agi_lc_next_session = ATOMIC64_INIT(0);
#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
static LIST_HEAD(agi_lc_rv_sessions);
static DEFINE_SPINLOCK(agi_lc_rv_sessions_lock);
static atomic64_t agi_lc_rv_sequence = ATOMIC64_INIT(0);
#endif
static atomic64_t agi_lc_next_recovery = ATOMIC64_INIT(0);
static atomic64_t agi_lc_next_lease = ATOMIC64_INIT(0);
static atomic64_t agi_lc_next_intent_lease = ATOMIC64_INIT(0);
static atomic64_t agi_lc_next_memory_region = ATOMIC64_INIT(0);
static atomic64_t agi_lc_next_artifact = ATOMIC64_INIT(0);
static DEFINE_MUTEX(agi_lc_memory_lock);
static struct agi_lc_memory_record
	agi_lc_memory_records[AGI_LC_MEMORY_REGIONS];

struct agi_lc_artifact_record {
	bool valid;
	u64 owner_session_id;
	struct agi_lc_learning_artifact artifact;
};

static DEFINE_MUTEX(agi_lc_artifact_lock);
static struct agi_lc_artifact_record
	agi_lc_artifact_records[AGI_LC_ARTIFACT_RECORDS];

static DEFINE_MUTEX(agi_lc_autonomy_lock);
static struct agi_lc_autonomy_record
	agi_lc_autonomy_records[AGI_LC_AUTONOMY_RECORDS];
static atomic64_t agi_lc_next_autonomy_control = ATOMIC64_INIT(0);
static int agi_lc_push_record(struct agi_lc_session *session, u16 type,
				      s32 status, u64 correlation, u64 metadata);

static void agi_lc_sandbox_capture(struct agi_lc_sandbox_binding *binding)
{
	struct nsproxy *ns = current->nsproxy;
	struct cgroup *cgrp = task_dfl_cgroup(current);
	struct cgroup *parent = cgroup_parent(cgrp);

	binding->owner_pid = task_pid_nr(current);
	binding->owner_tgid = task_tgid_nr(current);
	binding->pid_namespace = task_active_pid_ns(current)->ns.inum;
	binding->mount_namespace = ns->mnt_ns ? from_mnt_ns(ns->mnt_ns)->inum : 0;
	binding->net_namespace = ns->net_ns ? ns->net_ns->ns.inum : 0;
	binding->ipc_namespace = ns->ipc_ns ? ns->ipc_ns->ns.inum : 0;
	binding->uts_namespace = ns->uts_ns ? ns->uts_ns->ns.inum : 0;
	binding->user_namespace = current_user_ns()->ns.inum;
	binding->cgroup_id = cgroup_id(cgrp);
	/* reserved[0] is the ABI-stable hierarchy-owner attestation slot. */
	binding->reserved[0] = parent ? cgroup_id(parent) : 0;
	/* reserved[1] pins the cgroup namespace, preventing ID confusion across namespaces. */
	binding->reserved[1] = ns->cgroup_ns ? ns->cgroup_ns->ns.inum : 0;
}

static bool agi_lc_sandbox_matches_current(
		const struct agi_lc_sandbox_binding *expected)
{
	struct agi_lc_sandbox_binding observed = { 0 };

	agi_lc_sandbox_capture(&observed);
	return observed.owner_tgid == expected->owner_tgid &&
		observed.pid_namespace == expected->pid_namespace &&
		observed.mount_namespace == expected->mount_namespace &&
		observed.net_namespace == expected->net_namespace &&
		observed.ipc_namespace == expected->ipc_namespace &&
		observed.uts_namespace == expected->uts_namespace &&
					observed.user_namespace == expected->user_namespace &&
					observed.cgroup_id == expected->cgroup_id &&
					observed.reserved[0] == expected->reserved[0] &&
					observed.reserved[1] == expected->reserved[1];

}

static bool agi_lc_tenant_cgroup_matches_current(
		const struct agi_lc_session *session)
{
	struct cgroup *current_cgroup;

	if (!session->tenant_cgroup)
		return false;
	current_cgroup = task_dfl_cgroup(current);
	return cgroup_id(current_cgroup) == session->tenant_cgroup_parent_id ||
		cgroup_is_descendant(current_cgroup, session->tenant_cgroup);
}

static int agi_lc_sandbox_validate_requirements(u32 flags,
		const struct agi_lc_sandbox_binding *binding)
{
	if (flags & ~AGI_LC_SANDBOX_FLAGS_ALL)
		return -EINVAL;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_PID_NS) && !binding->pid_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_MOUNT_NS) && !binding->mount_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_NET_NS) && !binding->net_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_IPC_NS) && !binding->ipc_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_UTS_NS) && !binding->uts_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_USER_NS) && !binding->user_namespace)
		return -EOPNOTSUPP;
	if ((flags & AGI_LC_SANDBOX_REQUIRE_CGROUP) && !binding->cgroup_id)
		return -EOPNOTSUPP;
	return 0;
}

static int agi_lc_sandbox_ioctl(struct agi_lc_session *session,
			unsigned long arg)
{
	struct agi_lc_sandbox_binding binding;
	int ret;

	if (copy_from_user(&binding, (void __user *)arg, sizeof(binding)))
		return -EFAULT;
	if (binding.size != sizeof(binding) || binding.reserved32 ||
	    binding.reserved[0] || binding.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (binding.operation == AGI_LC_SANDBOX_BIND) {
		u32 requested_flags;

		if (session->sandbox_bound)
			return -EALREADY;
		requested_flags = binding.flags;
		memset(&binding, 0, sizeof(binding));
		binding.size = sizeof(binding);
		binding.operation = AGI_LC_SANDBOX_BIND;
		binding.flags = requested_flags;
		agi_lc_sandbox_capture(&binding);
		ret = agi_lc_sandbox_validate_requirements(requested_flags,
							  &binding);
		if (ret)
			return ret;
		session->sandbox_flags = requested_flags;
		session->sandbox_state = AGI_LC_SANDBOX_STATE_BOUND;
		session->sandbox_binding_id = atomic64_inc_return(&agi_lc_next_session);
		session->sandbox_generation = 1;
		binding.state = session->sandbox_state;
		binding.status = 0;
		binding.binding_id = session->sandbox_binding_id;
		binding.generation = session->sandbox_generation;
		session->sandbox_binding = binding;
		session->sandbox_bound = true;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_SECURITY_CAPABILITY,
					 0, binding.correlation, binding.binding_id);
	} else if (binding.operation == AGI_LC_SANDBOX_QUERY) {
		if (!session->sandbox_bound)
			return -ENOENT;
		binding = session->sandbox_binding;
		binding.operation = AGI_LC_SANDBOX_QUERY;
		binding.state = agi_lc_sandbox_matches_current(&binding) ?
			AGI_LC_SANDBOX_STATE_BOUND : AGI_LC_SANDBOX_STATE_REVOKED;
		binding.status = binding.state == AGI_LC_SANDBOX_STATE_BOUND ? 0 : -EXDEV;
		ret = binding.status;
	} else if (binding.operation == AGI_LC_SANDBOX_RELEASE) {
		if (!session->sandbox_bound)
			return -ENOENT;
		if (!agi_lc_sandbox_matches_current(&session->sandbox_binding))
			return -EXDEV;
		session->sandbox_state = AGI_LC_SANDBOX_STATE_REVOKED;
		session->sandbox_generation++;
		binding = session->sandbox_binding;
		binding.operation = AGI_LC_SANDBOX_RELEASE;
		binding.state = session->sandbox_state;
		binding.status = 0;
		binding.generation = session->sandbox_generation;
		session->sandbox_binding = binding;
		session->sandbox_bound = false;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_SECURITY_CAPABILITY,
					 0, binding.correlation, binding.binding_id);
	} else {
		return -EINVAL;
	}
	if (copy_to_user((void __user *)arg, &binding, sizeof(binding)))
		return -EFAULT;
	return ret;
}

static int agi_lc_push_record(struct agi_lc_session *session, u16 type,
					      s32 status, u64 correlation, u64 metadata);
static u32 agi_lc_world_priority(u16 type, s32 status);
static void agi_lc_remove_record_locked(struct agi_lc_session *session,
						u32 index);
static u32 agi_lc_world_drop_low_locked(struct agi_lc_session *session)
{
	u32 drop_index = session->head;
	u32 lowest;
	u32 i;

	lowest = agi_lc_world_priority(session->records[drop_index].type,
					       session->records[drop_index].status);
	for (i = 1; i < session->count; i++) {
		u32 index = (session->head + i) % AGI_LC_RING_SIZE;
		u32 candidate = agi_lc_world_priority(session->records[index].type,
							 session->records[index].status);

		if (candidate < lowest) {
			lowest = candidate;
			drop_index = index;
		}
	}
	return drop_index;
}

static int agi_lc_queue_full_locked(struct agi_lc_session *session,
					      bool world_event, u32 priority,
					      u64 event_sequence,
					      bool observability_sampled_event,
					      u64 *sequence_out)
{
	u32 drop_index;

	if (world_event &&
	    session->world_queue_policy != AGI_LC_WORLD_QUEUE_DROP_NEW) {
		drop_index = session->head;
		if (session->world_queue_policy == AGI_LC_WORLD_QUEUE_DROP_LOW) {
			drop_index = agi_lc_world_drop_low_locked(session);
			if (agi_lc_world_priority(session->records[drop_index].type,
							  session->records[drop_index].status) >=
			    priority) {
				session->world_dropped++;
				session->dropped_records++;
				if (observability_sampled_event)
					session->observability_dropped++;
				session->world_last_loss_sequence = event_sequence;
				session->world_resync_required = true;
				if (sequence_out)
					*sequence_out = session->world_last_loss_sequence;
				return -EAGAIN;
			}
		}
		session->world_dropped++;
		session->dropped_records++;
		if (observability_sampled_event)
			session->observability_dropped++;
		session->world_last_loss_sequence =
			session->records[drop_index].sequence;
		session->world_resync_required = true;
		agi_lc_remove_record_locked(session, drop_index);
		return 0;
	}

	session->dropped_records++;
	if (observability_sampled_event)
		session->observability_dropped++;
	if (world_event) {
		session->world_dropped++;
		session->world_last_loss_sequence = event_sequence;
		session->world_resync_required = true;
	}
	if (sequence_out)
		*sequence_out = event_sequence;
	return -EAGAIN;
}

static int agi_lc_push_record_ex(struct agi_lc_session *session, u16 type,
					 s32 status, u64 correlation,
					 u64 metadata, u64 *sequence_out);
static struct agi_lc_agent_record *
	agi_lc_find_agent(struct agi_lc_session *session, u64 agent_id);
static u64 agi_lc_capability_mask(kernel_cap_t caps);
static struct agi_lc_accel_record *agi_lc_find_accel_locked(u64 device_id);
static struct agi_lc_provenance_record *agi_lc_find_provenance(
			struct agi_lc_session *session, u64 provenance_id, u64 action_sequence);
static struct agi_lc_capability_record *agi_lc_find_capability(
			struct agi_lc_session *session, u64 grant_id,
							u64 capability, bool include_revoked);
static u64 agi_lc_memory_new_capability(void);



static struct agi_lc_autonomy_record *
agi_lc_autonomy_find_locked(u64 control_id, u64 capability)
{
	u32 i;

	if (!control_id || !capability)
		return NULL;
	for (i = 0; i < AGI_LC_AUTONOMY_RECORDS; i++) {
		struct agi_lc_autonomy_record *record = &agi_lc_autonomy_records[i];

		if (record->valid && record->control.control_id == control_id &&
		    record->control.capability == capability)
			return record;
	}
	return NULL;
}


static void agi_lc_autonomy_expire_locked(struct agi_lc_autonomy_record *record)
{
	if (record && record->valid && !record->closed &&
	    record->control.expires_ns &&
	    ktime_get_boottime_ns() > record->control.expires_ns) {
		record->control.state = AGI_LC_AUTONOMY_STATE_FAILED;
		record->control.status = -ETIME;
		record->control.generation++;
	}
}

static bool agi_lc_autonomy_has_approval(
		const struct agi_lc_autonomy_control *control, u32 flag)
{
	if (flag == AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR)
		return control->supervisor_session != 0;
	if (flag == AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR)
		return control->operator_session != 0;
	return true;
}

static int agi_lc_autonomy_control(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_autonomy_control request;
	struct agi_lc_autonomy_record *record = NULL;
	u64 now = ktime_get_boottime_ns();
	u64 ttl;
	bool privileged = capable(CAP_SYS_ADMIN);
	int ret = 0;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || request.flags & ~AGI_LC_AUTONOMY_FLAGS_ALL ||
	    request.required_evidence_mask & ~AGI_LC_AUTONOMY_EVIDENCE_ALL ||
	    request.evidence_mask & ~AGI_LC_AUTONOMY_EVIDENCE_ALL ||
	    request.reserved32 || request.reserved[0] || request.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;

	mutex_lock(&agi_lc_autonomy_lock);
	if (request.operation == AGI_LC_AUTONOMY_CREATE) {
		u32 i;

		if (request.control_id || request.capability || request.owner_lineage ||
		    request.evidence_mask || request.state || request.status ||
		    !request.required_evidence_mask ||
		    !request.required_evidence_mask ||
		    request.required_evidence_mask & ~AGI_LC_AUTONOMY_EVIDENCE_ALL) {
			ret = -EINVAL;
			goto out_unlock;
		}
		ttl = request.expires_ns ? request.expires_ns :
			60ULL * 60 * 1000000000ULL;
		if (ttl > AGI_LC_AUTONOMY_MAX_TTL_NS) {
			ret = -ERANGE;
			goto out_unlock;
		}
		for (i = 0; i < AGI_LC_AUTONOMY_RECORDS; i++)
			if (!agi_lc_autonomy_records[i].valid ||
			    agi_lc_autonomy_records[i].closed)
				break;
		if (i == AGI_LC_AUTONOMY_RECORDS) {
			ret = -ENOSPC;
			goto out_unlock;
		}
		record = &agi_lc_autonomy_records[i];
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->owner_session = session->session_id;
		record->control = request;
		record->control.control_id = atomic64_inc_return(
			&agi_lc_next_autonomy_control);
		if (!record->control.control_id)
			record->control.control_id = atomic64_inc_return(
			&agi_lc_next_autonomy_control);
		record->control.capability = agi_lc_memory_new_capability();
		record->control.owner_lineage = faisal_task_get_lineage(current);
		record->control.state = AGI_LC_AUTONOMY_STATE_OBSERVE;
		record->control.status = 0;
		record->control.expires_ns = now + ttl;
		record->control.generation = 1;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_OBSERVABILITY, 0,
					request.correlation,
					record->control.control_id);
		if (ret)
			memset(record, 0, sizeof(*record));
		else
			request = record->control;
		goto out_copy;
	}

	record = agi_lc_autonomy_find_locked(request.control_id,
						request.capability);
	if (!record) {
		ret = -EACCES;
		goto out_unlock;
	}
	agi_lc_autonomy_expire_locked(record);
	if (request.operation != AGI_LC_AUTONOMY_QUERY &&
	    record->control.state == AGI_LC_AUTONOMY_STATE_FAILED &&
	    request.operation != AGI_LC_AUTONOMY_ROLLBACK) {
		ret = record->control.status ? record->control.status : -ETIME;
		goto out_unlock;
	}
	switch (request.operation) {
	case AGI_LC_AUTONOMY_RECORD_EVIDENCE:
		if (record->owner_session != session->session_id ||
		    !request.evidence_mask ||
		    (record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_SIGNED_EVIDENCE &&
		     !memchr_inv(request.evidence_digest, 0,
				 sizeof(request.evidence_digest)))) {
			if (record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_SIGNED_EVIDENCE &&
			    !memchr_inv(request.evidence_digest, 0,
					 sizeof(request.evidence_digest)))
				ret = -EKEYREJECTED;
			else
				ret = -EACCES;
			goto out_unlock;
		}
		record->control.evidence_mask |= request.evidence_mask;
		if (memchr_inv(request.evidence_digest, 0,
			       sizeof(request.evidence_digest)))
			memcpy(record->control.evidence_digest, request.evidence_digest,
			       sizeof(record->control.evidence_digest));
		record->control.generation++;
		break;
	case AGI_LC_AUTONOMY_SUPERVISOR_APPROVE:
		if (!privileged || record->owner_session == session->session_id ||
		    !(record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR)) {
			ret = -EPERM;
			goto out_unlock;
		}
		record->control.supervisor_session = session->session_id;
		record->control.generation++;
		break;
	case AGI_LC_AUTONOMY_OPERATOR_APPROVE:
		if (!privileged || record->owner_session == session->session_id ||
		    !(record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR)) {
			ret = -EPERM;
			goto out_unlock;
		}
		record->control.operator_session = session->session_id;
		record->control.generation++;
		break;
	case AGI_LC_AUTONOMY_ADVANCE:
		if (record->owner_session != session->session_id ||
		    request.state != record->control.state + 1) {
			ret = -EPERM;
			goto out_unlock;
		}
		if (request.state == AGI_LC_AUTONOMY_STATE_DIAGNOSE &&
		    !(record->control.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION)) {
			ret = -EAGAIN;
			goto out_unlock;
		}
		if (request.state == AGI_LC_AUTONOMY_STATE_PROPOSE &&
		    !(record->control.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_DIAGNOSIS)) {
			ret = -EAGAIN;
			goto out_unlock;
		}
		if (request.state == AGI_LC_AUTONOMY_STATE_VERIFY &&
		    ((record->control.evidence_mask &
		      (AGI_LC_AUTONOMY_EVIDENCE_PATCH | AGI_LC_AUTONOMY_EVIDENCE_BUILD |
		       AGI_LC_AUTONOMY_EVIDENCE_TEST | AGI_LC_AUTONOMY_EVIDENCE_FUZZ |
		       AGI_LC_AUTONOMY_EVIDENCE_SECURITY)) !=
		     (AGI_LC_AUTONOMY_EVIDENCE_PATCH | AGI_LC_AUTONOMY_EVIDENCE_BUILD |
		      AGI_LC_AUTONOMY_EVIDENCE_TEST | AGI_LC_AUTONOMY_EVIDENCE_FUZZ |
		      AGI_LC_AUTONOMY_EVIDENCE_SECURITY))) {
			ret = -EAGAIN;
			goto out_unlock;
		}
		if (request.state == AGI_LC_AUTONOMY_STATE_DEPLOY &&
		    ((record->control.evidence_mask & record->control.required_evidence_mask) !=
		     record->control.required_evidence_mask ||
		     !(record->control.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_CANARY))) {
			ret = -EAGAIN;
			goto out_unlock;
		}
		if (request.state == AGI_LC_AUTONOMY_STATE_CANARY &&
		    ((!agi_lc_autonomy_has_approval(&record->control,
			 AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR) &&
		      (record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR)) ||
		     (!agi_lc_autonomy_has_approval(&record->control,
			 AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR) &&
		      (record->control.flags & AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR)))) {
			ret = -EACCES;
			goto out_unlock;
		}
		record->control.state = request.state;
		record->control.attempt++;
		record->control.generation++;
		break;
	case AGI_LC_AUTONOMY_ROLLBACK:
		if (record->owner_session != session->session_id && !privileged) {
			ret = -EPERM;
			goto out_unlock;
		}
		record->control.state = AGI_LC_AUTONOMY_STATE_ROLLED_BACK;
		record->control.status = 0;
		record->control.generation++;
		break;
	case AGI_LC_AUTONOMY_QUERY:
		break;
	case AGI_LC_AUTONOMY_CLOSE:
		if (record->owner_session != session->session_id) {
			ret = -EPERM;
			goto out_unlock;
		}
		record->closed = true;
		record->control.state = AGI_LC_AUTONOMY_STATE_CLOSED;
		record->control.generation++;
		break;
	default:
		ret = -EINVAL;
		goto out_unlock;
	}
	request = record->control;
out_copy:
	mutex_unlock(&agi_lc_autonomy_lock);
	if (ret || copy_to_user((void __user *)arg, &request, sizeof(request)))
		return ret ? ret : -EFAULT;
	return 0;
out_unlock:
	mutex_unlock(&agi_lc_autonomy_lock);
	return ret;
}

static int agi_lc_record_experience(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_experience_record experience;
	struct agi_lc_experience_slot *slot;
	unsigned long irqflags;
	u64 last_sequence;
	u64 sequence;
	u32 index;
	int ret;

	if (copy_from_user(&experience, (void __user *)arg,
			   sizeof(experience)))
		return -EFAULT;
	if (experience.size != sizeof(experience) || experience.flags ||
	    experience.kind < AGI_LC_EXPERIENCE_ACTION ||
	    experience.kind > AGI_LC_EXPERIENCE_FAILURE ||
	    experience.verification_state || experience.experience_sequence ||
	    experience.started_at_ns || experience.finished_at_ns ||
	    experience.lineage_id ||
	    experience.agent_id || experience.pid || experience.tgid ||
	    experience.cpu_time_ns || experience.memory_bytes ||
	    experience.reserved[0] || experience.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	experience.started_at_ns = ktime_get_ns();
	experience.finished_at_ns = ktime_get_ns();
	experience.verification_state = READ_ONCE(session->verification_state);

	spin_lock_irqsave(&session->queue_lock, irqflags);
	last_sequence = session->next_sequence ? session->next_sequence - 1 : 0;
	spin_unlock_irqrestore(&session->queue_lock, irqflags);
	if (experience.parent_sequence > last_sequence)
		return -EINVAL;

	experience.lineage_id = faisal_task_get_lineage(current);
	experience.agent_id = faisal_task_get_agent(current);
	experience.pid = task_pid_nr(current);
	experience.tgid = task_tgid_nr(current);
	experience.cpu_time_ns = READ_ONCE(current->se.sum_exec_runtime);
	experience.memory_bytes = current->mm ?
		((u64)get_mm_rss(current->mm) << PAGE_SHIFT) : 0;

	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_EXPERIENCE,
				    experience.status, experience.correlation,
				    experience.parent_sequence, &sequence);
	if (ret)
		return ret;
	experience.experience_sequence = sequence;

	spin_lock_irqsave(&session->queue_lock, irqflags);
	if (session->experience_count == AGI_LC_EXPERIENCE_RECORDS) {
		session->experience_head =
			(session->experience_head + 1) % AGI_LC_EXPERIENCE_RECORDS;
		session->experience_count--;
		session->experience_dropped++;
	}
	index = (session->experience_head + session->experience_count) %
		AGI_LC_EXPERIENCE_RECORDS;
	slot = &session->experiences[index];
	slot->valid = false;
	slot->record = experience;
	slot->valid = true;
	session->experience_count++;
	spin_unlock_irqrestore(&session->queue_lock, irqflags);

	if (copy_to_user((void __user *)arg, &experience, sizeof(experience)))
		return -EFAULT;
	return 0;
}

static int agi_lc_get_experience(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_experience_query query;
	unsigned long irqflags;
	u32 i;
	int ret = 0;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.next_sequence || query.dropped || query.reserved[0] ||
	    query.reserved[1] || memchr_inv(&query.record, 0,
					 sizeof(query.record)))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, irqflags);
	if (!session->experience_count) {
		ret = -ENOENT;
		goto out_unlock;
	}
	for (i = 0; i < session->experience_count; i++) {
		u32 index = (session->experience_head + i) %
			AGI_LC_EXPERIENCE_RECORDS;
		struct agi_lc_experience_slot *slot =
			&session->experiences[index];

		if (slot->valid &&
		    (!query.experience_sequence ||
		     slot->record.experience_sequence == query.experience_sequence)) {
			query.record = slot->record;
			query.experience_sequence = slot->record.experience_sequence;
			query.dropped = session->experience_dropped;
			if (i + 1 < session->experience_count) {
				u32 next_index = (session->experience_head + i + 1) %
					AGI_LC_EXPERIENCE_RECORDS;
				query.next_sequence = session->experiences[next_index].record.experience_sequence;
			}
			goto out_unlock;
		}
	}
	ret = session->experience_dropped && query.experience_sequence <
		session->experiences[session->experience_head].record.experience_sequence ?
		-ERANGE : -ENOENT;
out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, irqflags);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return 0;
}

static bool agi_lc_experience_present_locked(
		struct agi_lc_session *session, u64 sequence)
{
	u32 i;

	for (i = 0; i < session->experience_count; i++) {
		u32 index = (session->experience_head + i) %
			AGI_LC_EXPERIENCE_RECORDS;

		if (session->experiences[index].valid &&
		    session->experiences[index].record.experience_sequence == sequence)
			return true;
	}
	return false;
}

static int agi_lc_publish_artifact(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_learning_artifact artifact;
	struct agi_lc_artifact_record *slot;
	unsigned long irqflags;
	u64 sequence;
	u64 artifact_id;
	u64 capability;
	u64 source_lineage;
	u64 source_agent;
	u32 index;
	int ret;

	if (copy_from_user(&artifact, (void __user *)arg, sizeof(artifact)))
		return -EFAULT;
	if (artifact.size != sizeof(artifact) || artifact.flags ||
	    artifact.kind < AGI_LC_LEARNING_MEMORY ||
	    artifact.kind > AGI_LC_LEARNING_MODEL_TRAINING ||
	    artifact.artifact_id ||
	    artifact.source_lineage || artifact.source_agent ||
	    artifact.created_at_ns || artifact.capability ||
	    !memchr_inv(artifact.source_digest, 0,
			 sizeof(artifact.source_digest)) ||
	    !memchr_inv(artifact.artifact_digest, 0,
			 sizeof(artifact.artifact_digest)) ||
	    artifact.reserved[0] || artifact.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, irqflags);
	if (!agi_lc_experience_present_locked(session,
					      artifact.experience_sequence)) {
		spin_unlock_irqrestore(&session->queue_lock, irqflags);
		return -ENOENT;
	}
	spin_unlock_irqrestore(&session->queue_lock, irqflags);

	artifact_id = atomic64_inc_return(&agi_lc_next_artifact);
	if (!artifact_id)
		artifact_id = atomic64_inc_return(&agi_lc_next_artifact);
	capability = get_random_u64();
	while (!capability)
		capability = get_random_u64();
	source_lineage = faisal_task_get_lineage(current);
	source_agent = faisal_task_get_agent(current);
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_EXPERIENCE, 0,
				    artifact.correlation, artifact_id, &sequence);
	if (ret)
		return ret;

	artifact.artifact_id = artifact_id;
	artifact.source_lineage = source_lineage;
	artifact.source_agent = source_agent;
	artifact.created_at_ns = ktime_get_ns();
	artifact.capability = capability;
	index = artifact.artifact_id % AGI_LC_ARTIFACT_RECORDS;
	mutex_lock(&agi_lc_artifact_lock);
	slot = &agi_lc_artifact_records[index];
	slot->valid = false;
	slot->owner_session_id = session->session_id;
	slot->artifact = artifact;
	slot->valid = true;
	mutex_unlock(&agi_lc_artifact_lock);
	if (copy_to_user((void __user *)arg, &artifact, sizeof(artifact)))
		return -EFAULT;
	return 0;
}

static int agi_lc_get_artifact(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_learning_artifact artifact;
	struct agi_lc_artifact_record *slot;
	int ret = 0;

	if (copy_from_user(&artifact, (void __user *)arg, sizeof(artifact)))
		return -EFAULT;
	if (artifact.size != sizeof(artifact) || artifact.flags ||
	    !artifact.artifact_id || !artifact.capability ||
	    artifact.reserved[0] || artifact.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	mutex_lock(&agi_lc_artifact_lock);
	slot = &agi_lc_artifact_records[artifact.artifact_id %
		AGI_LC_ARTIFACT_RECORDS];
	if (!slot->valid || slot->artifact.artifact_id != artifact.artifact_id ||
	    slot->artifact.capability != artifact.capability) {
		ret = -EACCES;
		goto out_unlock;
	}
	artifact = slot->artifact;
out_unlock:
	mutex_unlock(&agi_lc_artifact_lock);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &artifact, sizeof(artifact)))
		return -EFAULT;
	return 0;
}

static void agi_lc_artifact_release_session(struct agi_lc_session *session,
						    bool preserve)
{
	u32 i;

	if (preserve)
		return;
	mutex_lock(&agi_lc_artifact_lock);
	for (i = 0; i < AGI_LC_ARTIFACT_RECORDS; i++)
		if (agi_lc_artifact_records[i].valid &&
		    agi_lc_artifact_records[i].owner_session_id == session->session_id) {
			agi_lc_artifact_records[i].valid = false;
		}
	mutex_unlock(&agi_lc_artifact_lock);
}

static int agi_lc_manifest_digest(const struct agi_lc_checkpoint_manifest *manifest,
					 u8 digest[AGI_LC_DIGEST_SIZE])
{
	struct agi_lc_checkpoint_manifest canonical = *manifest;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	unsigned int desc_size;
	int ret;

	memset(canonical.manifest_digest, 0,
	       sizeof(canonical.manifest_digest));
	canonical.correlation = 0;
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, (u8 *)&canonical, sizeof(canonical),
				  digest);
	kfree(desc);
	crypto_free_shash(tfm);
	return ret;
}

static void agi_lc_store_checkpoint(struct agi_lc_session *session,
					    const struct agi_lc_checkpoint *checkpoint,
					    u64 sequence, u64 event_mask)
{
	struct agi_lc_checkpoint_record *record;
	u32 slot = checkpoint->checkpoint_id % AGI_LC_CHECKPOINT_RECORDS;

	mutex_lock(&agi_lc_checkpoint_lock);
	record = &agi_lc_checkpoint_records[slot];
	record->valid = false;
	record->checkpoint_id = checkpoint->checkpoint_id;
	record->checkpoint_sequence = sequence;
	record->parent_sequence = checkpoint->parent_sequence;
	record->phase = session->checkpoint_phase;
	record->event_mask = event_mask;
	record->cpu_budget_ns = session->checkpoint_cpu_budget_ns;
	record->memory_limit_pages = session->checkpoint_memory_limit_pages;
	memcpy(record->state_digest, checkpoint->state_digest,
	       sizeof(record->state_digest));
	record->manifest_valid = false;
	record->scope_flags = 0;
	record->resource_policy = 0;
	record->lineage_id = faisal_task_get_lineage(current);
	record->agent_id = faisal_task_get_agent(current);
	record->recovery_state = AGI_LC_RECOVERY_NONE;
	record->recovery_sequence = 0;
	memset(&record->manifest, 0, sizeof(record->manifest));
	record->valid = true;
	mutex_unlock(&agi_lc_checkpoint_lock);
}

static bool agi_lc_find_checkpoint(const struct agi_lc_handoff *handoff,
					 struct agi_lc_checkpoint_record *out)
{
	struct agi_lc_checkpoint_record *record;
	u32 slot = handoff->checkpoint_id % AGI_LC_CHECKPOINT_RECORDS;
	bool found = false;

	mutex_lock(&agi_lc_checkpoint_lock);
	record = &agi_lc_checkpoint_records[slot];
	if (record->valid && record->checkpoint_id == handoff->checkpoint_id) {
		*out = *record;
		found = true;
	}
	mutex_unlock(&agi_lc_checkpoint_lock);
	return found;
}

static bool agi_lc_memory_flags_valid(u32 flags)
{
	u32 valid = AGI_LC_MEMORY_REGION_WORKING |
		AGI_LC_MEMORY_REGION_SHARED |
		AGI_LC_MEMORY_REGION_PERSISTENT |
		AGI_LC_MEMORY_REGION_SNAPSHOTABLE;

	return (flags & valid) && !(flags & ~valid);
}

static bool agi_lc_memory_access_valid(u32 access)
{
	return access && !(access & ~(AGI_LC_MEMORY_ACCESS_READ |
				       AGI_LC_MEMORY_ACCESS_WRITE));
}

static u64 agi_lc_memory_new_capability(void)
{
	u64 capability;

	do
		capability = get_random_u64();
	while (!capability);
	return capability;
}

static struct agi_lc_memory_record *
agi_lc_memory_find_locked(struct agi_lc_session *session, u64 region_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_MEMORY_REGIONS; i++)
		if (agi_lc_memory_records[i].valid &&
		    agi_lc_memory_records[i].region_id == region_id &&
		    (agi_lc_memory_records[i].session_id == session->session_id ||
		     (!agi_lc_memory_records[i].session_id &&
		      (agi_lc_memory_records[i].flags &
		       AGI_LC_MEMORY_REGION_PERSISTENT))))
			return &agi_lc_memory_records[i];
	return NULL;
}

static void agi_lc_memory_destroy_locked(struct agi_lc_memory_record *record)
{
	struct file *file = record->file;

	memset(record, 0, sizeof(*record));
	if (file)
		fput(file);
}

static void agi_lc_memory_release_session(struct agi_lc_session *session,
						  bool preserve_persistent)
{
	u32 i;

	mutex_lock(&agi_lc_memory_lock);
	for (i = 0; i < AGI_LC_MEMORY_REGIONS; i++)
		if (agi_lc_memory_records[i].valid &&
		    agi_lc_memory_records[i].session_id == session->session_id) {
			struct agi_lc_memory_record *record =
				&agi_lc_memory_records[i];

			if (preserve_persistent &&
			    (record->flags & AGI_LC_MEMORY_REGION_PERSISTENT) &&
			    !record->revoked) {
				u32 j;

				record->session_id = 0;
				record->owner_lineage = 0;
				record->owner_agent = 0;
				record->owner_tgid = 0;
				for (j = 0; j < AGI_LC_MEMORY_SHARES; j++)
					record->shares[j].active = false;
			} else {
				agi_lc_memory_destroy_locked(record);
			}
		}
	mutex_unlock(&agi_lc_memory_lock);
}

static bool agi_lc_memory_authorized_agent_locked(
		struct agi_lc_session *session, struct agi_lc_memory_record *record,
		u64 capability, u32 access, u64 agent_id)
{
	u32 i;

	if (record->revoked)
		return false;
	if ((access & ~record->access) || !agi_lc_memory_access_valid(access))
		return false;
	if (!record->session_id &&
	    (record->flags & AGI_LC_MEMORY_REGION_PERSISTENT) &&
	    capability == record->capability)
		return true;
	if (faisal_task_get_lineage(current) != record->owner_lineage ||
	    session->session_id != record->session_id)
		return false;
	if (capability == record->capability &&
	    agent_id == record->owner_agent)
		return true;
	for (i = 0; i < AGI_LC_MEMORY_SHARES; i++)
		if (record->shares[i].active &&
		    record->shares[i].capability == capability &&
		    record->shares[i].target_agent == agent_id &&
		    !(access & ~record->shares[i].access))
			return true;
	return false;
}

static bool agi_lc_memory_authorized_locked(
		struct agi_lc_session *session, struct agi_lc_memory_record *record,
		u64 capability, u32 access)
{
	return agi_lc_memory_authorized_agent_locked(session, record, capability,
							 access, faisal_task_get_agent(current));
}

static struct agi_lc_persistent_memory_record *
agi_lc_persistent_memory_find(struct agi_lc_session *session, u64 record_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_PERSISTENT_MEMORY_RECORDS_LOCAL; i++)
		if (session->persistent_memory_records[i].valid &&
		    session->persistent_memory_records[i].memory.record_id == record_id)
			return &session->persistent_memory_records[i];
	return NULL;
}

static bool agi_lc_persistent_memory_digest_equal(const u8 *a, const u8 *b)
{
	return !memcmp(a, b, AGI_LC_DIGEST_SIZE);
}

static bool agi_lc_persistent_memory_owner(
	struct agi_lc_session *session,
	struct agi_lc_persistent_memory_record *record)
{
	return record && record->valid &&
		record->memory.owner_lineage == faisal_task_get_lineage(current) &&
		record->memory.owner_lineage == session->session_id &&
		record->memory.owner_agent == faisal_task_get_agent(current);
}

static bool agi_lc_persistent_memory_authorized(
	struct agi_lc_session *session,
	struct agi_lc_persistent_memory_record *record,
	u64 authority_capability)
{
	return authority_capability && record && record->valid &&
		record->memory.authority_capability == authority_capability &&
		agi_lc_persistent_memory_owner(session, record);
}

static void agi_lc_persistent_memory_expire_if_needed(
	struct agi_lc_persistent_memory *memory, u64 now)
{
	if (memory->state == AGI_LC_MEMORY_STATE_ACTIVE &&
	    memory->expires_realtime_ns &&
	    now >= memory->expires_realtime_ns) {
		memory->state = AGI_LC_MEMORY_STATE_EXPIRED;
		memory->flags |= AGI_LC_MEMORY_RECORD_FLAG_EXPIRED;
		memory->freshness_state = AGI_LC_MEMORY_EXPIRED;
		memory->expiration_count++;
		memory->generation++;
		memory->updated_realtime_ns = now;
	}
}

static int agi_lc_persistent_memory_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_persistent_memory request;
	struct agi_lc_persistent_memory_record *record = NULL;
	struct agi_lc_persistent_memory_record *related = NULL;
	u64 now = ktime_get_real_ns();
	u64 id;
	u64 conflict_id = 0;
	u32 operation;
	u32 i;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	operation = request.operation;
	if (request.size != sizeof(request) ||
	    request.operation < AGI_LC_MEMORY_RECORD_CREATE ||
	    request.operation > AGI_LC_MEMORY_RECORD_REVALIDATE ||
	    request.flags & ~AGI_LC_MEMORY_RECORD_FLAGS_ALL ||
	    request.tier > AGI_LC_MEMORY_TIER_MAX ||
	    request.state || request.conflict_state || request.reserved32 ||
	    request.confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    request.importance_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    request.freshness_state > AGI_LC_MEMORY_EXPIRED ||
	    request.correlation == 0 || request.reserved[0] || request.reserved[1] ||
	    request.expires_realtime_ns > now + AGI_LC_MEMORY_MAX_TTL_NS)

		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	if (request.operation == AGI_LC_MEMORY_RECORD_CREATE ||
	    request.operation == AGI_LC_MEMORY_RECORD_UPSERT) {
		if (!request.tier || !request.scope_id ||
		    !memchr_inv(request.content_digest, 0, sizeof(request.content_digest)) ||
		    request.record_id || request.authority_capability ||
		    request.related_record_id || request.generation ||
		    request.correction_count || request.deletion_count ||
		    request.expiration_count || request.conflict_count ||
		    request.dedup_count || request.revalidation_count)
			return -EINVAL;
	} else {
		if (!request.record_id || !request.authority_capability ||
		    request.scope_id || request.memory_region_id ||
		    request.parent_record_id || request.provenance_sequence ||
		    request.artifact_id || request.confidence_ppm ||
		    request.importance_ppm || request.freshness_state ||
		    request.created_realtime_ns || request.retrieved_realtime_ns ||
		    request.published_realtime_ns || request.expires_realtime_ns ||
		    memchr_inv(request.source_digest, 0, sizeof(request.source_digest)) ||
		    memchr_inv(request.relationship_digest, 0, sizeof(request.relationship_digest)))
			return -EINVAL;
	}
	if (request.operation == AGI_LC_MEMORY_RECORD_RESOLVE &&
	    (!request.related_record_id || request.related_record_id == request.record_id))
		return -EINVAL;
	if (request.operation == AGI_LC_MEMORY_RECORD_QUERY &&
	    memchr_inv(request.content_digest, 0, sizeof(request.content_digest)))

		return -EINVAL;
	if ((request.operation == AGI_LC_MEMORY_RECORD_CORRECT ||
	     request.operation == AGI_LC_MEMORY_RECORD_REVALIDATE) &&
	    !memchr_inv(request.content_digest, 0, sizeof(request.content_digest)))
		return -EINVAL;

	if (request.operation == AGI_LC_MEMORY_RECORD_CREATE ||
	    request.operation == AGI_LC_MEMORY_RECORD_UPSERT) {
		for (i = 0; i < AGI_LC_PERSISTENT_MEMORY_RECORDS_LOCAL; i++) {
			struct agi_lc_persistent_memory *candidate =
				&session->persistent_memory_records[i].memory;
			if (!session->persistent_memory_records[i].valid ||
			    candidate->state == AGI_LC_MEMORY_STATE_DELETED ||
			    candidate->scope_id != request.scope_id ||
			    candidate->tier != request.tier)
				continue;
			agi_lc_persistent_memory_expire_if_needed(candidate, now);
			if (candidate->state == AGI_LC_MEMORY_STATE_EXPIRED)
				continue;
			if (agi_lc_persistent_memory_digest_equal(candidate->content_digest,
							 request.content_digest)) {
				candidate->dedup_count++;
				candidate->generation++;
				candidate->updated_realtime_ns = now;
				request = *candidate;
				request.operation = AGI_LC_MEMORY_RECORD_DEDUP;
				request.correlation = candidate->correlation;
				ret = agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_RECORD,
								0, request.correlation, candidate->record_id);
				if (ret)
					return ret;
				return copy_to_user((void __user *)arg, &request,
								 sizeof(request)) ? -EFAULT : 0;
			}
				if (!conflict_id)
					conflict_id = candidate->record_id;

		}
	}

	if (request.operation == AGI_LC_MEMORY_RECORD_CREATE ||
	    request.operation == AGI_LC_MEMORY_RECORD_UPSERT) {
		for (i = 0; i < AGI_LC_PERSISTENT_MEMORY_RECORDS_LOCAL; i++)
			if (!session->persistent_memory_records[i].valid ||
			    session->persistent_memory_records[i].memory.state == AGI_LC_MEMORY_STATE_DELETED) {
				record = &session->persistent_memory_records[i];
				break;
			}
		if (!record)
			return -ENOSPC;
		memset(record, 0, sizeof(*record));
		id = ++session->persistent_memory_next_id;
		if (!id)
			id = ++session->persistent_memory_next_id;
		record->memory = request;
		record->memory.record_id = id;
		record->memory.authority_capability = get_random_u64();
		while (!record->memory.authority_capability)
			record->memory.authority_capability = get_random_u64();
		record->memory.state = conflict_id ? AGI_LC_MEMORY_STATE_CONFLICT :
			AGI_LC_MEMORY_STATE_ACTIVE;
		record->memory.conflict_state = conflict_id ?
			AGI_LC_MEMORY_CONFLICT_DETECTED : AGI_LC_MEMORY_CONFLICT_NONE;
		if (conflict_id) {
			record->memory.related_record_id = conflict_id;
			record->memory.flags |= AGI_LC_MEMORY_RECORD_FLAG_CONFLICT;
			related = agi_lc_persistent_memory_find(session, conflict_id);
			if (related) {
				related->memory.state = AGI_LC_MEMORY_STATE_CONFLICT;
				related->memory.conflict_state = AGI_LC_MEMORY_CONFLICT_DETECTED;
				related->memory.flags |= AGI_LC_MEMORY_RECORD_FLAG_CONFLICT;
				related->memory.conflict_count++;
				related->memory.generation++;
				related->memory.updated_realtime_ns = now;
			}
		}
		record->memory.freshness_state = request.expires_realtime_ns ?
			AGI_LC_MEMORY_FRESH : AGI_LC_MEMORY_FRESHNESS_UNKNOWN;
		record->memory.created_realtime_ns = now;
		record->memory.checked_realtime_ns = now;
		record->memory.updated_realtime_ns = now;
		record->memory.generation = 1;
		record->memory.owner_lineage = faisal_task_get_lineage(current);
		record->memory.owner_agent = faisal_task_get_agent(current);
		record->memory.owner_tgid = task_tgid_nr(current);
		record->memory.creator_pid = task_pid_nr(current);
		record->memory.creator_tgid = task_tgid_nr(current);
		record->memory.creator_uid = from_kuid(&init_user_ns, current_uid());
		record->memory.creator_euid = from_kuid(&init_user_ns, current_euid());
		if (!record->memory.expires_realtime_ns)
			record->memory.flags &= ~AGI_LC_MEMORY_RECORD_FLAG_EXPIRED;
		record->valid = true;
		request = record->memory;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_RECORD, 0,
					 request.correlation, request.record_id);
		if (ret)
			return ret;
		return copy_to_user((void __user *)arg, &request,
					 sizeof(request)) ? -EFAULT : 0;
	}

	record = agi_lc_persistent_memory_find(session, request.record_id);
	if (!agi_lc_persistent_memory_authorized(session, record,
						 request.authority_capability))
		return -EACCES;
	agi_lc_persistent_memory_expire_if_needed(&record->memory, now);
	if (request.operation == AGI_LC_MEMORY_RECORD_QUERY) {
		request = record->memory;
		request.operation = AGI_LC_MEMORY_RECORD_QUERY;
		return copy_to_user((void __user *)arg, &request,
					 sizeof(request)) ? -EFAULT : 0;
	}
	if (record->memory.state == AGI_LC_MEMORY_STATE_DELETED &&
	    request.operation != AGI_LC_MEMORY_RECORD_QUERY)
		return -ENOENT;
	if (request.operation == AGI_LC_MEMORY_RECORD_CORRECT ||
	    request.operation == AGI_LC_MEMORY_RECORD_UPSERT) {
		memcpy(record->memory.content_digest, request.content_digest,
		       AGI_LC_DIGEST_SIZE);
		record->memory.flags &= ~(AGI_LC_MEMORY_RECORD_FLAG_VERIFIED |
						  AGI_LC_MEMORY_RECORD_FLAG_CONFLICT);
		record->memory.state = AGI_LC_MEMORY_STATE_ACTIVE;
		record->memory.conflict_state = AGI_LC_MEMORY_CONFLICT_NONE;
		record->memory.correction_count++;
		record->memory.generation++;
		record->memory.updated_realtime_ns = now;
	} else if (request.operation == AGI_LC_MEMORY_RECORD_DELETE) {
		record->memory.state = AGI_LC_MEMORY_STATE_DELETED;
		record->memory.flags |= AGI_LC_MEMORY_RECORD_FLAG_TOMBSTONE;
		record->memory.deletion_count++;
		record->memory.deleted_realtime_ns = now;
		record->memory.updated_realtime_ns = now;
		record->memory.generation++;
	} else if (request.operation == AGI_LC_MEMORY_RECORD_EXPIRE) {
		record->memory.state = AGI_LC_MEMORY_STATE_EXPIRED;
		record->memory.flags |= AGI_LC_MEMORY_RECORD_FLAG_EXPIRED;
		record->memory.freshness_state = AGI_LC_MEMORY_EXPIRED;
		record->memory.expiration_count++;
		record->memory.updated_realtime_ns = now;
		record->memory.generation++;
	} else if (request.operation == AGI_LC_MEMORY_RECORD_REVALIDATE) {
		if (!agi_lc_persistent_memory_digest_equal(record->memory.content_digest,
							 request.content_digest))
			return -EAGAIN;
		record->memory.state = AGI_LC_MEMORY_STATE_ACTIVE;
		record->memory.flags &= ~AGI_LC_MEMORY_RECORD_FLAG_EXPIRED;
		record->memory.freshness_state = AGI_LC_MEMORY_FRESH;
		record->memory.checked_realtime_ns = now;
		record->memory.revalidation_count++;
		record->memory.generation++;
		record->memory.updated_realtime_ns = now;
	} else if (request.operation == AGI_LC_MEMORY_RECORD_RESOLVE) {
		related = agi_lc_persistent_memory_find(session, request.related_record_id);
		if (!agi_lc_persistent_memory_owner(session, related))
			return -EACCES;
		record->memory.conflict_state = AGI_LC_MEMORY_CONFLICT_RESOLVED;
		record->memory.flags &= ~AGI_LC_MEMORY_RECORD_FLAG_CONFLICT;
		record->memory.conflict_count++;
		record->memory.generation++;
		record->memory.updated_realtime_ns = now;
		related->memory.conflict_state = AGI_LC_MEMORY_CONFLICT_RESOLVED;
		related->memory.flags &= ~AGI_LC_MEMORY_RECORD_FLAG_CONFLICT;
		related->memory.generation++;
		related->memory.updated_realtime_ns = now;
	} else {
		return -EINVAL;
	}
	request = record->memory;
	request.operation = operation;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_RECORD, 0,
				 request.correlation, request.record_id);
	if (ret)
		return ret;
	return copy_to_user((void __user *)arg, &request, sizeof(request)) ?
		-EFAULT : 0;
}

static int agi_lc_memory_region_create(struct agi_lc_session *session,
					       unsigned long arg)
{
	struct agi_lc_memory_region region;
	struct agi_lc_memory_record *record = NULL;
	struct file *file;
	struct inode *inode;
	u64 region_id;
	u64 owner_lineage;
	u64 owner_agent;
	u32 i;
	int ret = 0;

	if (copy_from_user(&region, (void __user *)arg, sizeof(region)))
		return -EFAULT;
	if (region.size != sizeof(region) || !agi_lc_memory_flags_valid(region.flags) ||
	    region.backing_fd < 0 || !agi_lc_memory_access_valid(region.access) ||
	    region.region_id || region.generation || region.snapshot_sequence ||
	    region.owner_agent || region.capability || region.reserved[0] ||
	    region.reserved[1] || !region.size_bytes ||
	    region.size_bytes > AGI_LC_MEMORY_REGION_MAX_BYTES ||
	    region.size_bytes & (PAGE_SIZE - 1))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	file = fget(region.backing_fd);
	if (!file)
		return -EBADF;
	inode = file_inode(file);
	if (!S_ISREG(inode->i_mode) ||
	    ((region.access & AGI_LC_MEMORY_ACCESS_READ) &&
	     !(file->f_mode & FMODE_READ)) ||
	    ((region.access & AGI_LC_MEMORY_ACCESS_WRITE) &&
	     !(file->f_mode & FMODE_WRITE)) ||
	    i_size_read(inode) < region.size_bytes) {
		fput(file);
		return -EINVAL;
	}

	owner_lineage = faisal_task_get_lineage(current);
	owner_agent = faisal_task_get_agent(current);
	region_id = atomic64_inc_return(&agi_lc_next_memory_region);
	if (!region_id)
		region_id = atomic64_inc_return(&agi_lc_next_memory_region);

	mutex_lock(&agi_lc_memory_lock);
	for (i = 0; i < AGI_LC_MEMORY_REGIONS; i++)
		if (!agi_lc_memory_records[i].valid) {
			record = &agi_lc_memory_records[i];
			break;
		}
	if (!record) {
		mutex_unlock(&agi_lc_memory_lock);
		fput(file);
		return -ENOSPC;
	}
	memset(record, 0, sizeof(*record));
	record->region_id = region_id;
	record->session_id = session->session_id;
	record->owner_lineage = owner_lineage;
	record->owner_agent = owner_agent;
	record->owner_tgid = task_tgid_nr(current);
	record->file = file;
	record->flags = region.flags;
	record->access = region.access;
	record->size_bytes = region.size_bytes;
	record->generation = 1;
	record->capability = agi_lc_memory_new_capability();
	region.region_id = record->region_id;
	region.generation = record->generation;
	region.owner_agent = record->owner_agent;
	region.capability = record->capability;
	ret = copy_to_user((void __user *)arg, &region, sizeof(region)) ?
		-EFAULT : 0;
	if (!ret)
		record->valid = true;
	else
		memset(record, 0, sizeof(*record));
	mutex_unlock(&agi_lc_memory_lock);
	if (ret) {
		fput(file);
		return ret;
	}
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_REGION, 0,
				  region.correlation, region.region_id);
}

static int agi_lc_memory_region_share(struct agi_lc_session *session,
					      unsigned long arg)
{
	struct agi_lc_memory_share share;
	struct agi_lc_memory_record *record;
	struct agi_lc_agent_record *agent;
	u64 agent_id = faisal_task_get_agent(current);
	u32 i;
	int ret = 0;

	if (copy_from_user(&share, (void __user *)arg, sizeof(share)))
		return -EFAULT;
	if (share.size != sizeof(share) || share.flags || !share.region_id ||
	    !share.owner_capability || !share.target_agent ||
	    !agi_lc_memory_access_valid(share.access) || share.reserved ||
	    share.share_capability || share.reserved2[0] || share.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, share.region_id);
	agent = agi_lc_find_agent(session, share.target_agent);
	if (!record || record->revoked) {
		ret = -ENOENT;
		goto out;
	}
	if (!(record->flags & AGI_LC_MEMORY_REGION_SHARED) ||
	    (record->session_id &&
	     (record->owner_lineage != faisal_task_get_lineage(current) ||
	      record->owner_agent != agent_id ||
	      record->capability != share.owner_capability)) ||
	    (!record->session_id && share.owner_capability != record->capability) ||
	    (share.access & ~record->access) || !agent) {
		ret = -EACCES;
		goto out;
	}
	if (!record->session_id) {
		record->session_id = session->session_id;
		record->owner_lineage = faisal_task_get_lineage(current);
		record->owner_agent = agent_id;
		record->owner_tgid = task_tgid_nr(current);
	}
	for (i = 0; i < AGI_LC_MEMORY_SHARES; i++)
		if (record->shares[i].active &&
		    record->shares[i].target_agent == share.target_agent) {
			ret = -EEXIST;
			goto out;
		}
	for (i = 0; i < AGI_LC_MEMORY_SHARES; i++)
		if (!record->shares[i].active) {
			record->shares[i].active = true;
			record->shares[i].target_agent = share.target_agent;
			record->shares[i].access = share.access;
			record->shares[i].capability = agi_lc_memory_new_capability();
			share.share_capability = record->shares[i].capability;
			break;
		}
	if (i == AGI_LC_MEMORY_SHARES) {
		ret = -ENOSPC;
		goto out;
	}
	if (copy_to_user((void __user *)arg, &share, sizeof(share)))
		ret = -EFAULT;
out:
	mutex_unlock(&agi_lc_memory_lock);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_SHARE, 0,
				  share.correlation, share.region_id);
}

static int agi_lc_memory_region_attach(struct agi_lc_session *session,
					       unsigned long arg)
{
	struct agi_lc_memory_attach attach;
	struct agi_lc_memory_record *record;
	struct file *file;
	u64 agent_id;
	int fd;
	int ret = 0;

	if (copy_from_user(&attach, (void __user *)arg, sizeof(attach)))
		return -EFAULT;
	if (attach.size != sizeof(attach) || attach.flags ||
	    attach.backing_fd || !attach.region_id || !attach.capability ||
	    attach.agent_id || attach.size_bytes || attach.generation ||
	    attach.correlation || attach.reserved[0] || attach.reserved[1] ||
	    !agi_lc_memory_access_valid(attach.access))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	agent_id = faisal_task_get_agent(current);
	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, attach.region_id);
	if (!record || !agi_lc_memory_authorized_locked(session, record,
							attach.capability, attach.access)) {
		ret = -EACCES;
		goto out_unlock;
	}
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto out_unlock;
	}
	if (!record->session_id) {
		record->session_id = session->session_id;
		record->owner_lineage = faisal_task_get_lineage(current);
		record->owner_agent = agent_id;
		record->owner_tgid = task_tgid_nr(current);
	}
	file = get_file(record->file);
	attach.backing_fd = fd;
	attach.agent_id = agent_id;
	attach.size_bytes = record->size_bytes;
	attach.generation = record->generation;
	if (copy_to_user((void __user *)arg, &attach, sizeof(attach))) {
		put_unused_fd(fd);
		fput(file);
		ret = -EFAULT;
		goto out_unlock;
	}
	mutex_unlock(&agi_lc_memory_lock);
	fd_install(fd, file);
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_SHARE, 0,
				  attach.correlation, attach.region_id);
out_unlock:
	mutex_unlock(&agi_lc_memory_lock);
	return ret;
}

static int agi_lc_memory_region_get(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_memory_region region;
	struct agi_lc_memory_record *record;
	int ret = 0;

	if (copy_from_user(&region, (void __user *)arg, sizeof(region)))
		return -EFAULT;
	if (region.size != sizeof(region) || region.flags ||
	    region.backing_fd || !region.region_id || !region.capability ||
	    region.size_bytes || region.generation || region.snapshot_sequence ||
	    region.owner_agent || region.correlation || region.reserved[0] ||
	    region.reserved[1] || !agi_lc_memory_access_valid(region.access))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, region.region_id);
	if (!record || !agi_lc_memory_authorized_locked(session, record,
							region.capability, region.access))
		ret = -EACCES;
	else {
		region.flags = record->flags;
		region.backing_fd = -1;
		region.size_bytes = record->size_bytes;
		region.generation = record->generation;
		region.snapshot_sequence = record->snapshot_sequence;
		region.owner_agent = record->owner_agent;
		if (copy_to_user((void __user *)arg, &region, sizeof(region)))
			ret = -EFAULT;
	}
	mutex_unlock(&agi_lc_memory_lock);
	return ret;
}

static int agi_lc_tensor_policy_validate_set(const struct agi_lc_tensor_policy *policy,
						 u64 region_size)
{
	u64 max_offset = 0;
	u32 i;

	if (policy->size != sizeof(*policy) ||
	    policy->operation != AGI_LC_TENSOR_POLICY_SET ||
	    policy->flags & ~AGI_LC_TENSOR_FLAGS_ALL ||
	    !policy->rank || policy->rank > AGI_LC_TENSOR_MAX_RANK ||
	    !policy->element_size ||
	    policy->element_size > AGI_LC_TENSOR_MAX_ELEMENT_SIZE ||
	    policy->preferred_numa_node < AGI_LC_TENSOR_NUMA_ANY ||
	    policy->preferred_numa_node >= MAX_NUMNODES ||
	    !policy->tier_mask ||
	    policy->tier_mask & ~AGI_LC_TENSOR_TIER_FLAGS_ALL ||
	    policy->reserved0 || !policy->region_id || !policy->capability ||
	    !policy->total_bytes || policy->total_bytes > region_size ||
	    policy->total_bytes % policy->element_size || !policy->alignment ||
	    policy->alignment > AGI_LC_TENSOR_MAX_ALIGNMENT ||
	    policy->alignment & (policy->alignment - 1) ||
	    policy->reserved[0] || policy->reserved[1])
		return -EINVAL;
	if ((policy->flags & AGI_LC_TENSOR_FLAG_TIER_STRICT) &&
	    (policy->tier_mask & (policy->tier_mask - 1)))
		return -EINVAL;
	for (i = 0; i < AGI_LC_TENSOR_MAX_RANK; i++) {
		if (i >= policy->rank) {
			if (policy->dimensions[i] || policy->strides[i])
				return -EINVAL;
			continue;
		}
		if (!policy->dimensions[i] || !policy->strides[i])
			return -EINVAL;
		if (policy->dimensions[i] - 1 >
		    (~0ULL - max_offset) / policy->strides[i])
			return -EOVERFLOW;
		max_offset += (policy->dimensions[i] - 1) * policy->strides[i];
	}
	if (max_offset > ~0ULL - policy->element_size ||
	    max_offset + policy->element_size > policy->total_bytes)
		return -EINVAL;
	if (policy->flags & AGI_LC_TENSOR_FLAG_PHYSICALLY_CONTIGUOUS)
		return -EOPNOTSUPP;
	return 0;
}

#define FAISAL_ADAPTIVE_MEMORY_MIN_SAMPLE_NS (1000ULL * 1000ULL)
#define FAISAL_ADAPTIVE_MEMORY_MAX_SAMPLE_NS (1000ULL * 1000ULL * 1000ULL)
#define FAISAL_ADAPTIVE_MEMORY_MAX_AGGREGATION_NS (60ULL * NSEC_PER_SEC)
#define FAISAL_ADAPTIVE_MEMORY_MAX_APPLY_NS (5ULL * 60ULL * NSEC_PER_SEC)
#define FAISAL_ADAPTIVE_MEMORY_MAX_BYTES_PER_INTERVAL (1U << 30)

static int agi_lc_adaptive_memory_policy_control(struct agi_lc_session *session,
							 unsigned long arg)
{
	struct agi_lc_adaptive_memory_policy policy;
	struct agi_lc_memory_record *record;
	u64 available_providers = 0;
	int ret;

	if (copy_from_user(&policy, (void __user *)arg, sizeof(policy)))
		return -EFAULT;
	if (policy.size != sizeof(policy) || policy.reserved[0] ||
	    policy.reserved[1] || !policy.region_id || !policy.capability ||
	    policy.flags & ~AGI_LC_ADAPTIVE_MEMORY_FLAGS_ALL ||
	    policy.provider_mask & ~AGI_LC_ADAPTIVE_MEMORY_PROVIDER_ALL ||
	    policy.operation < AGI_LC_ADAPTIVE_MEMORY_POLICY_SET ||
	    policy.operation > AGI_LC_ADAPTIVE_MEMORY_POLICY_CLEAR)
		return -EINVAL;
	if (policy.operation == AGI_LC_ADAPTIVE_MEMORY_POLICY_SET &&
	    (policy.action < AGI_LC_ADAPTIVE_MEMORY_ACTION_OBSERVE ||
	     policy.action > AGI_LC_ADAPTIVE_MEMORY_ACTION_MAX ||
	     !policy.provider_mask ||
	     policy.sample_interval_ns < FAISAL_ADAPTIVE_MEMORY_MIN_SAMPLE_NS ||
	     policy.sample_interval_ns > FAISAL_ADAPTIVE_MEMORY_MAX_SAMPLE_NS ||
	     policy.aggregation_interval_ns < policy.sample_interval_ns ||
	     policy.aggregation_interval_ns > FAISAL_ADAPTIVE_MEMORY_MAX_AGGREGATION_NS ||
	     policy.apply_interval_ns < policy.aggregation_interval_ns ||
	     policy.apply_interval_ns > FAISAL_ADAPTIVE_MEMORY_MAX_APPLY_NS ||
	     policy.max_overhead_ppm > 100000U ||
	     policy.max_bytes_per_interval > FAISAL_ADAPTIVE_MEMORY_MAX_BYTES_PER_INTERVAL))
		return -EINVAL;
	if (policy.operation != AGI_LC_ADAPTIVE_MEMORY_POLICY_SET &&
	    (policy.action || policy.provider_mask || policy.sample_interval_ns ||
	     policy.aggregation_interval_ns || policy.apply_interval_ns ||
	     policy.max_overhead_ppm || policy.max_bytes_per_interval))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, policy.region_id);
	if (!record || !agi_lc_memory_authorized_locked(session, record,
								 policy.capability,
								 AGI_LC_MEMORY_ACCESS_READ)) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (policy.operation == AGI_LC_ADAPTIVE_MEMORY_POLICY_GET) {
		if (!record->adaptive_memory_valid) {
			ret = -ENODATA;
			goto out_unlock;
		}
		policy = record->adaptive_memory;
		policy.operation = AGI_LC_ADAPTIVE_MEMORY_POLICY_GET;
		ret = copy_to_user((void __user *)arg, &policy, sizeof(policy)) ?
			-EFAULT : 0;
		goto out_unlock;
	}
	if (policy.operation == AGI_LC_ADAPTIVE_MEMORY_POLICY_CLEAR) {
		if (!record->adaptive_memory_valid) {
			ret = -ENODATA;
			goto out_unlock;
		}
		record->adaptive_memory_valid = false;
		record->generation++;
		policy.status = AGI_LC_ADAPTIVE_MEMORY_STATUS_RECORDED;
		policy.generation = record->generation;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_REGION,
					  0, policy.correlation, record->generation);
		if (!ret && copy_to_user((void __user *)arg, &policy, sizeof(policy)))
			ret = -EFAULT;
		goto out_unlock;

	}

	/* No provider is asserted by the kernel; providers must prove themselves. */
	policy.unsupported_provider_mask = policy.provider_mask & ~available_providers;
	policy.status = policy.unsupported_provider_mask ?
		AGI_LC_ADAPTIVE_MEMORY_STATUS_OBSERVE_ONLY :
		AGI_LC_ADAPTIVE_MEMORY_STATUS_RECORDED;
	if ((policy.flags & AGI_LC_ADAPTIVE_MEMORY_FLAG_PROVIDER_REQUIRED) &&
	    policy.unsupported_provider_mask) {
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}
	record->adaptive_memory = policy;
	record->adaptive_memory_valid = true;
	record->generation++;
	record->adaptive_memory.generation = record->generation;
	policy = record->adaptive_memory;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_REGION,
				 0, policy.correlation, record->generation);
	if (!ret && copy_to_user((void __user *)arg, &policy, sizeof(policy)))
		ret = -EFAULT;
out_unlock:
	mutex_unlock(&agi_lc_memory_lock);
	return ret;
}

static int agi_lc_tensor_policy_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_tensor_policy policy;
	struct agi_lc_memory_record *record;
	int ret;

	if (copy_from_user(&policy, (void __user *)arg, sizeof(policy)))
		return -EFAULT;
	if (policy.size != sizeof(policy) || policy.reserved0 ||
	    policy.reserved[0] || policy.reserved[1] ||
	    policy.provenance_binding_id || policy.provenance_id ||
	    policy.provenance_sequence || policy.provenance_generation ||
	    !policy.region_id || !policy.capability ||
	    (policy.operation != AGI_LC_TENSOR_POLICY_SET &&
	     policy.operation != AGI_LC_TENSOR_POLICY_GET))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (policy.operation == AGI_LC_TENSOR_POLICY_SET) {
		ret = agi_lc_tensor_policy_validate_set(&policy,
								AGI_LC_MEMORY_REGION_MAX_BYTES);
		if (ret)
			return ret;
	}
	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, policy.region_id);
	if (!record || !agi_lc_memory_authorized_locked(session, record,
								 policy.capability,
								 AGI_LC_MEMORY_ACCESS_READ)) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (policy.operation == AGI_LC_TENSOR_POLICY_GET) {
		if (!record->tensor_valid) {
			ret = -ENODATA;
			goto out_unlock;
		}
		policy = record->tensor;
		policy.operation = AGI_LC_TENSOR_POLICY_GET;
		policy.correlation = record->tensor.correlation;
		ret = copy_to_user((void __user *)arg, &policy, sizeof(policy)) ?
			-EFAULT : 0;
		goto out_unlock;
	}
	if (policy.total_bytes > record->size_bytes) {
		ret = -EINVAL;
		goto out_unlock;
	}
	record->tensor = policy;
	record->tensor_valid = true;
	record->generation++;
	record->tensor.generation = record->generation;
	policy.generation = record->generation;
	ret = copy_to_user((void __user *)arg, &policy, sizeof(policy)) ?
		-EFAULT : 0;
out_unlock:
	mutex_unlock(&agi_lc_memory_lock);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_REGION, 0,
				  policy.correlation, policy.region_id);
}

static int agi_lc_memory_region_snapshot(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_memory_snapshot snapshot;
	struct agi_lc_memory_record *record;
	u64 sequence;
	int ret;

	if (copy_from_user(&snapshot, (void __user *)arg, sizeof(snapshot)))
		return -EFAULT;
	if (snapshot.size != sizeof(snapshot) || snapshot.flags || snapshot.status ||
	    snapshot.reserved || !snapshot.region_id || !snapshot.owner_capability ||
	    !snapshot.parent_generation || snapshot.generation ||
	    snapshot.snapshot_sequence || !memchr_inv(snapshot.digest, 0,
							 sizeof(snapshot.digest)) ||
	    snapshot.reserved2[0] || snapshot.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, snapshot.region_id);
	if (!record || record->revoked ||
	    !(record->flags & AGI_LC_MEMORY_REGION_SNAPSHOTABLE) ||
	    (record->session_id &&
	     (record->owner_lineage != faisal_task_get_lineage(current) ||
	      record->owner_agent != faisal_task_get_agent(current) ||
	      record->capability != snapshot.owner_capability)) ||
	    (!record->session_id && snapshot.owner_capability != record->capability) ||
	    record->generation != snapshot.parent_generation) {
		mutex_unlock(&agi_lc_memory_lock);
		return -EACCES;
	}
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_MEMORY_SNAPSHOT, 0,
					 snapshot.correlation, snapshot.region_id,
					 &sequence);
	if (ret) {
		mutex_unlock(&agi_lc_memory_lock);
		return ret;
	}
	record->generation++;
	record->snapshot_sequence = sequence;
	memcpy(record->snapshot_digest, snapshot.digest,
	       sizeof(record->snapshot_digest));
	snapshot.generation = record->generation;
	snapshot.snapshot_sequence = sequence;
	if (copy_to_user((void __user *)arg, &snapshot, sizeof(snapshot)))
		ret = -EFAULT;
	mutex_unlock(&agi_lc_memory_lock);
	return ret;
}

static int agi_lc_memory_region_revoke(struct agi_lc_session *session,
					      unsigned long arg)
{
	struct agi_lc_memory_revoke revoke;
	struct agi_lc_memory_record *record;
	u64 agent_id = faisal_task_get_agent(current);
	u32 i;
	bool found = false;
	int ret = 0;

	if (copy_from_user(&revoke, (void __user *)arg, sizeof(revoke)))
		return -EFAULT;
	if (revoke.size != sizeof(revoke) || revoke.flags || !revoke.region_id ||
	    !revoke.owner_capability || revoke.reserved[0] || revoke.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	mutex_lock(&agi_lc_memory_lock);
	record = agi_lc_memory_find_locked(session, revoke.region_id);
	if (!record || record->revoked ||
	    (record->session_id &&
	     (record->owner_lineage != faisal_task_get_lineage(current) ||
	      record->owner_agent != agent_id ||
	      record->capability != revoke.owner_capability)) ||
	    (!record->session_id && revoke.owner_capability != record->capability)) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (!revoke.target_agent) {
		record->revoked = true;
		for (i = 0; i < AGI_LC_MEMORY_SHARES; i++)
			record->shares[i].active = false;
		found = true;
	} else {
		for (i = 0; i < AGI_LC_MEMORY_SHARES; i++)
			if (record->shares[i].active &&
			    record->shares[i].target_agent == revoke.target_agent) {
				record->shares[i].active = false;
				found = true;
				break;
			}
	}
	if (!found)
		ret = -ENOENT;
out_unlock:
	mutex_unlock(&agi_lc_memory_lock);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_REVOKE, 0,
				  revoke.correlation, revoke.region_id);
}

static bool agi_lc_has_record(struct agi_lc_session *session)
{
	return READ_ONCE(session->count) || READ_ONCE(session->revoked);
}

static u64 agi_lc_world_class_mask(u16 type)
{
	switch (type) {
	case AGI_LC_EVENT_BEGIN:
	case AGI_LC_EVENT_END:
	case AGI_LC_EVENT_CANCEL:
	case AGI_LC_EVENT_LIGHT_AGENT:
	case AGI_LC_EVENT_BROWSER:
	case AGI_LC_EVENT_PHASE:
	case AGI_LC_EVENT_AGENT:
	case AGI_LC_EVENT_MESSAGE:
	case AGI_LC_EVENT_IPC:
	case AGI_LC_EVENT_SCHED_HINT:
	case AGI_LC_EVENT_TEMPORAL:
	case AGI_LC_EVENT_REFLECTION:
	case AGI_LC_EVENT_OBSERVABILITY:
		return 1ULL << (AGI_LC_WORLD_EVENT_TASK_STATE - 1);
	case AGI_LC_EVENT_REVOKE:
	case AGI_LC_EVENT_VERIFY:
	case AGI_LC_EVENT_SECURITY_CAPABILITY:
	case AGI_LC_EVENT_KNOWLEDGE:
		return 1ULL << (AGI_LC_WORLD_EVENT_SECURITY - 1);
	case AGI_LC_EVENT_MEMORY_HINT:
	case AGI_LC_EVENT_MEMORY_BUDGET:
	case AGI_LC_EVENT_MEMORY_REGION:
	case AGI_LC_EVENT_MEMORY_SHARE:
	case AGI_LC_EVENT_MEMORY_SNAPSHOT:
	case AGI_LC_EVENT_MEMORY_REVOKE:
	case AGI_LC_EVENT_RESOURCE_DEMAND:
		return 1ULL << (AGI_LC_WORLD_EVENT_RESOURCE - 1);
	case AGI_LC_EVENT_PERF:
	case AGI_LC_EVENT_BUDGET:
		return 1ULL << (AGI_LC_WORLD_EVENT_RESOURCE - 1);
	case AGI_LC_EVENT_ACCEL:
	case AGI_LC_EVENT_ACCEL_WORKLOAD:
		return 1ULL << (AGI_LC_WORLD_EVENT_ACCELERATOR - 1);
	case AGI_LC_EVENT_NETWORK_POLICY:
		return 1ULL << (AGI_LC_WORLD_EVENT_NETWORK - 1);
	case AGI_LC_EVENT_GATE:
		return 1ULL << (AGI_LC_WORLD_EVENT_TIMER - 1);
	case AGI_LC_EVENT_CHECKPOINT:
	case AGI_LC_EVENT_HANDOFF:
	case AGI_LC_EVENT_RECOVERY:
		return 1ULL << (AGI_LC_WORLD_EVENT_CHECKPOINT - 1);
	default:
		return 0;
	}
}

static u32 agi_lc_world_priority(u16 type, s32 status)
{
	if (type == AGI_LC_EVENT_REVOKE || type == AGI_LC_EVENT_CANCEL ||
	    (type == AGI_LC_EVENT_IPC && status) ||
	    (type == AGI_LC_EVENT_VERIFY && status))
		return AGI_LC_WORLD_PRIORITY_CRITICAL;

	if (type == AGI_LC_EVENT_CHECKPOINT || type == AGI_LC_EVENT_HANDOFF ||
	    type == AGI_LC_EVENT_RECOVERY || type == AGI_LC_EVENT_MEMORY_BUDGET ||
	    type == AGI_LC_EVENT_VERIFY)
		return AGI_LC_WORLD_PRIORITY_HIGH;
	if (type == AGI_LC_EVENT_PERF || type == AGI_LC_EVENT_ACCEL ||
	    type == AGI_LC_EVENT_ACCEL_WORKLOAD || type == AGI_LC_EVENT_SCHED_HINT)
		return AGI_LC_WORLD_PRIORITY_LOW;
	return AGI_LC_WORLD_PRIORITY_NORMAL;
}

static int agi_lc_world_sync(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_world_sync sync;
	unsigned long flags;
	u32 tail_index;
	int ret = 0;

	if (copy_from_user(&sync, (void __user *)arg, sizeof(sync)))
		return -EFAULT;
	if (sync.size != sizeof(sync) ||
	    sync.operation < AGI_LC_WORLD_SYNC_QUERY ||
	    sync.operation > AGI_LC_WORLD_SYNC_RESYNC ||
	    sync.flags & ~AGI_LC_WORLD_SYNC_FLAGS_ALL ||
	    sync.correlation == 0 || sync.reserved[0] || sync.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (sync.operation == AGI_LC_WORLD_SYNC_QUERY) {
		if (sync.consumer_id || sync.ack_sequence || sync.resync_sequence ||
		    sync.next_sequence || sync.oldest_sequence || sync.newest_sequence ||
		    sync.queued || sync.generation || sync.delivered || sync.filtered ||
		    sync.dropped || sync.last_loss_sequence || sync.resync_required)
			return -EINVAL;
	} else {
		if (sync.consumer_id != session->session_id || !sync.ack_sequence ||
		    sync.next_sequence || sync.oldest_sequence || sync.newest_sequence ||
		    sync.queued || sync.generation || sync.delivered || sync.filtered ||
		    sync.dropped || sync.last_loss_sequence || sync.resync_required)
			return -EINVAL;
	}
	spin_lock_irqsave(&session->queue_lock, flags);
	if (sync.operation == AGI_LC_WORLD_SYNC_ACK) {
		u64 newest = session->count ?
			session->records[(session->tail + AGI_LC_RING_SIZE - 1) %
				 AGI_LC_RING_SIZE].sequence :
			(session->next_sequence ? session->next_sequence - 1 : 0);
		if (sync.ack_sequence < session->world_ack_sequence ||
		    sync.ack_sequence > newest)
			ret = -ERANGE;
		else
			session->world_ack_sequence = sync.ack_sequence;
	} else if (sync.operation == AGI_LC_WORLD_SYNC_RESYNC) {
		if (!session->world_resync_required ||
		    sync.resync_sequence != session->world_last_loss_sequence ||
		    sync.ack_sequence < session->world_last_loss_sequence)
			ret = -EAGAIN;
		else {
			session->world_ack_sequence = sync.ack_sequence;
			session->world_resync_required = false;
			session->world_resync_sequence = sync.resync_sequence;
		}
	}
	if (!ret) {
		sync.consumer_id = session->session_id;
		sync.next_sequence = session->next_sequence;
		sync.queued = session->count;
		sync.generation = session->change_generation;
		sync.delivered = session->world_delivered;
		sync.filtered = session->world_filtered;
		sync.dropped = session->world_dropped;
		sync.last_loss_sequence = session->world_last_loss_sequence;
		sync.resync_required = session->world_resync_required ? 1 : 0;
		sync.ack_sequence = session->world_ack_sequence;
		sync.resync_sequence = session->world_resync_sequence;
		if (session->count) {
			sync.oldest_sequence = session->records[session->head].sequence;
			tail_index = (session->tail + AGI_LC_RING_SIZE - 1) %
				AGI_LC_RING_SIZE;
			sync.newest_sequence = session->records[tail_index].sequence;
		} else {
			sync.oldest_sequence = session->next_sequence;
			sync.newest_sequence = session->next_sequence ?
				session->next_sequence - 1 : 0;
		}
	}
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &sync, sizeof(sync)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_temporal_record *
agi_lc_temporal_find(struct agi_lc_session *session, u64 record_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_TEMPORAL_RECORDS_LOCAL; i++)
		if (session->temporal_records[i].valid &&
		    session->temporal_records[i].temporal.record_id == record_id)
			return &session->temporal_records[i];
	return NULL;
}

static bool agi_lc_temporal_owner(struct agi_lc_session *session,
					struct agi_lc_temporal_record *record)
{
	return record && record->temporal.authority_capability &&
		record->temporal.lineage_id == faisal_task_get_lineage(current) &&
		record->temporal.agent_id == faisal_task_get_agent(current) &&
		record->temporal.lineage_id == session->session_id;
}

static int agi_lc_temporal_control(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_temporal request;
	struct agi_lc_temporal_record *record = NULL;
	u32 operation;
	u64 now_real, now_boot, latest_sequence;
	u64 sequence = 0;
	u32 i;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	operation = request.operation;
	if (request.size != sizeof(request) ||
	    request.operation < AGI_LC_TEMPORAL_RECORD ||
	    request.operation > AGI_LC_TEMPORAL_UPDATE ||
	    request.flags & ~AGI_LC_TEMPORAL_FLAGS_ALL ||
	    request.state > AGI_LC_TEMPORAL_STATE_EXPIRED ||
	    request.constraint_result > AGI_LC_TEMPORAL_RESULT_VIOLATED ||
	    request.status || request.reserved[0] || request.reserved[1] ||
	    !request.correlation)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	now_real = ktime_get_real_ns();
	now_boot = ktime_get_boottime_ns();
	latest_sequence = session->next_sequence ? session->next_sequence - 1 : 0;

	if (request.operation == AGI_LC_TEMPORAL_RECORD) {
		if (request.record_id || request.authority_capability ||
		    request.event_sequence || request.observation_realtime_ns ||
		    request.observation_boottime_ns || request.lineage_id ||
		    request.agent_id || request.task_id || request.generation ||
		    request.state || request.constraint_result ||
		    ((request.flags & AGI_LC_TEMPORAL_FLAG_PARENT) &&
		     (request.parent_sequence > latest_sequence)) ||
		    ((request.flags & AGI_LC_TEMPORAL_FLAG_REFERENCE) &&
		     (request.reference_sequence > latest_sequence)) ||
		    (!(request.flags & AGI_LC_TEMPORAL_FLAG_PARENT) && request.parent_sequence) ||
		    (!(request.flags & AGI_LC_TEMPORAL_FLAG_REFERENCE) && request.reference_sequence) ||
		    (!(request.flags & AGI_LC_TEMPORAL_FLAG_EVENT_REALTIME) && request.event_realtime_ns) ||
		    (!(request.flags & AGI_LC_TEMPORAL_FLAG_EVENT_BOOTTIME) && request.event_boottime_ns) ||
		    (request.event_realtime_ns > now_real) ||
		    (request.event_boottime_ns > now_boot) ||
		    ((request.flags & AGI_LC_TEMPORAL_FLAG_DEADLINE) &&
		     (!request.deadline_boottime_ns || request.deadline_boottime_ns <= now_boot)) ||
		    (!(request.flags & AGI_LC_TEMPORAL_FLAG_DEADLINE) && request.deadline_boottime_ns))
			return -EINVAL;
		for (i = 0; i < AGI_LC_TEMPORAL_RECORDS_LOCAL; i++)
			if (!session->temporal_records[i].valid) {
				record = &session->temporal_records[i];
				break;
			}
		if (!record)
			return -ENOSPC;
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->temporal = request;
		record->temporal.record_id = ++session->temporal_next_id;
		if (!record->temporal.record_id)
			record->temporal.record_id = ++session->temporal_next_id;
		record->temporal.authority_capability = get_random_u64();
		while (!record->temporal.authority_capability)
			record->temporal.authority_capability = get_random_u64();
		record->temporal.observation_realtime_ns = now_real;
		record->temporal.observation_boottime_ns = now_boot;
		record->temporal.lineage_id = faisal_task_get_lineage(current);
		record->temporal.agent_id = faisal_task_get_agent(current);
		record->temporal.task_id = task_pid_nr(current);
		record->temporal.generation = 1;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_TEMPORAL, 0,
					request.correlation, record->temporal.record_id,
					&sequence);
		if (ret && ret != -EAGAIN) {
			record->valid = false;
			return ret;
		}
		record->temporal.event_sequence = sequence;
		request = record->temporal;
		request.operation = operation;
		goto out_copy;
	}

	if (!request.record_id || !request.authority_capability ||
	    request.event_realtime_ns || request.event_boottime_ns ||
	    request.observation_realtime_ns || request.observation_boottime_ns ||
	    request.lineage_id || request.agent_id || request.task_id ||
	    request.generation || request.checkpoint_id)
		return -EINVAL;
	record = agi_lc_temporal_find(session, request.record_id);
	if (!record || record->temporal.authority_capability !=
		request.authority_capability || !agi_lc_temporal_owner(session, record))
		return -EACCES;
	if (request.operation == AGI_LC_TEMPORAL_QUERY) {
		if (request.flags || request.state || request.constraint_result ||
		    request.parent_sequence || request.reference_sequence ||
		    request.min_sequence || request.max_sequence ||
		    request.deadline_boottime_ns)
			return -EINVAL;
		request = record->temporal;
		request.operation = operation;
		goto out_copy;
	}
	if (request.operation == AGI_LC_TEMPORAL_CHECK) {
		if (!(request.flags & AGI_LC_TEMPORAL_FLAG_REFERENCE) ||
		    !request.reference_sequence || request.reference_sequence > latest_sequence ||
		    (request.min_sequence && request.reference_sequence < request.min_sequence) ||
		    (request.max_sequence && request.reference_sequence > request.max_sequence))
			return -EINVAL;
		record->temporal.reference_sequence = request.reference_sequence;
		record->temporal.min_sequence = request.min_sequence;
		record->temporal.max_sequence = request.max_sequence;
		if (record->temporal.deadline_boottime_ns &&
		    now_boot >= record->temporal.deadline_boottime_ns) {
			record->temporal.state = AGI_LC_TEMPORAL_STATE_EXPIRED;
			record->temporal.constraint_result = AGI_LC_TEMPORAL_RESULT_VIOLATED;
			ret = -ETIME;
		} else {
			record->temporal.state = AGI_LC_TEMPORAL_STATE_SATISFIED;
			record->temporal.constraint_result = AGI_LC_TEMPORAL_RESULT_OK;
			ret = 0;
		}
		record->temporal.generation++;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_TEMPORAL, ret,
					request.correlation, record->temporal.record_id);
		request = record->temporal;
		request.operation = operation;
		if (ret == -EAGAIN)
			ret = 0;
		goto out_copy_ret;
	}
	if (request.operation == AGI_LC_TEMPORAL_UPDATE) {
		if (!(request.flags & AGI_LC_TEMPORAL_FLAG_DEADLINE) ||
		    !request.deadline_boottime_ns || request.deadline_boottime_ns <= now_boot ||
		    request.flags & ~(AGI_LC_TEMPORAL_FLAG_DEADLINE))
			return -EINVAL;
		record->temporal.deadline_boottime_ns = request.deadline_boottime_ns;
		record->temporal.flags |= AGI_LC_TEMPORAL_FLAG_DEADLINE;
		record->temporal.state = AGI_LC_TEMPORAL_STATE_ACTIVE;
		record->temporal.constraint_result = AGI_LC_TEMPORAL_RESULT_UNKNOWN;
		record->temporal.generation++;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_TEMPORAL, 0,
					request.correlation, record->temporal.record_id);
		request = record->temporal;
		request.operation = operation;
		if (ret == -EAGAIN)
			ret = 0;
		goto out_copy_ret;
	}
	return -EINVAL;

out_copy_ret:
	if (ret)
		return ret;
out_copy:
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_reflection_record *
agi_lc_reflection_find(struct agi_lc_session *session, u64 action_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_REFLECTION_RECORDS_LOCAL; i++)
		if (session->reflection_records[i].valid &&
		    session->reflection_records[i].reflection.action_id == action_id)
			return &session->reflection_records[i];
	return NULL;
}

static bool agi_lc_reflection_owner(struct agi_lc_session *session,
					struct agi_lc_reflection_record *record)
{
	return record && record->reflection.authority_capability &&
		record->reflection.lineage_id == faisal_task_get_lineage(current) &&
		record->reflection.agent_id == faisal_task_get_agent(current) &&
		record->reflection.lineage_id == session->session_id;
}

static void agi_lc_reflection_resources(struct agi_lc_session *session,
					struct agi_lc_reflection *reflection)
{
	u64 budget_ns, elapsed_ns;
	u64 memory_limit_pages, memory_current_pages;
	u64 accel_compute_ns, accel_memory_bytes, accel_submissions;
	unsigned long flags;
	u32 i;
	bool exhausted, memory_exceeded;

	faisal_task_get_budget(current, &budget_ns, &elapsed_ns, &exhausted);
	faisal_task_get_memory_limit(current, &memory_limit_pages,
				     &memory_current_pages, &memory_exceeded);
	faisal_task_accel_get(current, &accel_compute_ns, &accel_memory_bytes,
				      &accel_submissions);
	reflection->sampled_realtime_ns = ktime_get_real_ns();
	reflection->sampled_boottime_ns = ktime_get_boottime_ns();
	reflection->cpu_end_ns = elapsed_ns;
	reflection->memory_end_pages = memory_current_pages;
	reflection->cpu_budget_ns = budget_ns;
	reflection->memory_limit_pages = memory_limit_pages;
	reflection->accel_compute_ns = accel_compute_ns;
	reflection->accel_memory_bytes = accel_memory_bytes;
	reflection->accel_submissions = accel_submissions;
	reflection->last_failure_sequence = session->last_failure_sequence;
	reflection->failure_count = session->failure_count;
	reflection->change_generation = session->change_generation;
	reflection->lineage_id = faisal_task_get_lineage(current);
	reflection->agent_id = faisal_task_get_agent(current);
	reflection->task_id = task_pid_nr(current);
	reflection->tgid = task_tgid_nr(current);
	reflection->checkpoint_id = session->checkpoint_valid ?
		session->checkpoint_id : 0;
	spin_lock_irqsave(&session->queue_lock, flags);
	reflection->event_sequence = session->next_sequence ?
		session->next_sequence - 1 : 0;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	reflection->blocked_count = 0;
	for (i = 0; i < AGI_LC_REFLECTION_RECORDS_LOCAL; i++)
		if (session->reflection_records[i].valid &&
		    session->reflection_records[i].reflection.state ==
			AGI_LC_REFLECTION_STATE_BLOCKED)
			reflection->blocked_count++;
}

static int agi_lc_reflection_control(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_reflection request;
	struct agi_lc_reflection_record *record = NULL;
	u32 operation;
	u64 sequence = 0;
	u64 now_real, now_boot;
	u32 i;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	operation = request.operation;
	if (request.size != sizeof(request) ||

	    request.operation < AGI_LC_REFLECTION_SNAPSHOT ||
	    request.operation > AGI_LC_REFLECTION_DEPENDENCY_QUERY ||
	    request.flags & ~AGI_LC_REFLECTION_FLAGS_ALL ||
	    request.state > AGI_LC_REFLECTION_STATE_CANCELLED ||
	    request.reserved[0] || request.reserved[1] || !request.correlation)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	now_real = ktime_get_real_ns();
	now_boot = ktime_get_boottime_ns();

	if (request.operation == AGI_LC_REFLECTION_SNAPSHOT) {
		if (request.flags || request.status || request.state ||
		    request.action_id || request.authority_capability ||
		    request.parent_action_id || request.dependency_id ||
		    request.dependency_reason || request.event_sequence ||
		    request.parent_sequence || request.start_realtime_ns ||
		    request.start_boottime_ns || request.end_realtime_ns ||
		    request.end_boottime_ns || request.cpu_start_ns ||
		    request.cpu_end_ns || request.cpu_delta_ns ||
		    request.memory_start_pages || request.memory_end_pages ||
		    request.memory_delta_pages || request.cpu_budget_ns ||
		    request.memory_limit_pages || request.accel_compute_ns ||
		    request.accel_memory_bytes || request.accel_submissions ||
		    request.sampled_realtime_ns ||
		    request.sampled_boottime_ns || request.last_failure_sequence ||
		    request.failure_count || request.blocked_count ||
		    request.change_generation || request.lineage_id ||
		    request.agent_id || request.task_id || request.tgid ||
		    request.checkpoint_id || request.result_code || request.generation)
			return -EINVAL;
		memset((u8 *)&request + offsetof(struct agi_lc_reflection,
							 action_id), 0,
		       sizeof(request) - offsetof(struct agi_lc_reflection,
							 action_id));
		request.size = sizeof(request);
		request.operation = AGI_LC_REFLECTION_SNAPSHOT;
		agi_lc_reflection_resources(session, &request);
		if (copy_to_user((void __user *)arg, &request, sizeof(request)))
			return -EFAULT;
		return 0;
	}

	if (request.operation == AGI_LC_REFLECTION_ACTION_BEGIN) {
		if (request.flags & AGI_LC_REFLECTION_FLAG_FAILURE ||
		    request.action_id || request.authority_capability ||
		    request.event_sequence || request.parent_sequence ||
		    request.start_realtime_ns || request.start_boottime_ns ||
		    request.end_realtime_ns || request.end_boottime_ns ||
		    request.cpu_start_ns || request.cpu_end_ns || request.cpu_delta_ns ||
		    request.memory_start_pages || request.memory_end_pages ||
		    request.memory_delta_pages || request.cpu_budget_ns ||
		    request.memory_limit_pages || request.accel_compute_ns ||
		    request.accel_memory_bytes || request.accel_submissions ||
		    request.status || request.state ||
		    request.result_code || request.generation ||
		    ((request.flags & AGI_LC_REFLECTION_FLAG_DEPENDENCY) &&
		     !request.dependency_id))
			return -EINVAL;
		if (request.parent_action_id &&
		    !agi_lc_reflection_find(session, request.parent_action_id))
			return -ENOENT;
		for (i = 0; i < AGI_LC_REFLECTION_RECORDS_LOCAL; i++)
			if (!session->reflection_records[i].valid) {
				record = &session->reflection_records[i];
				break;
			}
		if (!record)
			return -ENOSPC;
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->reflection = request;
		record->reflection.action_id = ++session->reflection_next_id;
		if (!record->reflection.action_id)
			record->reflection.action_id = ++session->reflection_next_id;
		record->reflection.authority_capability = get_random_u64();
		while (!record->reflection.authority_capability)
			record->reflection.authority_capability = get_random_u64();
		record->reflection.state = AGI_LC_REFLECTION_STATE_ACTIVE;
		record->reflection.start_realtime_ns = now_real;
		record->reflection.start_boottime_ns = now_boot;
		record->reflection.lineage_id = faisal_task_get_lineage(current);
		record->reflection.agent_id = faisal_task_get_agent(current);
		record->reflection.task_id = task_pid_nr(current);
		record->reflection.tgid = task_tgid_nr(current);
		record->reflection.parent_sequence = session->next_sequence ?
		 session->next_sequence - 1 : 0;
		agi_lc_reflection_resources(session, &record->reflection);
		record->reflection.cpu_start_ns = record->reflection.cpu_end_ns;
		record->reflection.memory_start_pages =
		record->reflection.memory_end_pages;
		record->reflection.generation = 1;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_REFLECTION, 0,
					request.correlation, record->reflection.action_id,
					&sequence);
		if (ret && ret != -EAGAIN) {
			record->valid = false;
			return ret;
		}
		record->reflection.event_sequence = sequence;
		request = record->reflection;
		request.operation = AGI_LC_REFLECTION_ACTION_BEGIN;
		if (copy_to_user((void __user *)arg, &request, sizeof(request)))
			return -EFAULT;
		return 0;
	}

	if (!request.action_id || !request.authority_capability ||
	    request.parent_action_id || request.event_sequence ||
	    request.parent_sequence || request.start_realtime_ns ||
	    request.start_boottime_ns || request.end_realtime_ns ||
	    request.end_boottime_ns || request.cpu_start_ns ||
	    request.cpu_end_ns || request.cpu_delta_ns ||
	    request.memory_start_pages || request.memory_end_pages ||
	    request.memory_delta_pages || request.cpu_budget_ns ||
		    request.memory_limit_pages || request.accel_compute_ns ||
		    request.accel_memory_bytes || request.accel_submissions ||
		    request.sampled_realtime_ns ||
	    request.sampled_boottime_ns || request.last_failure_sequence ||
	    request.failure_count || request.blocked_count ||
	    request.change_generation || request.lineage_id || request.agent_id ||
	    request.task_id || request.tgid || request.checkpoint_id ||
	    request.result_code || request.generation)
		return -EINVAL;
	record = agi_lc_reflection_find(session, request.action_id);
	if (!record || record->reflection.authority_capability !=
		request.authority_capability || !agi_lc_reflection_owner(session, record))
		return -EACCES;
	if (request.operation == AGI_LC_REFLECTION_ACTION_QUERY ||
	    request.operation == AGI_LC_REFLECTION_DEPENDENCY_QUERY) {
		if (request.flags || request.status || request.state ||
		    request.dependency_id || request.dependency_reason)
			return -EINVAL;
		request = record->reflection;
		request.operation = operation;
		goto out_copy;
	}
	if (request.operation == AGI_LC_REFLECTION_ACTION_END) {
		if (request.flags & AGI_LC_REFLECTION_FLAG_DEPENDENCY ||
		    record->reflection.state == AGI_LC_REFLECTION_STATE_COMPLETED ||
		    record->reflection.state == AGI_LC_REFLECTION_STATE_FAILED ||
		    record->reflection.state == AGI_LC_REFLECTION_STATE_CANCELLED)
			return -EINVAL;
		agi_lc_reflection_resources(session, &record->reflection);
		record->reflection.end_realtime_ns = now_real;
		record->reflection.end_boottime_ns = now_boot;
		record->reflection.cpu_delta_ns =
			record->reflection.cpu_end_ns - record->reflection.cpu_start_ns;
		record->reflection.memory_delta_pages =
			(s64)record->reflection.memory_end_pages -
			(s64)record->reflection.memory_start_pages;
		record->reflection.status = request.status;
		record->reflection.result_code = (u64)(s64)request.status;
		record->reflection.state = request.status ?
			AGI_LC_REFLECTION_STATE_FAILED :
			AGI_LC_REFLECTION_STATE_COMPLETED;
		if (request.status)
			record->reflection.flags |= AGI_LC_REFLECTION_FLAG_FAILURE;
		record->reflection.generation++;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_REFLECTION,
					request.status, request.correlation,
					record->reflection.action_id);
		request = record->reflection;
		request.operation = AGI_LC_REFLECTION_ACTION_END;
		if (ret == -EAGAIN)
			ret = 0;
		if (ret)
			return ret;
		goto out_copy;
	}
	if (request.operation == AGI_LC_REFLECTION_DEPENDENCY_BLOCK) {
		if (!(request.flags & AGI_LC_REFLECTION_FLAG_DEPENDENCY) ||
		    !request.dependency_id || !request.dependency_reason ||
		    request.status ||
		    record->reflection.state == AGI_LC_REFLECTION_STATE_COMPLETED ||
		    record->reflection.state == AGI_LC_REFLECTION_STATE_FAILED)
			return -EINVAL;
		record->reflection.flags |= AGI_LC_REFLECTION_FLAG_DEPENDENCY;
		record->reflection.state = AGI_LC_REFLECTION_STATE_BLOCKED;
		record->reflection.dependency_id = request.dependency_id;
		record->reflection.dependency_reason = request.dependency_reason;
		agi_lc_reflection_resources(session, &record->reflection);
		record->reflection.generation++;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_REFLECTION, 0,
					request.correlation, record->reflection.action_id);
		request = record->reflection;
		request.operation = AGI_LC_REFLECTION_DEPENDENCY_BLOCK;
		if (ret == -EAGAIN)
			ret = 0;
		if (ret)
			return ret;
		goto out_copy;
	}
	return -EINVAL;

out_copy:
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static int agi_lc_observability_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_observability request;
	unsigned long flags;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) ||
	    request.operation < AGI_LC_OBSERVABILITY_SET ||
	    request.operation > AGI_LC_OBSERVABILITY_RESET ||
	    request.flags & ~AGI_LC_OBSERVABILITY_FLAGS_ALL ||
	    request.enabled > 1 || request.reserved32 ||
	    request.reserved[0] || request.reserved[1] || !request.correlation)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (request.operation == AGI_LC_OBSERVABILITY_SET) {
		if (!request.event_mask ||
		    ((request.flags & AGI_LC_OBSERVABILITY_FLAG_SAMPLE) &&
		     (!request.sample_period ||
		      request.sample_period > AGI_LC_OBSERVABILITY_MAX_SAMPLE_PERIOD)) ||
		    (!(request.flags & AGI_LC_OBSERVABILITY_FLAG_SAMPLE) &&
		     request.sample_period) || request.emitted || request.filtered ||
		    request.sampled || request.dropped || request.last_sequence ||
		    request.generation || request.lineage_id || request.agent_id ||
		    request.task_id)
			return -EINVAL;
	} else if (request.operation == AGI_LC_OBSERVABILITY_QUERY) {
		if (request.flags || request.enabled || request.event_mask ||
		    request.sample_period || request.emitted || request.filtered ||
		    request.sampled || request.dropped || request.last_sequence ||
		    request.generation || request.lineage_id || request.agent_id ||
		    request.task_id)
			return -EINVAL;
	} else {
		if (request.flags || request.enabled || request.event_mask ||
		    request.sample_period || request.emitted || request.filtered ||
		    request.sampled || request.dropped || request.last_sequence ||
		    request.generation || request.lineage_id || request.agent_id ||
		    request.task_id)
			return -EINVAL;
	}

	spin_lock_irqsave(&session->queue_lock, flags);
	if (request.operation == AGI_LC_OBSERVABILITY_SET) {
		session->observability_flags = request.flags;
		session->observability_enabled = request.enabled != 0;
		session->observability_event_mask = request.event_mask;
		session->observability_sample_period = request.sample_period;
		session->observability_sample_index = 0;
		session->observability_generation++;
	} else if (request.operation == AGI_LC_OBSERVABILITY_RESET) {
		session->observability_emitted = 0;
		session->observability_filtered = 0;
		session->observability_sampled = 0;
		session->observability_dropped = 0;
		session->observability_last_sequence = 0;
		session->observability_sample_index = 0;
		session->observability_generation++;
	}
	request.enabled = session->observability_enabled ? 1 : 0;
	request.flags = session->observability_flags;
	request.event_mask = session->observability_event_mask;
	request.sample_period = session->observability_sample_period;
	request.emitted = session->observability_emitted;
	request.filtered = session->observability_filtered;
	request.sampled = session->observability_sampled;
	request.dropped = session->observability_dropped;
	request.last_sequence = session->observability_last_sequence;
	request.generation = session->observability_generation;
	request.lineage_id = faisal_task_get_lineage(current);
	request.agent_id = faisal_task_get_agent(current);
	request.task_id = task_pid_nr(current);
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_world_subscription(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_world_subscription subscription;
	unsigned long flags;

	if (copy_from_user(&subscription, (void __user *)arg,
			   sizeof(subscription)))
		return -EFAULT;
	if (subscription.size != sizeof(subscription) || subscription.flags ||
	    subscription.class_mask >> AGI_LC_WORLD_EVENT_MAX ||
	    subscription.min_priority > AGI_LC_WORLD_PRIORITY_CRITICAL ||
	    subscription.queue_policy > AGI_LC_WORLD_QUEUE_DROP_LOW ||
	    subscription.delivered || subscription.filtered ||
	    subscription.dropped || subscription.last_loss_sequence ||
	    subscription.reserved[0] || subscription.reserved[1])
		return -EINVAL;
	if (subscription.lineage_id &&
	    subscription.lineage_id != session->session_id)
		return -EPERM;
	if (subscription.agent_id &&
	    subscription.agent_id != faisal_task_get_agent(current) &&
	    !agi_lc_find_agent(session, subscription.agent_id))
		return -EPERM;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, flags);
	session->world_class_mask = subscription.class_mask;
	session->world_enabled = subscription.class_mask != 0;
	session->world_lineage_id = subscription.lineage_id;
	session->world_agent_id = subscription.agent_id;
	session->world_min_priority = subscription.min_priority;
	session->world_queue_policy = subscription.queue_policy;
	session->world_delivered = 0;
	session->world_filtered = 0;
	session->world_dropped = 0;
	session->world_last_loss_sequence = 0;
	session->world_resync_required = false;
	session->world_ack_sequence = 0;
	session->world_resync_sequence = 0;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return 0;
}

static int agi_lc_get_world_subscription(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_world_subscription subscription;
	unsigned long flags;

	if (copy_from_user(&subscription, (void __user *)arg,
			   sizeof(subscription)))
		return -EFAULT;
	if (subscription.size != sizeof(subscription) || subscription.flags ||
	    subscription.reserved[0] || subscription.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	spin_lock_irqsave(&session->queue_lock, flags);
	subscription.class_mask = session->world_class_mask;
	subscription.lineage_id = session->world_lineage_id;
	subscription.agent_id = session->world_agent_id;
	subscription.min_priority = session->world_min_priority;
	subscription.queue_policy = session->world_queue_policy;
	subscription.delivered = session->world_delivered;
	subscription.filtered = session->world_filtered;
	subscription.dropped = session->world_dropped;
	subscription.last_loss_sequence = session->world_last_loss_sequence;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &subscription,
			 sizeof(subscription)))
		return -EFAULT;
	return 0;
}

static void agi_lc_remove_record_locked(struct agi_lc_session *session,
						u32 index)
{
	u32 last = (session->tail + AGI_LC_RING_SIZE - 1) % AGI_LC_RING_SIZE;

	while (index != last) {
		u32 next = (index + 1) % AGI_LC_RING_SIZE;

		session->records[index] = session->records[next];
		index = next;
	}
	session->tail = last;
	session->count--;
}

static void agi_lc_get_current_parent_pid_t(pid_t *parent_pid,
						pid_t *parent_tgid)
{
	struct task_struct *parent;

	*parent_pid = 0;
	*parent_tgid = 0;
	rcu_read_lock();
	parent = rcu_dereference(current->real_parent);
	if (parent) {
		*parent_pid = task_pid_nr(parent);
		*parent_tgid = task_tgid_nr(parent);
	}
	rcu_read_unlock();
}

static void agi_lc_get_current_parent_ids(u64 *parent_pid, u64 *parent_tgid)
{
	pid_t parent_pid_value;
	pid_t parent_tgid_value;

	agi_lc_get_current_parent_pid_t(&parent_pid_value, &parent_tgid_value);
	*parent_pid = parent_pid_value;
	*parent_tgid = parent_tgid_value;
}

static void agi_lc_capture_attribution(struct agi_lc_session *session,
					 struct agi_lc_attribution *attribution,
					 u64 sequence, u16 type, s32 status,
					 u64 correlation, u64 metadata)
{
	struct agi_lc_agent_record *agent;
	struct agi_lc_light_agent_record *light = NULL;
	u64 budget_ns, elapsed_ns, limit_pages, current_pages;
	bool budget_exhausted, memory_exceeded;
	u64 agent_id = faisal_task_get_agent(current);
	u32 i;

	memset(attribution, 0, sizeof(*attribution));
	attribution->size = sizeof(*attribution);
	attribution->sequence = sequence;
	attribution->action_type = type;
	attribution->status = status;
	attribution->session_id = session->session_id;
	attribution->lineage_id = faisal_task_get_lineage(current);
	attribution->agent_id = agent_id;
	attribution->task_id = task_pid_nr(current);
	attribution->tgid = task_tgid_nr(current);
	agi_lc_get_current_parent_ids(&attribution->parent_task_id,
				       &attribution->parent_tgid);
	attribution->capabilities_effective =
		agi_lc_capability_mask(current_cred()->cap_effective);
	attribution->capabilities_permitted =
		agi_lc_capability_mask(current_cred()->cap_permitted);
	attribution->phase = faisal_task_get_phase(current);
	attribution->correlation = correlation;
	attribution->metadata = metadata;
	attribution->recorded_at_ns = ktime_get_ns();
	faisal_task_get_budget(current, &budget_ns, &elapsed_ns, &budget_exhausted);
	faisal_task_get_memory_limit(current, &limit_pages, &current_pages,
				     &memory_exceeded);
	attribution->cpu_budget_ns = budget_ns;
	attribution->cpu_elapsed_ns = elapsed_ns;
	attribution->memory_limit_pages = limit_pages;
	attribution->memory_current_pages = current_pages;
	attribution->state = budget_exhausted || memory_exceeded ?
		AGI_LC_AGENT_STATE_BLOCKED : AGI_LC_AGENT_STATE_RUNNING;

	agent = agi_lc_find_agent(session, agent_id);
	if (!agent && session->light_agents && agent_id &&
	    agent_id <= AGI_LC_LIGHT_AGENT_MAX &&
	    session->light_agents[agent_id - 1].valid)
		light = &session->light_agents[agent_id - 1];
	if (agent) {
		attribution->parent_agent = agent->parent_agent;
		attribution->creator_pid = agent->creator_pid;
		attribution->creator_tgid = agent->creator_tgid;
		attribution->parent_task_id = agent->parent_pid;
		attribution->creator_uid = agent->creator_uid;
		attribution->creator_euid = agent->creator_euid;
		attribution->state = agent->state;
	} else if (light) {
		attribution->parent_agent = light->parent_agent;
		attribution->creator_pid = light->creator_pid;
		attribution->creator_tgid = light->creator_tgid;
		attribution->parent_task_id = light->parent_pid;
		attribution->creator_uid = light->creator_uid;
		attribution->creator_euid = light->creator_euid;
		attribution->state = light->state;
	}
	for (i = 0; i < AGI_LC_CAPABILITY_RECORDS; i++) {
		struct agi_lc_capability_record *grant = &session->capabilities[i];

		if (!grant->valid || grant->grant.status != AGI_LC_CAP_STATUS_ACTIVE ||
		    grant->grant.agent_id != agent_id)
			continue;
		attribution->authority_rights |= grant->grant.rights;
		attribution->sandbox_flags |= grant->grant.sandbox_flags;
		attribution->active_grants++;
		attribution->authority_generation = max_t(u64,
			attribution->authority_generation, grant->grant.generation);
	}
	session->attributions[sequence % AGI_LC_RING_SIZE] = *attribution;
}

static bool agi_lc_observability_sample(struct agi_lc_session *session,
						 u16 type, u64 sequence)
{
	if (unlikely(!session->observability_enabled))
		return false;
	if (!type || type > 64 ||
	    !(session->observability_event_mask & (1ULL << (type - 1)))) {
		session->observability_filtered++;
		return false;
	}
	session->observability_emitted++;
	if ((session->observability_flags & AGI_LC_OBSERVABILITY_FLAG_SAMPLE) &&
	    session->observability_sample_period > 1) {
		session->observability_sample_index++;
		if (session->observability_sample_index <
		    session->observability_sample_period)
			return false;
		session->observability_sample_index = 0;
	}
	session->observability_sampled++;
	session->observability_last_sequence = sequence;
	return true;
}

static int agi_lc_push_record_ex(struct agi_lc_session *session, u16 type,
							   s32 status, u64 correlation,
							   u64 metadata, u64 *sequence_out)
{

	struct agi_lc_record *record;
	unsigned long flags;
	u64 class_mask;
	u64 lineage_id;
	u64 agent_id;
	u64 event_sequence;
	u32 priority;
	u32 i;
	bool world_event;
	bool observability_sampled_event = false;
	bool active = false;
	bool queued = false;
	bool light_wake = false;
	int ret = 0;

	spin_lock_irqsave(&session->queue_lock, flags);
	if (!session->revoked && session->session_id) {
		active = true;
					event_sequence = session->next_sequence++;
			observability_sampled_event =
				agi_lc_observability_sample(session, type, event_sequence);
			agi_lc_capture_attribution(session,

			&session->attributions[event_sequence % AGI_LC_RING_SIZE],
			event_sequence, type, status, correlation, metadata);
		session->change_generation++;
		if (status < 0) {
			session->failure_count++;
			session->last_failure_sequence = event_sequence;
		}
		if (session->light_agents && type && type <= 64) {
			for (i = 0; i < AGI_LC_LIGHT_AGENT_MAX; i++) {
				struct agi_lc_light_agent_record *light =
					&session->light_agents[i];

				if (!light->valid ||
				    !(light->event_mask & (1ULL << (type - 1))))
					continue;
				light->events_delivered++;
				light->last_event_sequence = event_sequence;
				light->generation++;
				light_wake = true;
			}
		}
		class_mask = agi_lc_world_class_mask(type);
		world_event = class_mask != 0 && session->world_enabled;
		priority = agi_lc_world_priority(type, status);
		lineage_id = faisal_task_get_lineage(current);
		agent_id = faisal_task_get_agent(current);
		if (world_event &&
		    (!(session->world_class_mask & class_mask) ||
		     (session->world_lineage_id &&
		      session->world_lineage_id != lineage_id) ||
		     (session->world_agent_id &&
		      session->world_agent_id != agent_id) ||
		     priority < session->world_min_priority)) {
			session->world_filtered++;
			if (sequence_out)
				*sequence_out = event_sequence;
			goto out_unlock;
		}
		if (type && type <= 64 &&
		    !(session->event_mask & (1ULL << (type - 1)))) {
			if (world_event)
				session->world_filtered++;
			if (sequence_out)
				*sequence_out = event_sequence;
			goto out_unlock;
		}
		if (session->count == AGI_LC_RING_SIZE) {
			ret = agi_lc_queue_full_locked(session, world_event, priority,
					event_sequence, observability_sampled_event,
					sequence_out);
			if (ret)
				goto out_unlock;
		}
		record = &session->records[session->tail];
		record->sequence = event_sequence;
		record->timestamp_ns = ktime_get_ns();
		record->session_id = session->session_id;
		record->pid = task_pid_nr(current);
		record->tgid = task_tgid_nr(current);
		record->type = type;
					record->flags = world_event ? priority : 0;
			if (type == AGI_LC_EVENT_VERIFY &&
			    (metadata & AGI_LC_RV_METADATA_TAG_MASK) == AGI_LC_RV_METADATA_TAG)
				record->flags = AGI_LC_VERIFY_FLAG_RV_OBSERVATION;

		record->status = status;
		record->reserved = 0;
		record->correlation = correlation;
		record->metadata = metadata;
		record->lineage_id = lineage_id;
		if (world_event)
			session->world_delivered++;
		if (sequence_out)
			*sequence_out = record->sequence;
		session->tail = (session->tail + 1) % AGI_LC_RING_SIZE;
		session->count++;
		queued = true;
	}

out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);

	if (queued)
		wake_up_interruptible(&session->read_wait);
	if (light_wake)
		wake_up_interruptible(&session->light_wait);
	if (!active)
		return -ESHUTDOWN;
	return ret;
}

static int agi_lc_push_record(struct agi_lc_session *session, u16 type,
	s32 status, u64 correlation, u64 metadata)
{
	return agi_lc_push_record_ex(session, type, status, correlation,
		metadata, NULL);
}

#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
void agi_lc_rv_report(const char *monitor_name, s32 status)
{
	struct agi_lc_session *session;
	unsigned long flags;
	u64 sequence;
	u64 metadata;
	u32 monitor_hash = 2166136261U;
	const unsigned char *p;

	if (!monitor_name || !*monitor_name)
		return;
	for (p = (const unsigned char *)monitor_name; *p; p++)
		monitor_hash = (monitor_hash ^ *p) * 16777619U;
	sequence = atomic64_inc_return(&agi_lc_rv_sequence);
	metadata = AGI_LC_RV_METADATA_TAG |
		(((u64)(monitor_hash & 0xffffU)) << AGI_LC_RV_METADATA_MONITOR_SHIFT) |
		(sequence & AGI_LC_RV_METADATA_SEQUENCE_MASK);

	spin_lock_irqsave(&agi_lc_rv_sessions_lock, flags);
	list_for_each_entry(session, &agi_lc_rv_sessions, rv_node) {
		if (!READ_ONCE(session->revoked) && READ_ONCE(session->session_id))
			(void)agi_lc_push_record_ex(session, AGI_LC_EVENT_VERIFY,
						    status, sequence, metadata, NULL);
	}
	spin_unlock_irqrestore(&agi_lc_rv_sessions_lock, flags);
}
EXPORT_SYMBOL_GPL(agi_lc_rv_report);
#endif

static bool agi_lc_lease_resource_valid(u32 resource)
{
	switch (resource) {
	case AGI_LC_LEASE_NETWORK:
	case AGI_LC_LEASE_STORAGE:
	case AGI_LC_LEASE_ACCELERATOR:
	case AGI_LC_LEASE_TOOL:
		return true;
	default:
		return false;
	}
}

#define FAISAL_LEASE_MAX_NS (7ULL * 24 * 60 * 60 * NSEC_PER_SEC)

static struct agi_lc_lease_record *
agi_lc_find_lease(struct agi_lc_session *session, u64 lease_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_LEASE_MAX; i++)
		if (session->leases[i].lease_id == lease_id)
			return &session->leases[i];
	return NULL;
}

static int agi_lc_lease_acquire(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_lease lease;
	struct agi_lc_lease_record *record = NULL;
	u64 now;
	u64 duration;
	u32 i;
	int ret;

	if (copy_from_user(&lease, (void __user *)arg, sizeof(lease)))
		return -EFAULT;
	if (lease.size != sizeof(lease) || lease.flags ||
	    !agi_lc_lease_resource_valid(lease.resource) || lease.lease_id ||
	    lease.active || lease.owner_agent || !lease.expires_ns ||
	    lease.reserved[0] || lease.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!faisal_task_get_agent(current))
		return -EPERM;

	duration = lease.expires_ns;
	if (duration > FAISAL_LEASE_MAX_NS)
		return -ERANGE;
	now = ktime_get_ns();
	if (now > U64_MAX - duration)
		return -ERANGE;
	for (i = 0; i < AGI_LC_LEASE_MAX; i++) {
		if (!session->leases[i].active ||
		    session->leases[i].expires_ns <= now) {
			record = &session->leases[i];
			break;
		}
	}
	if (!record)
		return -ENOSPC;

	record->active = true;
	record->resource = lease.resource;
	record->lease_id = atomic64_inc_return(&agi_lc_next_lease);
	record->owner_agent = faisal_task_get_agent(current);
	record->expires_ns = now + duration;
	lease.lease_id = record->lease_id;
	lease.owner_agent = record->owner_agent;
	lease.expires_ns = record->expires_ns;
	lease.active = 1;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_LEASE, 0,
					 lease.correlation, lease.lease_id);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &lease, sizeof(lease)))
		return -EFAULT;
	return 0;
}

static int agi_lc_lease_check(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_lease lease;
	struct agi_lc_lease_record *record;
	bool active;

	if (copy_from_user(&lease, (void __user *)arg, sizeof(lease)))
		return -EFAULT;
	if (lease.size != sizeof(lease) || lease.flags || !lease.lease_id ||
	    lease.active || lease.owner_agent || lease.expires_ns ||
	    lease.reserved[0] || lease.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	record = agi_lc_find_lease(session, lease.lease_id);
	if (!record)
		return -ENOENT;
	active = record->active && record->expires_ns > ktime_get_ns();
	if (!active)
		record->active = false;
	lease.resource = record->resource;
	lease.active = active;
	lease.owner_agent = record->owner_agent;
	lease.expires_ns = record->expires_ns;
	lease.correlation = 0;
	if (copy_to_user((void __user *)arg, &lease, sizeof(lease)))
		return -EFAULT;
	return 0;
}

static int agi_lc_lease_revoke(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_lease lease;
	struct agi_lc_lease_record *record;
	int ret;

	if (copy_from_user(&lease, (void __user *)arg, sizeof(lease)))
		return -EFAULT;
	if (lease.size != sizeof(lease) || lease.flags || !lease.lease_id ||
	    lease.resource || lease.active || lease.owner_agent ||
	    lease.expires_ns || lease.reserved[0] || lease.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	record = agi_lc_find_lease(session, lease.lease_id);
	if (!record)
		return -ENOENT;
	if (record->owner_agent != faisal_task_get_agent(current) &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	record->active = false;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_LEASE, -ECANCELED,
					 lease.correlation, lease.lease_id);
	return ret;
}

static u64 agi_lc_intent_required_rights(u32 operation_class)
{
	switch (operation_class) {
	case AGI_LC_INTENT_OP_FILESYSTEM:
		return AGI_LC_CAP_FS_WRITE;
	case AGI_LC_INTENT_OP_NETWORK:
		return AGI_LC_CAP_NET_CONNECT;
	case AGI_LC_INTENT_OP_BROWSER:
		return AGI_LC_CAP_BROWSER_CONTROL;
	case AGI_LC_INTENT_OP_DEVICE:
		return AGI_LC_CAP_DEVICE_USE;
	case AGI_LC_INTENT_OP_PRIVILEGED:
	case AGI_LC_INTENT_OP_TOOL:
		return AGI_LC_CAP_PRIVILEGED_API;
	case AGI_LC_INTENT_OP_MODEL_DEPLOYMENT:
		return AGI_LC_CAP_COMPUTE_EXECUTE;
	default:
		return 0;
	}
}

static struct agi_lc_intent_lease_record *
agi_lc_find_intent_lease(struct agi_lc_session *session, u64 lease_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_INTENT_LEASE_RECORDS; i++)
		if (session->intent_leases[i].valid &&
		    session->intent_leases[i].lease.lease_id == lease_id)
			return &session->intent_leases[i];
	return NULL;
}

static int agi_lc_intent_common_validate(struct agi_lc_session *session,
						struct agi_lc_intent_lease *lease)
{
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!faisal_task_get_agent(current) ||
	    lease->agent_id != faisal_task_get_agent(current))
		return -EPERM;
	if (!lease->agent_capability || !lease->grant_id ||
	    !lease->grant_capability)
		return -EINVAL;
	return 0;
}

static int agi_lc_intent_authority_validate(struct agi_lc_session *session,
						struct agi_lc_intent_lease *lease)
{
	struct agi_lc_capability_record *record;
	u64 required;
	int ret;

	ret = agi_lc_intent_common_validate(session, lease);
	if (ret)
		return ret;
	record = agi_lc_find_capability(session, lease->grant_id,
					lease->grant_capability, false);
	if (!record || record->grant.agent_id != lease->agent_id ||
	    record->grant.agent_capability != lease->agent_capability)
		return -EACCES;
	required = agi_lc_intent_required_rights(lease->operation_class);
	if (!required || (record->grant.rights & required) != required)
		return -EACCES;
	if (record->grant.scope_kind != AGI_LC_CAP_SCOPE_NONE &&
	    record->grant.scope_id != lease->scope_id)
		return -EACCES;
	return 0;
}

static void agi_lc_intent_set_status(struct agi_lc_intent_lease *lease,
						u64 now)
{
	if (lease->status == AGI_LC_INTENT_STATUS_REVOKED)
		return;
	if (now >= lease->expires_ns)
		lease->status = AGI_LC_INTENT_STATUS_EXPIRED;
	else if (!lease->remaining_uses)
		lease->status = AGI_LC_INTENT_STATUS_EXHAUSTED;
	else
		lease->status = AGI_LC_INTENT_STATUS_ACTIVE;
}

static int agi_lc_intent_lease_control(struct agi_lc_session *session,
						unsigned long arg)
{
	struct agi_lc_intent_lease request;
	struct agi_lc_intent_lease_record *record = NULL;
	u64 now;
	u32 i;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) ||
	    request.operation < AGI_LC_INTENT_LEASE_ACQUIRE ||
	    request.operation > AGI_LC_INTENT_LEASE_REVOKE ||
	    request.flags & ~AGI_LC_INTENT_LEASE_FLAGS_ALL ||
	    request.operation_class > AGI_LC_INTENT_OP_MAX ||
	    request.resource_mask & ~AGI_LC_RESOURCE_ALL ||
	    request.status || request.reserved[0] || request.reserved[1])
		return -EINVAL;

	if (request.operation == AGI_LC_INTENT_LEASE_ACQUIRE) {
		if (!request.operation_class || !request.resource_mask ||
		    request.lease_id || request.generation || request.expires_ns == 0 ||
		    request.max_uses == 0 || request.remaining_uses ||
		    request.use_sequence || request.created_ns || request.last_used_ns ||
		    !request.grant_id || !request.grant_capability ||
		    !request.agent_id || !request.agent_capability ||
		    !memchr_inv(request.intent_digest, 0,
				 sizeof(request.intent_digest)) ||
		    (request.flags & AGI_LC_INTENT_LEASE_FLAG_SINGLE_USE &&
		     request.max_uses != 1))
			return -EINVAL;
		if (request.max_uses > AGI_LC_INTENT_MAX_USES ||
		    request.expires_ns > AGI_LC_INTENT_MAX_TTL_NS)
			return -ERANGE;
		ret = agi_lc_intent_authority_validate(session, &request);
		if (ret)
			return ret;
		now = ktime_get_ns();
		if (now > U64_MAX - request.expires_ns)
			return -ERANGE;
		for (i = 0; i < AGI_LC_INTENT_LEASE_RECORDS; i++) {
			struct agi_lc_intent_lease_record *candidate =
				&session->intent_leases[i];

			if (!candidate->valid || candidate->revoked ||
			    candidate->lease.status != AGI_LC_INTENT_STATUS_ACTIVE ||
			    candidate->lease.expires_ns <= now ||
			    !candidate->lease.remaining_uses) {
				record = candidate;
				break;
			}
		}
		if (!record)
			return -ENOSPC;
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->lease = request;
		record->lease.lease_id = atomic64_inc_return(&agi_lc_next_intent_lease);
		if (!record->lease.lease_id)
			record->lease.lease_id =
				atomic64_inc_return(&agi_lc_next_intent_lease);
		record->lease.lineage_id = session->session_id;
		record->lease.generation = 1;
		record->lease.created_ns = now;
		record->lease.expires_ns = now + request.expires_ns;
		record->lease.remaining_uses = request.max_uses;
		record->lease.status = AGI_LC_INTENT_STATUS_ACTIVE;
		request = record->lease;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_INTENT_LEASE, 0,
					 request.correlation, request.lease_id);
		if (ret) {
			record->valid = false;
			return ret;
		}
		if (copy_to_user((void __user *)arg, &request, sizeof(request)))
			return -EFAULT;
		return 0;
	}

	if (!request.lease_id || !request.operation_class ||
	    !request.resource_mask || !request.generation ||
	    !request.agent_id || !request.agent_capability ||
	    !request.grant_id || !request.grant_capability ||
	    !memchr_inv(request.intent_digest, 0, sizeof(request.intent_digest)))
		return -EINVAL;
	ret = agi_lc_intent_common_validate(session, &request);
	if (ret)
		return ret;
	record = agi_lc_find_intent_lease(session, request.lease_id);
	if (!record)
		return -ENOENT;
	if (record->lease.agent_id != request.agent_id ||
	    record->lease.agent_capability != request.agent_capability ||
	    record->lease.grant_id != request.grant_id ||
	    record->lease.grant_capability != request.grant_capability ||
	    record->lease.flags != request.flags ||
	    record->lease.lineage_id != session->session_id ||
	    record->lease.generation != request.generation ||
	    record->lease.operation_class != request.operation_class ||
	    record->lease.resource_mask != request.resource_mask ||
	    record->lease.scope_id != request.scope_id ||
	    memcmp(record->lease.intent_digest, request.intent_digest,
		   sizeof(request.intent_digest)))
		return -EACCES;

	now = ktime_get_ns();
	agi_lc_intent_set_status(&record->lease, now);
	if (request.operation == AGI_LC_INTENT_LEASE_QUERY) {
		request = record->lease;
		request.operation = AGI_LC_INTENT_LEASE_QUERY;
		if (copy_to_user((void __user *)arg, &request, sizeof(request)))
			return -EFAULT;
		return 0;
	}
	if (request.operation == AGI_LC_INTENT_LEASE_REVOKE) {
		record->revoked = true;
		record->lease.status = AGI_LC_INTENT_STATUS_REVOKED;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_INTENT_LEASE,
					 -ECANCELED, request.correlation,
					 request.lease_id);
			return ret;
	}
	if (request.operation != AGI_LC_INTENT_LEASE_CONSUME)
		return -EINVAL;
	if (record->revoked || record->lease.status == AGI_LC_INTENT_STATUS_REVOKED)
		return -EKEYREVOKED;
	if (record->lease.status == AGI_LC_INTENT_STATUS_EXPIRED)
		return -ETIME;
	if (record->lease.status == AGI_LC_INTENT_STATUS_EXHAUSTED)
		return -ENOSPC;
	if (record->lease.flags & AGI_LC_INTENT_LEASE_FLAG_REQUIRE_PROVENANCE &&
	    session->verification_state != AGI_LC_VERIFY_MATCHED)
		return -EKEYREJECTED;

	record->lease.remaining_uses--;
	record->lease.use_sequence++;
	record->lease.last_used_ns = now;
	agi_lc_intent_set_status(&record->lease, now);
	request = record->lease;
	request.operation = AGI_LC_INTENT_LEASE_CONSUME;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_INTENT_LEASE, 0,
				 request.correlation, request.use_sequence);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_budget(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_budget budget;
	int ret;

	if (copy_from_user(&budget, (void __user *)arg, sizeof(budget)))
		return -EFAULT;
	if (budget.size != sizeof(budget) || budget.flags ||
	    budget.elapsed_ns || budget.exhausted || budget.reserved ||
	    budget.reserved2[0] || budget.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	ret = faisal_task_set_budget(current, budget.cpu_time_ns);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_BUDGET, 0,
					  budget.correlation, budget.cpu_time_ns);
}

static int agi_lc_get_budget(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_budget budget;
	bool exhausted;

	if (copy_from_user(&budget, (void __user *)arg, sizeof(budget)))
		return -EFAULT;
	if (budget.size != sizeof(budget) || budget.flags || budget.reserved ||
	    budget.reserved2[0] || budget.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	faisal_task_get_budget(current, &budget.cpu_time_ns,
				      &budget.elapsed_ns, &exhausted);
	budget.exhausted = exhausted;
	budget.correlation = 0;
	if (copy_to_user((void __user *)arg, &budget, sizeof(budget)))
		return -EFAULT;
	return 0;
}

static int agi_lc_verify_checkpoint(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_verify verify;
	struct agi_lc_checkpoint_record record;
	struct agi_lc_handoff lookup = { 0 };
	bool found = false;
	bool matched = false;
	int ret;

	if (copy_from_user(&verify, (void __user *)arg, sizeof(verify)))
		return -EFAULT;
	if (verify.size != sizeof(verify) || verify.flags || verify.status ||
	    verify.state != AGI_LC_VERIFY_UNVERIFIED || !verify.checkpoint_id ||
	    !verify.checkpoint_sequence || verify.reserved[0] ||
	    verify.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	lookup.checkpoint_id = verify.checkpoint_id;
	found = agi_lc_find_checkpoint(&lookup, &record);
	if (found) {
		matched = record.checkpoint_sequence == verify.checkpoint_sequence &&
			record.parent_sequence == verify.parent_sequence &&
			!memcmp(record.state_digest, verify.state_digest,
				sizeof(record.state_digest));
	}
	if (matched) {
		verify.status = 0;
		verify.state = AGI_LC_VERIFY_MATCHED;
		session->verification_state = AGI_LC_VERIFY_MATCHED;
		session->verification_checkpoint_id = verify.checkpoint_id;
		session->verification_checkpoint_sequence =
			verify.checkpoint_sequence;
		session->verification_parent_sequence = verify.parent_sequence;
		memcpy(session->verification_digest, verify.state_digest,
		       sizeof(session->verification_digest));
	} else {
		verify.status = found ? -EINVAL : -ENOENT;
		verify.state = AGI_LC_VERIFY_FAILED;
		session->verification_state = AGI_LC_VERIFY_FAILED;
	}
	ret = agi_lc_push_record(session, AGI_LC_EVENT_VERIFY, verify.status,
					 verify.correlation, verify.checkpoint_id);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &verify, sizeof(verify)))
		return -EFAULT;
	return verify.status;
}

static int agi_lc_export_checkpoint(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_handoff handoff;
	unsigned long flags;
	u64 event_mask;
	int ret;

	if (copy_from_user(&handoff, (void __user *)arg, sizeof(handoff)))
		return -EFAULT;
	if (handoff.size != sizeof(handoff) || handoff.flags ||
	    handoff.validated || handoff.reserved || handoff.reserved2[0] ||
	    handoff.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!session->checkpoint_valid)
		return -ENOENT;
	if (session->verification_state != AGI_LC_VERIFY_MATCHED ||
	    session->verification_checkpoint_id != session->checkpoint_id ||
	    session->verification_checkpoint_sequence !=
	    session->checkpoint_sequence ||
	    session->verification_parent_sequence !=
	    session->checkpoint_parent_sequence ||
	    memcmp(session->verification_digest, session->checkpoint_digest,
		    sizeof(session->verification_digest)))
		return -EKEYREJECTED;
	if (READ_ONCE(session->gate_open))
		return -EBUSY;

	spin_lock_irqsave(&session->queue_lock, flags);
	event_mask = session->event_mask;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	memset(&handoff, 0, sizeof(handoff));
	handoff.size = sizeof(handoff);
	handoff.checkpoint_id = session->checkpoint_id;
	handoff.checkpoint_sequence = session->checkpoint_sequence;
	handoff.parent_sequence = session->checkpoint_parent_sequence;
	handoff.phase = session->checkpoint_phase;
	handoff.gate_open = 0;
	handoff.event_mask = event_mask;
	handoff.cpu_budget_ns = session->checkpoint_cpu_budget_ns;
	handoff.memory_limit_pages = session->checkpoint_memory_limit_pages;
	memcpy(handoff.state_digest, session->checkpoint_digest,
	       sizeof(handoff.state_digest));
	handoff.correlation = 0;
	handoff.validated = 1;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_HANDOFF, 0,
					  handoff.correlation,
					  handoff.checkpoint_sequence);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &handoff, sizeof(handoff)))
		return -EFAULT;
	return 0;
}

static int agi_lc_import_checkpoint(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_handoff handoff;
	struct agi_lc_checkpoint_record record;
	int ret;

	if (copy_from_user(&handoff, (void __user *)arg, sizeof(handoff)))
		return -EFAULT;
	if (handoff.size != sizeof(handoff) || handoff.flags ||
	    handoff.validated || handoff.gate_open || handoff.reserved ||
	    handoff.reserved2[0] || handoff.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (READ_ONCE(session->gate_open))
		return -EBUSY;
	if (session->verification_state != AGI_LC_VERIFY_MATCHED ||
	    session->verification_checkpoint_id != handoff.checkpoint_id ||
	    session->verification_checkpoint_sequence !=
	    handoff.checkpoint_sequence ||
	    session->verification_parent_sequence != handoff.parent_sequence ||
	    memcmp(session->verification_digest, handoff.state_digest,
		    sizeof(session->verification_digest)))
		return -EKEYREJECTED;
	if (!agi_lc_find_checkpoint(&handoff, &record))
		return -ENOENT;
	if (record.checkpoint_sequence != handoff.checkpoint_sequence ||
	    record.parent_sequence != handoff.parent_sequence ||
	    record.phase != handoff.phase || record.event_mask != handoff.event_mask ||
	    record.cpu_budget_ns != handoff.cpu_budget_ns ||
	    record.memory_limit_pages != handoff.memory_limit_pages ||
	    memcmp(record.state_digest, handoff.state_digest,
		   sizeof(record.state_digest)))
		return -EINVAL;

	ret = faisal_task_set_phase(current, record.phase);
	if (ret)
		return ret;
	ret = faisal_task_set_budget(current, record.cpu_budget_ns);
	if (ret)
		return ret;
	ret = faisal_task_set_memory_limit(current, record.memory_limit_pages);
	if (ret)
		return ret;
	session->event_mask = record.event_mask;
	session->gate_open = false;
	session->checkpoint_valid = true;
	session->checkpoint_id = record.checkpoint_id;
	session->checkpoint_sequence = record.checkpoint_sequence;
	session->checkpoint_parent_sequence = record.parent_sequence;
	session->checkpoint_cpu_budget_ns = record.cpu_budget_ns;
	session->checkpoint_memory_limit_pages = record.memory_limit_pages;
	session->checkpoint_phase = record.phase;
	memcpy(session->checkpoint_digest, record.state_digest,
	       sizeof(session->checkpoint_digest));
	if (record.manifest_valid) {
		session->checkpoint_manifest = record.manifest;
		session->checkpoint_manifest_valid = true;
	}
	if (session->recovery_state == AGI_LC_RECOVERY_RESTORE_PENDING) {
		session->recovery_state = AGI_LC_RECOVERY_RESTORED;
		session->recovery_checkpoint_id = record.checkpoint_id;
		session->recovery_checkpoint_sequence = record.checkpoint_sequence;
	}
	handoff.validated = 1;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_HANDOFF, 0,
					  handoff.correlation,
					  handoff.checkpoint_sequence);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &handoff, sizeof(handoff)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_memory_budget(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_memory_budget budget;
	int ret;

	if (copy_from_user(&budget, (void __user *)arg, sizeof(budget)))
		return -EFAULT;
	if (budget.size != sizeof(budget) || budget.flags ||
	    budget.current_pages || budget.exceeded || budget.reserved ||
	    budget.reserved2[0] || budget.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	ret = faisal_task_set_memory_limit(current, budget.limit_pages);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_BUDGET, 0,
					  budget.correlation, budget.limit_pages);
}

static int agi_lc_get_memory_budget(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_memory_budget budget;
	bool exceeded;

	if (copy_from_user(&budget, (void __user *)arg, sizeof(budget)))
		return -EFAULT;
	if (budget.size != sizeof(budget) || budget.flags || budget.reserved ||
	    budget.reserved2[0] || budget.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	faisal_task_get_memory_limit(current, &budget.limit_pages,
					     &budget.current_pages, &exceeded);
	budget.exceeded = exceeded;
	budget.correlation = 0;
	if (copy_to_user((void __user *)arg, &budget, sizeof(budget)))
		return -EFAULT;
	return 0;
}

static int agi_lc_checkpoint(struct agi_lc_session *session,
					  unsigned long arg)
{
	struct agi_lc_checkpoint checkpoint;
	unsigned long flags;
	u64 last_sequence;
	u64 sequence;
	u64 event_mask;
	u64 cpu_budget_ns;
	u64 elapsed_ns;
	u64 memory_limit_pages;
	u64 current_pages;
	bool gate_open;
	bool budget_exhausted;
	bool memory_exceeded;
	int ret;

	if (copy_from_user(&checkpoint, (void __user *)arg,
			   sizeof(checkpoint)))
		return -EFAULT;
	if (checkpoint.size != sizeof(checkpoint) || checkpoint.flags ||
	    checkpoint.reserved || checkpoint.reserved2[0] ||
	    checkpoint.reserved2[1] || !checkpoint.checkpoint_id ||
	    checkpoint.checkpoint_sequence)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, flags);
	last_sequence = session->next_sequence ? session->next_sequence - 1 : 0;
	gate_open = session->gate_open;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (gate_open)
		return -EBUSY;
	if (checkpoint.parent_sequence > last_sequence)
		return -EINVAL;

	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_CHECKPOINT,
					    checkpoint.status, checkpoint.correlation,
					    checkpoint.parent_sequence, &sequence);
	if (ret)
		return ret;
	checkpoint.checkpoint_sequence = sequence;
	faisal_task_get_budget(current, &cpu_budget_ns, &elapsed_ns,
				       &budget_exhausted);
	faisal_task_get_memory_limit(current, &memory_limit_pages,
					     &current_pages, &memory_exceeded);
	session->checkpoint_valid = true;
	session->checkpoint_id = checkpoint.checkpoint_id;
	session->checkpoint_sequence = sequence;
	session->checkpoint_parent_sequence = checkpoint.parent_sequence;
	session->checkpoint_cpu_budget_ns = cpu_budget_ns;
	session->checkpoint_memory_limit_pages = memory_limit_pages;
	session->checkpoint_phase = faisal_task_get_phase(current);
	memcpy(session->checkpoint_digest, checkpoint.state_digest,
	       sizeof(session->checkpoint_digest));
	session->verification_state = AGI_LC_VERIFY_UNVERIFIED;
	session->verification_checkpoint_id = 0;
	session->verification_checkpoint_sequence = 0;
	session->verification_parent_sequence = 0;
	memset(session->verification_digest, 0,
	       sizeof(session->verification_digest));
	session->checkpoint_manifest_valid = false;
	memset(&session->checkpoint_manifest, 0,
	       sizeof(session->checkpoint_manifest));
	session->recovery_state = AGI_LC_RECOVERY_NONE;
	session->recovery_sequence = 0;
	session->recovery_checkpoint_id = 0;
	session->recovery_checkpoint_sequence = 0;
	spin_lock_irqsave(&session->queue_lock, flags);
	event_mask = session->event_mask;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	agi_lc_store_checkpoint(session, &checkpoint, sequence, event_mask);
	if (copy_to_user((void __user *)arg, &checkpoint,
			 sizeof(checkpoint)))
		return -EFAULT;
	return 0;
}

static int agi_lc_checkpoint_regions_validate(struct agi_lc_session *session,
						 const struct agi_lc_checkpoint_manifest *manifest)
{
	u32 i;

	if (manifest->region_count > AGI_LC_CHECKPOINT_REGION_MAX)
		return -E2BIG;
	mutex_lock(&agi_lc_memory_lock);
	for (i = 0; i < manifest->region_count; i++) {
		struct agi_lc_memory_record *record;

		if (!manifest->region_ids[i] || !manifest->region_generations[i]) {
			mutex_unlock(&agi_lc_memory_lock);
			return -EINVAL;
		}
		record = agi_lc_memory_find_locked(session,
						   manifest->region_ids[i]);
		if (!record || record->revoked ||
		    (record->session_id &&
		     record->session_id != session->session_id) ||
		    record->generation != manifest->region_generations[i]) {
			mutex_unlock(&agi_lc_memory_lock);
			return -EACCES;
		}
	}
	mutex_unlock(&agi_lc_memory_lock);
	return 0;
}

static void agi_lc_recovery_fill(const struct agi_lc_checkpoint_record *record,
					 struct agi_lc_recovery *recovery)
{
	const struct agi_lc_checkpoint_manifest *manifest = &record->manifest;

	recovery->checkpoint_id = record->checkpoint_id;
	recovery->checkpoint_sequence = record->checkpoint_sequence;
	recovery->parent_sequence = record->parent_sequence;
	recovery->lineage_id = manifest->lineage_id;
	recovery->agent_id = manifest->agent_id;
	recovery->phase = manifest->phase;
	recovery->scope_flags = record->scope_flags;
	recovery->resource_policy = record->resource_policy;
	recovery->cpu_budget_ns = record->cpu_budget_ns;
	recovery->memory_limit_pages = record->memory_limit_pages;
	recovery->region_count = manifest->region_count;
	memcpy(recovery->region_ids, manifest->region_ids,
	       sizeof(recovery->region_ids));
	memcpy(recovery->region_generations, manifest->region_generations,
	       sizeof(recovery->region_generations));
	memcpy(recovery->user_state_digest, record->state_digest,
	       sizeof(recovery->user_state_digest));
	memcpy(recovery->manifest_digest, manifest->manifest_digest,
	       sizeof(recovery->manifest_digest));
}

static void agi_lc_checkpoint_mark_crashed(u64 checkpoint_id)
{
	struct agi_lc_checkpoint_record *record;
	u32 slot = checkpoint_id % AGI_LC_CHECKPOINT_RECORDS;

	mutex_lock(&agi_lc_checkpoint_lock);
	record = &agi_lc_checkpoint_records[slot];
	if (record->valid && record->checkpoint_id == checkpoint_id &&
	    record->manifest_valid &&
	    record->recovery_state != AGI_LC_RECOVERY_CONTINUED) {
		record->recovery_state = AGI_LC_RECOVERY_CRASHED;
		record->recovery_sequence =
			atomic64_inc_return(&agi_lc_next_recovery);
	}
	mutex_unlock(&agi_lc_checkpoint_lock);
}

static int agi_lc_checkpoint_manifest(struct agi_lc_session *session,
					       unsigned long arg)
{
	struct agi_lc_checkpoint_manifest manifest;
	struct agi_lc_checkpoint_record *record;
	u8 digest[AGI_LC_DIGEST_SIZE];
	u64 lineage_id;
	u64 agent_id;
	u32 i;
	int ret;

	if (copy_from_user(&manifest, (void __user *)arg, sizeof(manifest)))
		return -EFAULT;
	if (manifest.size != sizeof(manifest) || manifest.flags ||
	    !manifest.checkpoint_id || manifest.checkpoint_sequence ||
	    manifest.lineage_id || manifest.agent_id ||
	    !manifest.scope_flags ||
	    (manifest.scope_flags & ~AGI_LC_CHECKPOINT_SCOPE_ALL) ||
	    (manifest.resource_policy & ~AGI_LC_CHECKPOINT_RESOURCE_MAX) ||
	    manifest.recovery_state || manifest.region_count > AGI_LC_CHECKPOINT_REGION_MAX ||
	    manifest.reserved32 || memchr_inv(manifest.manifest_digest, 0,
					       sizeof(manifest.manifest_digest)) ||
	    !memchr_inv(manifest.user_state_digest, 0,
				 sizeof(manifest.user_state_digest)) ||
	    manifest.correlation == 0 || manifest.reserved[0] ||
	    manifest.reserved[1])
		return -EINVAL;
	for (i = manifest.region_count; i < AGI_LC_CHECKPOINT_REGION_MAX; i++)
		if (manifest.region_ids[i] || manifest.region_generations[i])
			return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!session->checkpoint_valid ||
	    manifest.checkpoint_id != session->checkpoint_id)
		return -ENOENT;
	if (session->verification_state != AGI_LC_VERIFY_UNVERIFIED)
		return -EBUSY;
	ret = agi_lc_checkpoint_regions_validate(session, &manifest);
	if (ret)
		return ret;
	lineage_id = faisal_task_get_lineage(current);
	agent_id = faisal_task_get_agent(current);
	manifest.checkpoint_sequence = session->checkpoint_sequence;
	manifest.parent_sequence = session->checkpoint_parent_sequence;
	manifest.lineage_id = lineage_id;
	manifest.agent_id = agent_id;
	manifest.phase = session->checkpoint_phase;
	manifest.recovery_state = AGI_LC_RECOVERY_NONE;
	manifest.cpu_budget_ns = session->checkpoint_cpu_budget_ns;
	manifest.memory_limit_pages = session->checkpoint_memory_limit_pages;
	ret = agi_lc_manifest_digest(&manifest, digest);
	if (ret)
		return ret;
	memcpy(manifest.manifest_digest, digest, sizeof(manifest.manifest_digest));
	mutex_lock(&agi_lc_checkpoint_lock);
	record = &agi_lc_checkpoint_records[manifest.checkpoint_id %
					AGI_LC_CHECKPOINT_RECORDS];
	if (!record->valid || record->checkpoint_id != manifest.checkpoint_id ||
	    record->checkpoint_sequence != manifest.checkpoint_sequence) {
		mutex_unlock(&agi_lc_checkpoint_lock);
		return -ENOENT;
	}
	record->manifest = manifest;
	record->manifest_valid = true;
	record->scope_flags = manifest.scope_flags;
	record->resource_policy = manifest.resource_policy;
	record->lineage_id = lineage_id;
	record->agent_id = agent_id;
	record->recovery_state = AGI_LC_RECOVERY_NONE;
	record->recovery_sequence = 0;
	mutex_unlock(&agi_lc_checkpoint_lock);
	session->checkpoint_manifest = manifest;
	session->checkpoint_manifest_valid = true;
	session->recovery_state = AGI_LC_RECOVERY_NONE;
	if (copy_to_user((void __user *)arg, &manifest, sizeof(manifest)))
		return -EFAULT;
	return agi_lc_push_record(session, AGI_LC_EVENT_RECOVERY, 0,
					 manifest.correlation, manifest.checkpoint_id);
}

static int agi_lc_recovery(struct agi_lc_session *session,
				   unsigned long arg)
{
	struct agi_lc_recovery recovery;
	struct agi_lc_checkpoint_record record;
	struct agi_lc_handoff lookup = { 0 };
	bool exact_lineage;
	int ret;

	if (copy_from_user(&recovery, (void __user *)arg, sizeof(recovery)))
		return -EFAULT;
	if (recovery.size != sizeof(recovery) ||
	    recovery.action < AGI_LC_RECOVERY_MARK_CRASH ||
	    recovery.action > AGI_LC_RECOVERY_ACTION_MAX || recovery.status ||
	    recovery.state || !recovery.checkpoint_id || recovery.recovery_sequence ||
	    recovery.lineage_id || recovery.agent_id || recovery.phase ||
	    recovery.flags || recovery.scope_flags || recovery.resource_policy ||
	    recovery.cpu_budget_ns || recovery.memory_limit_pages ||
	    recovery.region_count || recovery.reserved32 ||
	    memchr_inv(recovery.region_ids, 0, sizeof(recovery.region_ids)) ||
	    memchr_inv(recovery.region_generations, 0,
				 sizeof(recovery.region_generations)) ||
	    !memchr_inv(recovery.user_state_digest, 0,
				 sizeof(recovery.user_state_digest)) ||
	    !memchr_inv(recovery.manifest_digest, 0,
				 sizeof(recovery.manifest_digest)) ||
	    recovery.correlation == 0 || recovery.reserved[0] ||
	    recovery.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	exact_lineage = faisal_task_get_lineage(current) == session->session_id;
	lookup.checkpoint_id = recovery.checkpoint_id;
	if (!agi_lc_find_checkpoint(&lookup, &record))
		return -ENOENT;
	if (!record.manifest_valid)
		return -ENODATA;

	if (recovery.action == AGI_LC_RECOVERY_MARK_CRASH) {
		if (!exact_lineage || recovery.checkpoint_id != session->checkpoint_id ||
		    !session->checkpoint_manifest_valid)
			return -EPERM;
		mutex_lock(&agi_lc_checkpoint_lock);
		record.recovery_state = AGI_LC_RECOVERY_CRASHED;
		record.recovery_sequence =
			atomic64_inc_return(&agi_lc_next_recovery);
		agi_lc_checkpoint_records[recovery.checkpoint_id %
					AGI_LC_CHECKPOINT_RECORDS] = record;
		mutex_unlock(&agi_lc_checkpoint_lock);
		session->recovery_state = AGI_LC_RECOVERY_CRASHED;
		session->recovery_sequence = record.recovery_sequence;
		session->recovery_checkpoint_id = record.checkpoint_id;
		session->recovery_checkpoint_sequence = record.checkpoint_sequence;
		recovery.state = record.recovery_state;
		recovery.recovery_sequence = record.recovery_sequence;
		agi_lc_recovery_fill(&record, &recovery);
		recovery.state = AGI_LC_RECOVERY_CRASHED;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_RECOVERY, 0,
					 recovery.correlation, recovery.checkpoint_id);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &recovery, sizeof(recovery)))
			return -EFAULT;
		return 0;
	}

	if (recovery.action == AGI_LC_RECOVERY_RESTORE_BEGIN) {
		if (!exact_lineage && !capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (record.recovery_state != AGI_LC_RECOVERY_CRASHED ||
		    record.checkpoint_sequence != recovery.checkpoint_sequence ||
		    record.parent_sequence != recovery.parent_sequence ||
		    memcmp(record.state_digest, recovery.user_state_digest,
			   sizeof(record.state_digest)) ||
		    memcmp(record.manifest.manifest_digest, recovery.manifest_digest,
			   sizeof(record.manifest.manifest_digest)))
			return -EKEYREJECTED;
		session->recovery_state = AGI_LC_RECOVERY_RESTORE_PENDING;
		session->recovery_sequence =
			atomic64_inc_return(&agi_lc_next_recovery);
		session->recovery_checkpoint_id = record.checkpoint_id;
		session->recovery_checkpoint_sequence = record.checkpoint_sequence;
		recovery.state = AGI_LC_RECOVERY_RESTORE_PENDING;
		recovery.recovery_sequence = session->recovery_sequence;
		agi_lc_recovery_fill(&record, &recovery);
		recovery.state = AGI_LC_RECOVERY_RESTORE_PENDING;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_RECOVERY, 0,
					 recovery.correlation, recovery.checkpoint_id);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &recovery, sizeof(recovery)))
			return -EFAULT;
		return 0;
	}

	if (!exact_lineage ||
	    (session->recovery_state != AGI_LC_RECOVERY_RESTORED &&
	     session->recovery_state != AGI_LC_RECOVERY_NONE) ||
	    recovery.checkpoint_id != session->checkpoint_id ||
	    session->verification_state != AGI_LC_VERIFY_MATCHED)
		return -EPERM;
	if (session->verification_checkpoint_sequence != session->checkpoint_sequence ||
	    session->verification_parent_sequence != session->checkpoint_parent_sequence ||
	    memcmp(session->verification_digest, session->checkpoint_digest,
		   sizeof(session->verification_digest)))
		return -EKEYREJECTED;
	mutex_lock(&agi_lc_checkpoint_lock);
	record.recovery_state = AGI_LC_RECOVERY_CONTINUED;
	record.recovery_sequence = atomic64_inc_return(&agi_lc_next_recovery);
	agi_lc_checkpoint_records[recovery.checkpoint_id %
				AGI_LC_CHECKPOINT_RECORDS] = record;
	mutex_unlock(&agi_lc_checkpoint_lock);
	session->recovery_state = AGI_LC_RECOVERY_CONTINUED;
	session->recovery_sequence = record.recovery_sequence;
	recovery.state = AGI_LC_RECOVERY_CONTINUED;
	recovery.recovery_sequence = record.recovery_sequence;
	agi_lc_recovery_fill(&record, &recovery);
	recovery.state = AGI_LC_RECOVERY_CONTINUED;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_RECOVERY, 0,
				 recovery.correlation, recovery.checkpoint_id);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &recovery, sizeof(recovery)))
		return -EFAULT;
	return 0;
}

static int agi_lc_subscribe(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_subscribe subscribe;
	unsigned long flags;

	if (copy_from_user(&subscribe, (void __user *)arg,
			   sizeof(subscribe)))
		return -EFAULT;
	if (subscribe.size != sizeof(subscribe) || subscribe.flags ||
	    subscribe.reserved[0] || subscribe.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, flags);
	session->event_mask = subscribe.event_mask;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return 0;
}

static int agi_lc_event_backpressure(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_event_backpressure backpressure;
	unsigned long flags;
	u32 newest_index;

	if (copy_from_user(&backpressure, (void __user *)arg,
			   sizeof(backpressure)))
		return -EFAULT;
	if (backpressure.size != sizeof(backpressure) || backpressure.flags ||
	    backpressure.state || backpressure.capacity || backpressure.queued ||
	    backpressure.reserved32 || backpressure.dropped_records ||
	    backpressure.oldest_sequence || backpressure.newest_sequence ||
	    backpressure.next_sequence || backpressure.reserved[0] ||
	    backpressure.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, flags);
	backpressure.capacity = AGI_LC_RING_SIZE;
	backpressure.queued = session->count;
	backpressure.dropped_records = session->dropped_records;
	backpressure.next_sequence = session->next_sequence;
	if (session->count) {
		newest_index = (session->tail + AGI_LC_RING_SIZE - 1) %
			AGI_LC_RING_SIZE;
		backpressure.oldest_sequence = session->records[session->head].sequence;
		backpressure.newest_sequence = session->records[newest_index].sequence;
	}
	if (session->dropped_records)
		backpressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS;
	else if (session->count == AGI_LC_RING_SIZE)
		backpressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_FULL;
	else if (session->count >= (AGI_LC_RING_SIZE * 3) / 4)
		backpressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_NEAR_FULL;
	else
		backpressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &backpressure,
			 sizeof(backpressure)))
		return -EFAULT;
	return 0;
}

static int agi_lc_accel_account(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_accel accel;

	if (copy_from_user(&accel, (void __user *)arg, sizeof(accel)))
		return -EFAULT;
	if (accel.size != sizeof(accel) || accel.flags || accel.reserved[0] ||
	    accel.reserved[1])
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	faisal_task_accel_account(current, accel.compute_ns,
					  accel.memory_bytes, accel.submissions);
	return agi_lc_push_record(session, AGI_LC_EVENT_ACCEL, 0,
					  accel.correlation, accel.submissions);
}

static int agi_lc_accel_get(struct agi_lc_session *session,
				    unsigned long arg)
{
	struct agi_lc_accel accel;

	if (copy_from_user(&accel, (void __user *)arg, sizeof(accel)))
		return -EFAULT;
	if (accel.size != sizeof(accel) || accel.flags || accel.reserved[0] ||
	    accel.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	faisal_task_accel_get(current, &accel.compute_ns,
				     &accel.memory_bytes, &accel.submissions);
	accel.correlation = 0;
	if (copy_to_user((void __user *)arg, &accel, sizeof(accel)))
		return -EFAULT;
	return 0;
}

static int agi_lc_experience(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_experience experience;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	unsigned long flags;
	u64 last_sequence;
	u64 sequence;
	unsigned int desc_size;
	int ret;

	if (copy_from_user(&experience, (void __user *)arg,
			   sizeof(experience)))
		return -EFAULT;
	if (experience.size != sizeof(experience) || experience.flags ||
	    experience.length > AGI_LC_EXPERIENCE_MAX ||
	    experience.experience_sequence)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	spin_lock_irqsave(&session->queue_lock, flags);
	last_sequence = session->next_sequence ? session->next_sequence - 1 : 0;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (experience.parent_sequence > last_sequence)
		return -EINVAL;

	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);
	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	desc = kzalloc(desc_size, GFP_KERNEL);
	if (!desc) {
		crypto_free_shash(tfm);
		return -ENOMEM;
	}
	desc->tfm = tfm;
	ret = crypto_shash_digest(desc, experience.payload, experience.length,
				  experience.digest);
	kfree(desc);
	crypto_free_shash(tfm);
	if (ret)
		return ret;

	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_EXPERIENCE,
					    experience.status, experience.correlation,
					    experience.parent_sequence, &sequence);
	if (ret)
		return ret;
	experience.experience_sequence = sequence;
	if (copy_to_user((void __user *)arg, &experience,
			 sizeof(experience)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_graph_node_record *
agi_lc_graph_find_locked(struct agi_lc_session *s, u64 graph_id, u64 node_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_GRAPH_NODES; i++) {
		struct agi_lc_graph_node_record *record = &s->graph_nodes[i];

		if (record->valid && record->node.graph_id == graph_id &&
		    record->node.node_id == node_id)
			return record;
	}
	return NULL;
}
static void agi_lc_graph_refresh_locked(struct agi_lc_session *session,
						 u64 graph_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_GRAPH_NODES; i++) {
		struct agi_lc_graph_node *node;
		u32 completed = 0;
		bool cancelled = false;
		u32 j;

		if (!session->graph_nodes[i].valid ||
		    session->graph_nodes[i].node.graph_id != graph_id)
			continue;
		node = &session->graph_nodes[i].node;
		if (node->state == AGI_LC_GRAPH_STATE_COMPLETE ||
		    node->state == AGI_LC_GRAPH_STATE_CANCELLED)
			continue;
		for (j = 0; j < node->dependency_count; j++) {
			struct agi_lc_graph_node_record *dependency;

			dependency = agi_lc_graph_find_locked(session, graph_id,
							     node->dependencies[j]);
			if (!dependency)
				continue;
			if (dependency->node.state == AGI_LC_GRAPH_STATE_COMPLETE)
				completed++;
			if (dependency->node.state == AGI_LC_GRAPH_STATE_CANCELLED)
				cancelled = true;
		}
		node->completed_dependencies = completed;
		if (cancelled)
			node->state = AGI_LC_GRAPH_STATE_CANCELLED;
		else if (completed == node->dependency_count &&
			 node->state == AGI_LC_GRAPH_STATE_PENDING)
			node->state = AGI_LC_GRAPH_STATE_READY;
		node->ready = node->state == AGI_LC_GRAPH_STATE_READY;
		node->criticality = node->priority +
			(node->latency_sensitive ? AGI_LC_SCHED_PRIORITY_MAX + 1 : 0);
	}
}
static int agi_lc_graph_node_control(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_graph_node request, output;
	struct agi_lc_graph_node_record *record = NULL, *slot = NULL;
	u32 i, j;
	int ret = 0;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || request.flags ||
	    request.reserved32 || request.reserved[0] || request.reserved[1] ||
	    request.operation < AGI_LC_GRAPH_NODE_CREATE ||
	    request.operation > AGI_LC_GRAPH_NODE_CANCEL)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (request.agent_id &&
	    request.agent_id != faisal_task_get_agent(current))
		return -EPERM;

	mutex_lock(&session->graph_lock);
	if (request.operation == AGI_LC_GRAPH_NODE_CREATE) {
		if (!request.graph_id || !request.node_id ||
		    request.dependency_count > AGI_LC_GRAPH_MAX_DEPS ||
		    !request.device_mask ||
		    (request.device_mask & ~AGI_LC_GRAPH_DEVICE_ALL) ||
		    request.priority > AGI_LC_SCHED_PRIORITY_MAX ||
		    request.latency_sensitive > 1 ||
		    agi_lc_graph_find_locked(session, request.graph_id,
						      request.node_id)) {
			ret = -EINVAL;
			goto out;
		}
		for (j = 0; j < request.dependency_count; j++) {
			if (!request.dependencies[j] ||
			    request.dependencies[j] == request.node_id ||
			    !agi_lc_graph_find_locked(session, request.graph_id,
						       request.dependencies[j])) {
				ret = -EINVAL;
				goto out;
			}
			for (i = j + 1; i < request.dependency_count; i++) {
				if (request.dependencies[j] == request.dependencies[i]) {
					ret = -EINVAL;
					goto out;
				}
			}
		}
		for (i = 0; i < AGI_LC_GRAPH_NODES; i++) {
			if (!session->graph_nodes[i].valid) {
				slot = &session->graph_nodes[i];
				break;
			}
		}
		if (!slot) {
			ret = -ENOSPC;
			goto out;
		}
		request.agent_id = request.agent_id ? request.agent_id :
			faisal_task_get_agent(current);
		request.state = AGI_LC_GRAPH_STATE_PENDING;
		request.ready = 0;
		request.completed_dependencies = 0;
		request.generation = 1;
		slot->valid = true;
		slot->node = request;
		agi_lc_graph_refresh_locked(session, request.graph_id);
		output = slot->node;
	} else {
		if (!request.graph_id || !request.node_id) {
			ret = -EINVAL;
			goto out;
		}
		record = agi_lc_graph_find_locked(session, request.graph_id,
						   request.node_id);
		if (!record) {
			ret = -ENOENT;
			goto out;
		}
		if (request.operation == AGI_LC_GRAPH_NODE_GET) {
			output = record->node;
			output.operation = AGI_LC_GRAPH_NODE_GET;
			goto copy_out;
		}
		if (request.operation == AGI_LC_GRAPH_NODE_COMPLETE) {
			if (record->node.state != AGI_LC_GRAPH_STATE_READY &&
			    record->node.state != AGI_LC_GRAPH_STATE_RUNNING) {
				ret = -EINVAL;
				goto out;
			}
			record->node.state = AGI_LC_GRAPH_STATE_COMPLETE;
			record->node.observed_runtime_ns = request.observed_runtime_ns;
		} else {
			if (record->node.state == AGI_LC_GRAPH_STATE_COMPLETE) {
				ret = -EALREADY;
				goto out;
			}
			record->node.state = AGI_LC_GRAPH_STATE_CANCELLED;
			record->node.ready = 0;
		}
		record->node.generation++;
		agi_lc_graph_refresh_locked(session, request.graph_id);
		output = record->node;
	}
copy_out:
	mutex_unlock(&session->graph_lock);
	if (copy_to_user((void __user *)arg, &output, sizeof(output)))
		return -EFAULT;
	if (request.operation != AGI_LC_GRAPH_NODE_GET)
		return agi_lc_push_record(session, AGI_LC_EVENT_SCHED_HINT, 0,
					  output.correlation, output.node_id);
	return 0;
out:
	mutex_unlock(&session->graph_lock);
	return ret;
}

static struct agi_lc_compute_context_record *
agi_lc_context_find_locked(struct agi_lc_session *session, u64 context_id,
				   u64 capability)
{
	u32 i;

	for (i = 0; i < AGI_LC_CONTEXT_RECORDS; i++) {
		struct agi_lc_compute_context_record *record = &session->contexts[i];

		if (record->valid && record->context.context_id == context_id &&
		    record->context.context_capability == capability)
			return record;
	}
	return NULL;
}
static void agi_lc_compute_context_fabric_caps(struct agi_lc_compute_context *context)
{
	u64 active = AGI_LC_CONTEXT_FABRIC_CPU;

	if (IS_ENABLED(CONFIG_DMA_SHARED_BUFFER))
		active |= AGI_LC_CONTEXT_FABRIC_DMA_BUF;
	if (IS_ENABLED(CONFIG_DMA_ENGINE))
		active |= AGI_LC_CONTEXT_FABRIC_DMA_ENGINE;
	if (IS_ENABLED(CONFIG_IOMMU_SVA))
		active |= AGI_LC_CONTEXT_FABRIC_IOMMU_SVA;
	if (IS_ENABLED(CONFIG_HMM_MIRROR))
		active |= AGI_LC_CONTEXT_FABRIC_HMM;
	if (IS_ENABLED(CONFIG_UACCE))
		active |= AGI_LC_CONTEXT_FABRIC_UACCE;
	context->active_fabric = active;
	context->unsupported_fabric = context->requested_fabric & ~active;
	context->active_device_mask = context->device_mask & AGI_LC_CONTEXT_DEVICE_CPU;
	context->unsupported_device_mask = context->device_mask &
		~context->active_device_mask;
	context->provider_kind = context->active_device_mask ?
		AGI_LC_CONTEXT_PROVIDER_CPU : AGI_LC_CONTEXT_PROVIDER_NONE;
	context->address_space_mode = context->active_device_mask ?
		AGI_LC_CONTEXT_ADDRESS_SPACE_PROCESS :
		AGI_LC_CONTEXT_ADDRESS_SPACE_NONE;
}
static int agi_lc_compute_context_control(struct agi_lc_session *session,
					  unsigned long arg)
{
	struct agi_lc_compute_context request, output;
	struct agi_lc_compute_context_record *record = NULL, *slot = NULL;
	struct agi_lc_memory_record *memory;
	u64 task_id = task_pid_nr(current);
	u32 i;
	int ret = 0;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || request.flags ||
	    request.reserved[0] || request.reserved[1] ||
	    request.operation < AGI_LC_CONTEXT_CREATE ||
	    request.operation > AGI_LC_CONTEXT_CLOSE)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	mutex_lock(&session->context_lock);
	if (request.operation == AGI_LC_CONTEXT_CREATE) {
		if (request.context_id || request.context_capability ||
		    (request.agent_id &&
		     request.agent_id != faisal_task_get_agent(current)) ||
		    (request.device_mask & ~AGI_LC_CONTEXT_DEVICE_ALL) ||
		    (request.requested_fabric & ~AGI_LC_CONTEXT_FABRIC_ALL) ||
		    request.attached_tasks || request.bound_regions ||
		    request.active_device_mask || request.unsupported_device_mask ||
		    request.generation || request.task_id || request.region_id ||
		    request.region_capability || request.region_access ||
		    request.status || request.bytes_referenced ||
		    request.active_fabric || request.unsupported_fabric ||
		    request.address_space_mode || request.provider_kind ||
		    request.bytes_accounted || request.transfer_bytes ||
		    request.compute_ns || request.state_sequence) {
			ret = -EINVAL;
			goto out;
		}
		for (i = 0; i < AGI_LC_CONTEXT_RECORDS; i++) {
			if (!session->contexts[i].valid) {
				slot = &session->contexts[i];
				break;
			}
		}
		if (!slot) {
			ret = -ENOSPC;
			goto out;
		}
		memset(slot, 0, sizeof(*slot));
		slot->valid = true;
		slot->context = request;
		slot->context.state = AGI_LC_CONTEXT_STATE_ACTIVE;
		slot->context.context_id = ++session->next_context_id;
		if (!slot->context.context_id)
			slot->context.context_id = ++session->next_context_id;
		slot->context.context_capability = agi_lc_memory_new_capability();
		slot->context.agent_id = faisal_task_get_agent(current);
		slot->context.generation = 1;
		agi_lc_compute_context_fabric_caps(&slot->context);
		output = slot->context;
	} else {
		if (!request.context_id || !request.context_capability) {
			ret = -EINVAL;
			goto out;
		}
		record = agi_lc_context_find_locked(session, request.context_id,
						     request.context_capability);
		if (!record || record->context.agent_id != faisal_task_get_agent(current)) {
			ret = -EACCES;
			goto out;
		}
		if (request.operation == AGI_LC_CONTEXT_GET) {
			output = record->context;
			goto copy_out;
		}
		if (record->context.state != AGI_LC_CONTEXT_STATE_ACTIVE) {
			ret = -ESHUTDOWN;
			goto out;
		}
		switch (request.operation) {
		case AGI_LC_CONTEXT_ATTACH_TASK:
			for (i = 0; i < AGI_LC_CONTEXT_MAX_TASKS; i++)
				if (record->tasks[i] == task_id)
					break;
			if (i == AGI_LC_CONTEXT_MAX_TASKS) {
				for (i = 0; i < AGI_LC_CONTEXT_MAX_TASKS; i++) {
					if (!record->tasks[i]) {
						record->tasks[i] = task_id;
						record->context.attached_tasks++;
						break;
					}
				}
				if (i == AGI_LC_CONTEXT_MAX_TASKS) {
					ret = -ENOSPC;
					goto out;
				}
			}
			record->context.task_id = task_id;
			record->context.state_sequence++;
			break;
		case AGI_LC_CONTEXT_DETACH_TASK:
			for (i = 0; i < AGI_LC_CONTEXT_MAX_TASKS; i++) {
				if (record->tasks[i] == task_id) {
					record->tasks[i] = 0;
					record->context.attached_tasks--;
					break;
				}
			}
			if (i == AGI_LC_CONTEXT_MAX_TASKS) {
				ret = -ENOENT;
				goto out;
			}
			record->context.task_id = task_id;
			record->context.state_sequence++;
			break;
		case AGI_LC_CONTEXT_BIND_REGION:
			if (!request.region_id || !request.region_capability ||
			    !agi_lc_memory_access_valid(request.region_access)) {
				ret = -EINVAL;
				goto out;
			}
			mutex_lock(&agi_lc_memory_lock);
			memory = agi_lc_memory_find_locked(session, request.region_id);
			if (!memory || !agi_lc_memory_authorized_locked(session, memory,
									request.region_capability,
									request.region_access)) {
				mutex_unlock(&agi_lc_memory_lock);
				ret = -EACCES;
				goto out;
			}
			for (i = 0; i < AGI_LC_CONTEXT_MAX_REGIONS; i++)
				if (record->regions[i] == request.region_id)
					break;
			if (i == AGI_LC_CONTEXT_MAX_REGIONS) {
				for (i = 0; i < AGI_LC_CONTEXT_MAX_REGIONS; i++) {
					if (!record->regions[i]) {
						record->regions[i] = request.region_id;
						record->region_capabilities[i] = request.region_capability;
						record->region_access[i] = request.region_access;
						record->context.bound_regions++;
						record->context.bytes_referenced += memory->size_bytes;
						break;
					}
				}
				if (i == AGI_LC_CONTEXT_MAX_REGIONS) {
					mutex_unlock(&agi_lc_memory_lock);
					ret = -ENOSPC;
					goto out;
				}
			}
			mutex_unlock(&agi_lc_memory_lock);
			record->context.region_id = request.region_id;
			record->context.region_capability = request.region_capability;
			record->context.region_access = request.region_access;
			record->context.bytes_accounted = record->context.bytes_referenced;
			record->context.state_sequence++;
			break;
		case AGI_LC_CONTEXT_UNBIND_REGION:
			if (!request.region_id) {
				ret = -EINVAL;
				goto out;
			}
			for (i = 0; i < AGI_LC_CONTEXT_MAX_REGIONS; i++)
				if (record->regions[i] == request.region_id)
					break;
			if (i == AGI_LC_CONTEXT_MAX_REGIONS) {
				ret = -ENOENT;
				goto out;
			}
			mutex_lock(&agi_lc_memory_lock);
			memory = agi_lc_memory_find_locked(session, request.region_id);
			if (memory && record->context.bytes_referenced >= memory->size_bytes)
				record->context.bytes_referenced -= memory->size_bytes;
			mutex_unlock(&agi_lc_memory_lock);
			record->regions[i] = 0;
			record->region_capabilities[i] = 0;
			record->region_access[i] = 0;
			record->context.bound_regions--;
			record->context.bytes_accounted = record->context.bytes_referenced;
			record->context.state_sequence++;
			break;
		case AGI_LC_CONTEXT_CLOSE:
			record->context.state = AGI_LC_CONTEXT_STATE_CLOSED;
			record->context.state_sequence++;
			break;
		default:
			ret = -EINVAL;
			goto out;
		}
		record->context.generation++;
		output = record->context;
	}
copy_out:
	mutex_unlock(&session->context_lock);
	if (copy_to_user((void __user *)arg, &output, sizeof(output)))
		return -EFAULT;
	return agi_lc_push_record(session, AGI_LC_EVENT_SCHED_HINT, output.status,
					  output.correlation, output.context_id);
out:
	mutex_unlock(&session->context_lock);
	return ret;
}
static struct agi_lc_graph_telemetry_record *agi_lc_graph_telemetry_find_locked(struct agi_lc_session *s, u64 id, u64 cap)
{
	u32 i;

	for (i = 0; i < AGI_LC_GRAPH_TELEMETRY_RECORDS; i++)
		if (s->graph_telemetry[i].valid &&
		    s->graph_telemetry[i].telemetry.telemetry_id == id &&
		    s->graph_telemetry[i].telemetry.telemetry_capability == cap)
			return &s->graph_telemetry[i];
	return NULL;
}
static int agi_lc_graph_telemetry_control(struct agi_lc_session *s, unsigned long arg)
{
	struct agi_lc_graph_telemetry p, out;
	struct agi_lc_graph_telemetry_record *r = NULL, *slot = NULL;
	struct agi_lc_graph_node_record *node;
	struct agi_lc_memory_record *memory;
	u64 now;
	u32 i;
	int ret = 0;

	if (copy_from_user(&p, (void __user *)arg, sizeof(p)))
		return -EFAULT;
	if (p.size != sizeof(p) ||
	    p.operation < AGI_LC_GRAPH_TELEMETRY_BEGIN ||
	    p.operation > AGI_LC_GRAPH_TELEMETRY_QUERY ||
	    p.flags & ~AGI_LC_GRAPH_TELEMETRY_FLAGS_ALL ||
	    p.device_mask & ~AGI_LC_GRAPH_DEVICE_ALL ||
	    p.operator_kind > AGI_LC_GRAPH_TELEMETRY_MAX_OPERATOR_KIND ||
	    p.anomaly_score > AGI_LC_GRAPH_TELEMETRY_MAX_ANOMALY_SCORE ||
	    p.reserved[0] || p.reserved[1] || !p.correlation)
		return -EINVAL;
	if (!s->session_id || READ_ONCE(s->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != s->session_id)
		return -EPERM;
	if (p.operation == AGI_LC_GRAPH_TELEMETRY_BEGIN) {
		if (!p.graph_id || !p.node_id || !p.device_mask ||
		    p.telemetry_id || p.telemetry_capability || p.state || p.status ||
		    p.start_ns || p.end_ns || p.duration_ns || p.queue_delay_ns ||
		    p.observed_runtime_ns || p.bytes_in || p.bytes_out ||
		    p.provider_sequence || p.anomaly_score || p.anomaly_flags ||
		    p.generation)
			return -EINVAL;
	} else {
		if (!p.telemetry_id || !p.telemetry_capability)
			return -EINVAL;
		if (p.operation == AGI_LC_GRAPH_TELEMETRY_QUERY &&
		    (p.flags || p.status || p.device_mask || p.context_id ||
		     p.context_capability || p.tensor_region_id || p.tensor_capability ||
		     p.transport_id || p.transport_capability || p.provenance_id ||
		     p.provenance_sequence || p.operator_kind || p.dependency_count ||
		     p.start_ns || p.end_ns || p.duration_ns || p.queue_delay_ns ||
		     p.observed_runtime_ns || p.bytes_in || p.bytes_out ||
		     p.provider_sequence || p.anomaly_score || p.anomaly_flags ||
		     p.generation))
			return -EINVAL;
	}
	mutex_lock(&s->graph_lock);
	if (p.operation == AGI_LC_GRAPH_TELEMETRY_BEGIN)
		node = agi_lc_graph_find_locked(s, p.graph_id, p.node_id);
	else
		node = NULL;
	if (node && node->node.agent_id != faisal_task_get_agent(current))
		node = NULL;
	if (p.operation == AGI_LC_GRAPH_TELEMETRY_BEGIN &&
	    (!node || (node->node.state != AGI_LC_GRAPH_STATE_READY &&
		       node->node.state != AGI_LC_GRAPH_STATE_RUNNING))) {
		mutex_unlock(&s->graph_lock);
		return -EINVAL;
	}
	if (p.operation != AGI_LC_GRAPH_TELEMETRY_BEGIN) {
		r = agi_lc_graph_telemetry_find_locked(s, p.telemetry_id,
							p.telemetry_capability);
		if (!r) {
			mutex_unlock(&s->graph_lock);
			return -EACCES;
		}
		if (r->telemetry.agent_id != faisal_task_get_agent(current)) {
			mutex_unlock(&s->graph_lock);
			return -EACCES;
		}
	}
	if ((p.context_id || p.context_capability) !=
	    !!(p.flags & AGI_LC_GRAPH_TELEMETRY_FLAG_CONTEXT) ||
	    (p.tensor_region_id || p.tensor_capability) !=
	    !!(p.flags & AGI_LC_GRAPH_TELEMETRY_FLAG_TENSOR) ||
	    (p.transport_id || p.transport_capability) !=
	    !!(p.flags & AGI_LC_GRAPH_TELEMETRY_FLAG_TRANSPORT) ||
	    (p.provenance_id || p.provenance_sequence) !=
	    !!(p.flags & AGI_LC_GRAPH_TELEMETRY_FLAG_PROVENANCE)) {
		mutex_unlock(&s->graph_lock);
		return -EINVAL;
	}
	if (p.context_id || p.context_capability) {
		struct agi_lc_compute_context_record *context;

		if (!p.context_id || !p.context_capability) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		mutex_lock(&s->context_lock);
		context = agi_lc_context_find_locked(s, p.context_id,
							p.context_capability);
		if (!context || context->context.agent_id != faisal_task_get_agent(current))
			ret = -EACCES;
		mutex_unlock(&s->context_lock);
		if (ret) {
			mutex_unlock(&s->graph_lock);
			return ret;
		}
	}
	if (p.tensor_region_id || p.tensor_capability) {
		if (!p.tensor_region_id || !p.tensor_capability) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		mutex_lock(&agi_lc_memory_lock);
		memory = agi_lc_memory_find_locked(s, p.tensor_region_id);
		if (!memory || memory->revoked ||
		    !agi_lc_memory_authorized_locked(s, memory,
						      p.tensor_capability,
						      AGI_LC_MEMORY_ACCESS_READ))
			ret = -EACCES;
		mutex_unlock(&agi_lc_memory_lock);
		if (ret) {
			mutex_unlock(&s->graph_lock);
			return ret;
		}
	}
	if (p.transport_id || p.transport_capability) {
		bool transport_ok = false;

		if (!p.transport_id || !p.transport_capability) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		for (i = 0; i < AGI_LC_TRANSPORT_RECORDS; i++)
			if (s->transports[i].valid &&
			    s->transports[i].transport.state == AGI_LC_TRANSPORT_STATE_ACTIVE &&
			    s->transports[i].transport.transport_id == p.transport_id &&
			    s->transports[i].transport.capability == p.transport_capability) {
				transport_ok = true;
				break;
			}
		if (!transport_ok) {
			mutex_unlock(&s->graph_lock);
			return -EACCES;
		}
	}
	if (p.provenance_id || p.provenance_sequence) {
		bool provenance_ok = false;

		if (!p.provenance_id || !p.provenance_sequence) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		for (i = 0; i < AGI_LC_PROVENANCE_RECORDS; i++)
			if (s->provenance[i].valid &&
			    s->provenance[i].provenance.provenance_id == p.provenance_id &&
			    s->provenance[i].provenance.action_sequence == p.provenance_sequence) {
				provenance_ok = true;
				break;
			}
		if (!provenance_ok) {
			mutex_unlock(&s->graph_lock);
			return -EACCES;
		}
	}
	if (p.operation == AGI_LC_GRAPH_TELEMETRY_BEGIN) {
		for (i = 0; i < AGI_LC_GRAPH_TELEMETRY_RECORDS; i++)
			if (!s->graph_telemetry[i].valid) {
				slot = &s->graph_telemetry[i];
				break;
			}
		if (!slot) {
			mutex_unlock(&s->graph_lock);
			return -ENOSPC;
		}
		if (++s->graph_telemetry_next_id == U64_MAX) {
			mutex_unlock(&s->graph_lock);
			return -EOVERFLOW;
		}
		memset(slot, 0, sizeof(*slot));
		slot->valid = true;
		slot->telemetry = p;
		slot->telemetry.telemetry_id = s->graph_telemetry_next_id;
		slot->telemetry.telemetry_capability = get_random_u64();
		while (!slot->telemetry.telemetry_capability)
			slot->telemetry.telemetry_capability = get_random_u64();
		slot->telemetry.state = AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE;
		slot->telemetry.status = 0;
		slot->telemetry.agent_id = faisal_task_get_agent(current);
		slot->telemetry.task_id = task_pid_nr(current);
		slot->telemetry.device_mask = node->node.device_mask;
		slot->telemetry.dependency_count = node->node.dependency_count;
		slot->telemetry.start_ns = ktime_get_boottime_ns();
		slot->telemetry.generation = 1;
		out = slot->telemetry;
	} else {
		if (p.graph_id && p.graph_id != r->telemetry.graph_id) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		if (p.node_id && p.node_id != r->telemetry.node_id) {
			mutex_unlock(&s->graph_lock);
			return -EINVAL;
		}
		if (p.operation == AGI_LC_GRAPH_TELEMETRY_QUERY) {
			out = r->telemetry;
			out.operation = AGI_LC_GRAPH_TELEMETRY_QUERY;
			mutex_unlock(&s->graph_lock);
			if (copy_to_user((void __user *)arg, &out, sizeof(out)))
				return -EFAULT;
			return 0;
		}
		if (r->telemetry.state != AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE &&
		    p.operation != AGI_LC_GRAPH_TELEMETRY_ANOMALY) {
			mutex_unlock(&s->graph_lock);
			return -ESHUTDOWN;
		}
		now = ktime_get_boottime_ns();
		if (p.operation == AGI_LC_GRAPH_TELEMETRY_END ||
		    p.operation == AGI_LC_GRAPH_TELEMETRY_FAIL) {
			r->telemetry.end_ns = now;
			r->telemetry.duration_ns = now >= r->telemetry.start_ns ?
				now - r->telemetry.start_ns : 0;
			r->telemetry.state = p.operation == AGI_LC_GRAPH_TELEMETRY_END ?
			AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE :
			AGI_LC_GRAPH_TELEMETRY_STATE_FAILED;
		} else if (p.operation == AGI_LC_GRAPH_TELEMETRY_CHECKPOINT) {
			r->telemetry.state = AGI_LC_GRAPH_TELEMETRY_STATE_CHECKPOINTED;
		}
		r->telemetry.flags |= p.flags;
		r->telemetry.status = p.status;
		r->telemetry.queue_delay_ns = p.queue_delay_ns;
		r->telemetry.observed_runtime_ns = p.observed_runtime_ns;
		r->telemetry.bytes_in = p.bytes_in;
		r->telemetry.bytes_out = p.bytes_out;
		r->telemetry.provider_sequence = p.provider_sequence;
		if (p.flags & AGI_LC_GRAPH_TELEMETRY_FLAG_ANOMALY) {
			r->telemetry.anomaly_score = p.anomaly_score;
			r->telemetry.anomaly_flags = p.anomaly_flags;
		}
		r->telemetry.generation++;
		out = r->telemetry;
	}
	mutex_unlock(&s->graph_lock);
	if (copy_to_user((void __user *)arg, &out, sizeof(out)))
		return -EFAULT;
	return agi_lc_push_record(s, AGI_LC_EVENT_GRAPH_OPERATION,
					out.status, out.correlation, out.telemetry_id);
}
static void agi_lc_power_policy_mask_from_uapi(cpumask_t *mask,
						 const u64 words[AGI_LC_EXEC_DOMAIN_CPU_WORDS])
{
	u32 cpu;

	cpumask_clear(mask);
	for (cpu = 0; cpu < nr_cpu_ids &&
	     cpu < AGI_LC_EXEC_DOMAIN_CPU_WORDS * 64; cpu++)
		if (words[cpu / 64] & (1ULL << (cpu % 64)))
			cpumask_set_cpu(cpu, mask);
}
static struct agi_lc_power_policy_record *agi_lc_power_policy_find_locked(struct agi_lc_session *s, u64 id, u64 cap)
{
	u32 i;

	for (i = 0; i < AGI_LC_POWER_POLICY_RECORDS; i++)
		if (s->power_policies[i].valid &&
		    s->power_policies[i].policy.policy_id == id &&
		    s->power_policies[i].policy.capability == cap)
			return &s->power_policies[i];
	return NULL;
}
static void agi_lc_power_policy_remove_qos(struct agi_lc_power_policy_record *record)
{
	if (record->cpu_qos_active) {
		cpu_latency_qos_remove_request(&record->cpu_latency_qos);
		record->cpu_qos_active = false;
	}
}
static u64 agi_lc_power_policy_available_features(u64 device_id)
{
	u64 available = 0;

#if IS_ENABLED(CONFIG_CPU_IDLE)
	available |= AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS;
#endif
	if (device_id) {
		struct agi_lc_accel_record *device;

		mutex_lock(&agi_lc_accel_lock);
		device = agi_lc_find_accel_locked(device_id);
		if (device && (device->device.capabilities & AGI_LC_ACCEL_CAP_POWER_CONTROL))
			available |= AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET |
				AGI_LC_POWER_POLICY_FEATURE_ACCELERATOR_PROVIDER;
		mutex_unlock(&agi_lc_accel_lock);
	}
	return available;
}
static int agi_lc_power_policy_control(struct agi_lc_session *session,
					       unsigned long arg)
{
	struct agi_lc_power_policy p, out;
	struct agi_lc_power_policy_record *record = NULL;
	cpumask_t requested;
	u64 available, unsupported;
	u32 i;
	int ret = 0;

	if (copy_from_user(&p, (void __user *)arg, sizeof(p)))
		return -EFAULT;
	if (p.size != sizeof(p) ||
	    p.operation < AGI_LC_POWER_POLICY_SET ||
	    p.operation > AGI_LC_POWER_POLICY_RELEASE ||
	    p.flags & ~AGI_LC_POWER_POLICY_FLAGS_ALL ||
	    p.requested_features & ~AGI_LC_POWER_POLICY_FEATURES_ALL ||
	    p.available_features || p.unsupported_features || p.applied_features ||
	    p.min_cpu_util > AGI_LC_POWER_POLICY_CPU_UTIL_MAX ||
	    p.max_cpu_util > AGI_LC_POWER_POLICY_CPU_UTIL_MAX ||
	    p.min_cpu_util > p.max_cpu_util ||
	    p.cpu_latency_us > AGI_LC_POWER_POLICY_MAX_LATENCY_US ||
	    p.power_budget_uw > AGI_LC_POWER_POLICY_MAX_BUDGET_UW ||
	    p.power_window_us > (24ULL * 60 * 60 * 1000000ULL) ||
	    p.reserved32 || p.reserved[0] || p.reserved[1] || !p.correlation)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	cpumask_clear(&requested);
	if (p.operation == AGI_LC_POWER_POLICY_SET) {
		if (p.profile < AGI_LC_POWER_PROFILE_INFERENCE ||
		    p.profile > AGI_LC_POWER_PROFILE_MAX)
			return -EINVAL;
		if (!p.requested_features || p.policy_id || p.capability || p.state ||
		    p.status || p.agent_id || p.task_id || p.generation ||
		    (p.power_budget_uw && !(p.requested_features &
					AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET)) ||
		    (p.power_window_us && !p.power_budget_uw))
			return -EINVAL;
		if (nr_cpu_ids > AGI_LC_EXEC_DOMAIN_CPU_WORDS * 64)
			return -E2BIG;
		agi_lc_power_policy_mask_from_uapi(&requested, p.requested_cpus);
		if (!cpumask_empty(&requested) &&
		    !cpumask_subset(&requested, cpu_online_mask))
			return -EINVAL;
	} else {
		if (!p.policy_id || !p.capability || p.flags || p.profile ||
		    p.state || p.status || p.agent_id || p.task_id ||
		    p.requested_features || p.available_features ||
		    p.unsupported_features || p.applied_features ||
		    !cpumask_empty(&requested) || p.min_cpu_util || p.max_cpu_util ||
		    p.cpu_latency_us || p.device_id || p.power_budget_uw ||
		    p.power_window_us || p.sampled_power_uw || p.sampled_energy_uj ||
		    p.generation)
			return -EINVAL;
	}
	available = agi_lc_power_policy_available_features(p.device_id);
	unsupported = p.requested_features & ~available;
	if ((p.flags & AGI_LC_POWER_POLICY_FLAG_REQUIRE_ALL) && unsupported)
		return -EOPNOTSUPP;
	if (p.operation == AGI_LC_POWER_POLICY_SET) {
		for (i = 0; i < AGI_LC_POWER_POLICY_RECORDS; i++)
			if (!session->power_policies[i].valid) {
				record = &session->power_policies[i];
				break;
			}
		if (!record) {
			ret = -ENOSPC;
			goto out_unlock;
		}
		if (++session->power_policy_next_id == U64_MAX) {
			ret = -EOVERFLOW;
			goto out_unlock;
		}
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->policy = p;
		record->policy.policy_id = session->power_policy_next_id;
		record->policy.capability = get_random_u64();
		while (!record->policy.capability)
			record->policy.capability = get_random_u64();
		record->policy.agent_id = faisal_task_get_agent(current);
		record->policy.task_id = task_pid_nr(current);
		record->policy.available_features = available;
		record->policy.unsupported_features = unsupported;
		record->policy.applied_features = 0;
#if IS_ENABLED(CONFIG_CPU_IDLE)
		if (p.requested_features & AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS) {
			cpu_latency_qos_add_request(&record->cpu_latency_qos,
						   p.cpu_latency_us);
			if (cpu_latency_qos_request_active(&record->cpu_latency_qos)) {
				record->cpu_qos_active = true;
				record->policy.applied_features |=
					AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS;
			} else {
				record->policy.unsupported_features |=
					AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS;
			}
		}
#endif
		record->policy.state = AGI_LC_POWER_POLICY_STATE_ACTIVE;
		record->policy.status = record->policy.unsupported_features ?
			-EOPNOTSUPP : 0;
		record->policy.generation = 1;
		out = record->policy;
	} else {
		record = agi_lc_power_policy_find_locked(session, p.policy_id,
							p.capability);
		if (!record || record->policy.agent_id != faisal_task_get_agent(current)) {
			ret = -EACCES;
			goto out_unlock;
		}
		if (p.operation == AGI_LC_POWER_POLICY_RELEASE) {
			if (record->policy.state != AGI_LC_POWER_POLICY_STATE_ACTIVE) {
				ret = -EALREADY;
				goto out_unlock;
			}
			agi_lc_power_policy_remove_qos(record);
			record->policy.applied_features = 0;
			record->policy.state = AGI_LC_POWER_POLICY_STATE_RELEASED;
			record->policy.generation++;
		}
		out = record->policy;
		out.operation = p.operation;
	}
	mutex_unlock(&session->ioctl_lock);
	if (copy_to_user((void __user *)arg, &out, sizeof(out)))
		return -EFAULT;
	return agi_lc_push_record(session, AGI_LC_EVENT_POWER_POLICY,
					out.status, out.correlation, out.policy_id);
out_unlock:
	return ret;
}
static void agi_lc_power_policy_release_all(struct agi_lc_session *session)
{
	u32 i;

	for (i = 0; i < AGI_LC_POWER_POLICY_RECORDS; i++)
		if (session->power_policies[i].valid)
			agi_lc_power_policy_remove_qos(&session->power_policies[i]);
}
static struct agi_lc_provenance_binding_record *agi_lc_provenance_binding_find(struct agi_lc_session *s, u64 id)
{
	u32 i;

	for (i = 0; i < AGI_LC_PROVENANCE_BINDING_RECORDS; i++)
		if (s->provenance_bindings[i].valid &&
		    s->provenance_bindings[i].binding.binding_id == id)
			return &s->provenance_bindings[i];
	return NULL;
}
static int agi_lc_provenance_binding_control(struct agi_lc_session *s,
						unsigned long arg)
{
	struct agi_lc_provenance_binding p, out;
	struct agi_lc_provenance_binding_record *record = NULL;
	struct agi_lc_provenance_record *provenance;
	struct agi_lc_memory_record *memory;
	struct agi_lc_compute_context_record *context;
	u32 i;
	int ret = 0;

	if (copy_from_user(&p, (void __user *)arg, sizeof(p)))
		return -EFAULT;
	if (p.size != sizeof(p) || p.flags ||
	    p.scope_kind < AGI_LC_PROVENANCE_BIND_TENSOR ||
	    p.scope_kind > AGI_LC_PROVENANCE_BIND_CONTEXT ||
	    p.reserved32 || p.reserved[0] || p.reserved[1] || !p.correlation ||
	    p.operation < AGI_LC_PROVENANCE_BIND ||
	    p.operation > AGI_LC_PROVENANCE_BIND_REVOKE)
		return -EINVAL;
	if (!s->session_id || READ_ONCE(s->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != s->session_id)
		return -EPERM;
	if (p.operation == AGI_LC_PROVENANCE_BIND) {
		if (p.binding_id || p.status || p.binding_generation ||
		    !p.resource_id || !p.resource_capability || !p.resource_generation ||
		    !p.provenance_id || !p.provenance_sequence)
			return -EINVAL;
		provenance = agi_lc_find_provenance(s, p.provenance_id,
							p.provenance_sequence);
		if (!provenance || !provenance->valid ||
		    provenance->provenance.agent_id != faisal_task_get_agent(current))
			return -EACCES;
		for (i = 0; i < AGI_LC_PROVENANCE_BINDING_RECORDS; i++)
			if (!s->provenance_bindings[i].valid) {
				record = &s->provenance_bindings[i];
				break;
			}
		if (!record)
			return -ENOSPC;
		if (++s->provenance_binding_next_id == U64_MAX)
			return -EOVERFLOW;
		if (p.scope_kind == AGI_LC_PROVENANCE_BIND_TENSOR) {
			mutex_lock(&agi_lc_memory_lock);
			memory = agi_lc_memory_find_locked(s, p.resource_id);
			if (!memory || memory->revoked ||
			    !agi_lc_memory_authorized_locked(s, memory,
							p.resource_capability,
							AGI_LC_MEMORY_ACCESS_READ) ||
			    !memory->tensor_valid ||
			    memory->tensor.generation != p.resource_generation) {
				mutex_unlock(&agi_lc_memory_lock);
				return -EACCES;
			}
			memory->tensor.provenance_binding_id = s->provenance_binding_next_id;
			memory->tensor.provenance_id = p.provenance_id;
			memory->tensor.provenance_sequence = p.provenance_sequence;
			memory->tensor.provenance_generation = p.resource_generation;
			mutex_unlock(&agi_lc_memory_lock);
		} else {
			mutex_lock(&s->context_lock);
			context = agi_lc_context_find_locked(s, p.resource_id,
							p.resource_capability);
			if (!context || context->context.agent_id != faisal_task_get_agent(current) ||
			    context->context.state != AGI_LC_CONTEXT_STATE_ACTIVE ||
			    context->context.generation != p.resource_generation) {
				mutex_unlock(&s->context_lock);
				return -EACCES;
			}
			context->context.provenance_binding_id = s->provenance_binding_next_id;
			context->context.provenance_id = p.provenance_id;
			context->context.provenance_sequence = p.provenance_sequence;
			context->context.provenance_generation = p.resource_generation;
			mutex_unlock(&s->context_lock);
		}
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->owner_agent = faisal_task_get_agent(current);
		record->binding = p;
		record->binding.binding_id = s->provenance_binding_next_id;
		record->binding.binding_generation = 1;
		record->binding.status = 0;
		out = record->binding;
	} else {
		if (!p.binding_id || p.status || p.binding_generation)
			return -EINVAL;
		record = agi_lc_provenance_binding_find(s, p.binding_id);
		if (!record || record->owner_agent != faisal_task_get_agent(current))
			return -EACCES;
		if (p.operation == AGI_LC_PROVENANCE_BIND_GET) {
			out = record->binding;
			out.operation = AGI_LC_PROVENANCE_BIND_GET;
		} else {
			if (record->binding.status) {
				ret = -EALREADY;
				goto out;
			}
			if (record->binding.scope_kind == AGI_LC_PROVENANCE_BIND_TENSOR) {
				mutex_lock(&agi_lc_memory_lock);
				memory = agi_lc_memory_find_locked(s, record->binding.resource_id);
				if (memory && memory->tensor.provenance_binding_id == p.binding_id) {
					memory->tensor.provenance_binding_id = 0;
					memory->tensor.provenance_id = 0;
					memory->tensor.provenance_sequence = 0;
					memory->tensor.provenance_generation = 0;
				}
				mutex_unlock(&agi_lc_memory_lock);
			} else {
				mutex_lock(&s->context_lock);
				context = agi_lc_context_find_locked(s,
						record->binding.resource_id,
						record->binding.resource_capability);
				if (context && context->context.provenance_binding_id == p.binding_id) {
					context->context.provenance_binding_id = 0;
					context->context.provenance_id = 0;
					context->context.provenance_sequence = 0;
					context->context.provenance_generation = 0;
				}
				mutex_unlock(&s->context_lock);
			}
			record->binding.operation = AGI_LC_PROVENANCE_BIND_REVOKE;
			record->binding.status = -ECANCELED;
			record->binding.binding_generation++;
			out = record->binding;
		}
	}
out:
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &out, sizeof(out)))
		return -EFAULT;
	return agi_lc_push_record(s, AGI_LC_EVENT_PROVENANCE, out.status,
					out.correlation, out.binding_id);
}
static int agi_lc_open(struct inode *inode, struct file *file)
{
	struct agi_lc_session *session;

	session = kzalloc_obj(*session);
	if (!session)
		return -ENOMEM;
	mutex_init(&session->ioctl_lock);
mutex_init(&session->context_lock);
mutex_init(&session->graph_lock);
	spin_lock_init(&session->queue_lock);
	init_waitqueue_head(&session->read_wait);
	init_waitqueue_head(&session->gate_wait);
	init_waitqueue_head(&session->msg_wait);
	init_waitqueue_head(&session->light_wait);
	init_waitqueue_head(&session->ipc_wait);
#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
	INIT_LIST_HEAD(&session->rv_node);
	spin_lock(&agi_lc_rv_sessions_lock);
	list_add_tail(&session->rv_node, &agi_lc_rv_sessions);
	session->rv_registered = true;
	spin_unlock(&agi_lc_rv_sessions_lock);
#endif
	session->gate_open = true;
	session->event_mask = ~0ULL;
	session->world_class_mask = 0;
	session->world_min_priority = AGI_LC_WORLD_PRIORITY_LOW;
	session->world_queue_policy = AGI_LC_WORLD_QUEUE_DROP_NEW;
	file->private_data = session;
	return 0;
}

static int agi_lc_release(struct inode *inode, struct file *file)
{
	struct agi_lc_session *session = file->private_data;
	unsigned long flags;
	u32 i;

#ifdef CONFIG_AGI_LIFECYCLE_RV_BRIDGE
	spin_lock(&agi_lc_rv_sessions_lock);
	if (session->rv_registered) {
		list_del_init(&session->rv_node);
		session->rv_registered = false;
	}
	spin_unlock(&agi_lc_rv_sessions_lock);
#endif
	spin_lock_irqsave(&session->queue_lock, flags);
	session->revoked = true;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	for (i = 0; i < AGI_LC_INTENT_LEASE_RECORDS; i++) {
		session->intent_leases[i].revoked = true;
		session->intent_leases[i].lease.status =
			AGI_LC_INTENT_STATUS_REVOKED;
	}
	WRITE_ONCE(session->gate_open, true);

	wake_up_interruptible(&session->read_wait);
	wake_up_interruptible(&session->gate_wait);
	wake_up_interruptible(&session->msg_wait);
	wake_up_interruptible(&session->ipc_wait);
	if (session->checkpoint_manifest_valid && !session->recovery_invalidated)
		agi_lc_checkpoint_mark_crashed(session->checkpoint_id);
	agi_lc_memory_release_session(session, true);
	agi_lc_power_policy_release_all(session);
	agi_lc_artifact_release_session(session, true);
	if (session->tenant_cgroup) {
		cgroup_put(session->tenant_cgroup);
		session->tenant_cgroup = NULL;
	}
	memset(session->persistent_memory_records, 0, sizeof(session->persistent_memory_records));
	kfree(session->ipc_channels);
	kfree(session->light_agents);
	kfree(session);
	return 0;
}

static ssize_t agi_lc_read(struct file *file, char __user *buffer,
			   size_t length, loff_t *offset)
{
	struct agi_lc_session *session = file->private_data;
	struct agi_lc_record record;
	unsigned long flags;
	int ret;

	if (length < sizeof(record))
		return -EINVAL;
	if (!READ_ONCE(session->count)) {
		if (READ_ONCE(session->revoked))
			return 0;
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		ret = wait_event_interruptible(session->read_wait,
					       agi_lc_has_record(session));
		if (ret)
			return ret;
		if (!READ_ONCE(session->count))
			return 0;
	}

	spin_lock_irqsave(&session->queue_lock, flags);
	if (!session->count) {
		spin_unlock_irqrestore(&session->queue_lock, flags);
		return READ_ONCE(session->revoked) ? 0 : -EAGAIN;
	}
	record = session->records[session->head];
	session->head = (session->head + 1) % AGI_LC_RING_SIZE;
	session->count--;
	spin_unlock_irqrestore(&session->queue_lock, flags);

	if (copy_to_user(buffer, &record, sizeof(record)))
		return -EFAULT;
	return sizeof(record);
}

static __poll_t agi_lc_poll(struct file *file, poll_table *wait)
{
	struct agi_lc_session *session = file->private_data;
	__poll_t mask = 0;

	poll_wait(file, &session->read_wait, wait);
	if (READ_ONCE(session->count))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (READ_ONCE(session->revoked))
		mask |= EPOLLHUP;
	return mask;
}

static int agi_lc_copy_event(struct agi_lc_session *session,
				      unsigned int command, unsigned long arg)
{
	struct agi_lc_event event;

	if (copy_from_user(&event, (void __user *)arg, sizeof(event)))
		return -EFAULT;
	if (event.size != sizeof(event) || event.flags || event.reserved)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	return agi_lc_push_record(session,
				  command == AGI_LC_BEGIN ? AGI_LC_EVENT_BEGIN :
				  AGI_LC_EVENT_END, event.status,
				  event.correlation, event.metadata);
}

static int agi_lc_cancel(struct agi_lc_session *session,
				  unsigned long arg)
{
	struct agi_lc_cancel cancel;
	struct task_struct *target;
	struct pid *pid;
	int ret;

	if (copy_from_user(&cancel, (void __user *)arg, sizeof(cancel)))
		return -EFAULT;
	if (cancel.size != sizeof(cancel) || cancel.flags ||
	    cancel.reserved[0] || cancel.reserved[1] || cancel.pid <= 0 ||
	    cancel.signal != SIGTERM)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	pid = find_get_pid(cancel.pid);
	if (!pid)
		return -ESRCH;
	target = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!target)
		return -ESRCH;
	if (faisal_task_get_lineage(target) != session->session_id) {
		put_task_struct(target);
		return -EPERM;
	}

	faisal_task_request_cancel(target);
	ret = send_sig(SIGTERM, target, 0);
	put_task_struct(target);
	if (ret)
		return ret;

	return agi_lc_push_record(session, AGI_LC_EVENT_CANCEL, 0,
					  cancel.correlation, (u64)cancel.pid);
}

static int agi_lc_get_stats(struct agi_lc_session *session,
				    unsigned long arg)
{
	struct agi_lc_stats stats = {
		.size = sizeof(stats),
	};
	struct task_struct *group;
	struct task_struct *task;

	if (copy_from_user(&stats, (void __user *)arg, sizeof(stats)))
		return -EFAULT;
	if (stats.size != sizeof(stats) || stats.reserved[0] ||
	    stats.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	rcu_read_lock();
	for_each_process_thread(group, task) {
		if (faisal_task_get_lineage(task) != session->session_id)
			continue;
		stats.thread_count++;
		if (thread_group_leader(task))
			stats.process_count++;
		stats.cpu_time_ns += READ_ONCE(task->se.sum_exec_runtime);
		stats.voluntary_context_switches += READ_ONCE(task->nvcsw);
		stats.involuntary_context_switches += READ_ONCE(task->nivcsw);
		stats.minor_faults += READ_ONCE(task->min_flt);
		stats.major_faults += READ_ONCE(task->maj_flt);
	}
	rcu_read_unlock();

	stats.abi_version = AGI_LC_ABI_VERSION;
	stats.session_id = session->session_id;
	stats.sampled_at_ns = ktime_get_ns();
	if (copy_to_user((void __user *)arg, &stats, sizeof(stats)))
		return -EFAULT;
	return 0;
}

static u64 agi_lc_capability_mask(kernel_cap_t caps)
{
	u64 mask = 0;
	u32 i;

	for (i = 0; i <= CAP_LAST_CAP && i < 64; i++)
		if (cap_raised(caps, i))
			mask |= 1ULL << i;
	return mask;
}

static int agi_lc_get_self_state(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_self_state state;
	struct task_struct *group;
	struct task_struct *task;
	struct agi_lc_agent_record *agent;
	unsigned long flags;
	u64 memory_limit_pages;
	u64 memory_current_pages;
	u64 cpu_budget_ns;
	u64 cpu_elapsed_ns;
	u64 accel_compute_ns;
	u64 accel_memory_bytes;
	u64 accel_submissions;
	u64 top_cpu_time_ns = 0;
	u64 top_memory_bytes = 0;
	u32 i;
	u64 correlation;
	bool budget_exhausted;
	bool memory_exceeded;

	if (copy_from_user(&state, (void __user *)arg, sizeof(state)))
		return -EFAULT;
	if (state.size != sizeof(state) || state.flags || state.reserved32 ||
	    state.reserved[0] || state.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	correlation = state.correlation;

	memset((u8 *)&state + offsetof(struct agi_lc_self_state, session_id),
	       0, sizeof(state) - offsetof(struct agi_lc_self_state, session_id));
	state.size = sizeof(state);
	state.correlation = correlation;
	state.session_id = session->session_id;
	state.sampled_at_ns = ktime_get_ns();
	state.current_pid = task_pid_nr(current);
	state.current_tgid = task_tgid_nr(current);
	state.current_lineage = faisal_task_get_lineage(current);
	state.current_agent = faisal_task_get_agent(current);
	state.current_phase = faisal_task_get_phase(current);
	state.current_state = task_state_index(current);
	state.current_cancelled = faisal_task_cancelled(current);
	state.capabilities_effective =
		agi_lc_capability_mask(current_cred()->cap_effective);
	state.capabilities_permitted =
		agi_lc_capability_mask(current_cred()->cap_permitted);
	state.capabilities_inheritable =
		agi_lc_capability_mask(current_cred()->cap_inheritable);
	state.capabilities_bounding =
		agi_lc_capability_mask(current_cred()->cap_bset);
	faisal_task_get_budget(current, &cpu_budget_ns, &cpu_elapsed_ns,
			       &budget_exhausted);
	faisal_task_get_memory_limit(current, &memory_limit_pages,
				     &memory_current_pages, &memory_exceeded);
	faisal_task_accel_get(current, &accel_compute_ns,
				      &accel_memory_bytes, &accel_submissions);
	state.cpu_budget_ns = cpu_budget_ns;
	state.cpu_elapsed_ns = cpu_elapsed_ns;
	state.current_budget_exhausted = budget_exhausted;
	state.memory_limit_pages = memory_limit_pages;
	state.memory_current_pages = memory_current_pages;
	state.current_memory_exceeded = memory_exceeded;
	state.accel_compute_ns = accel_compute_ns;
	state.accel_memory_bytes = accel_memory_bytes;
	state.accel_submissions = accel_submissions;
	spin_lock_irqsave(&session->queue_lock, flags);
	state.change_generation = session->change_generation;
	state.last_event_sequence = session->next_sequence ?
		session->next_sequence - 1 : 0;
	state.last_failure_sequence = session->last_failure_sequence;
	state.failed_count = session->failure_count;
	state.dropped_records = session->dropped_records;
	state.world_delivered = session->world_delivered;
	state.world_filtered = session->world_filtered;
	state.world_dropped = session->world_dropped;
	spin_unlock_irqrestore(&session->queue_lock, flags);

	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		agent = &session->agents[i];
		if (!agent->valid)
			continue;
		state.agent_count++;
		if (agent->state != AGI_LC_AGENT_STATE_COMPLETED)
			state.active_agent_count++;
	}
	for (i = 0; i < AGI_LC_LEASE_MAX; i++) {
		if (!session->leases[i].lease_id)
			continue;
		state.lease_count++;
		if (session->leases[i].active) {
			state.active_lease_count++;
			if (session->leases[i].resource > 0 &&
			    session->leases[i].resource <= 64)
				state.lease_resource_mask |=
					1ULL << (session->leases[i].resource - 1);
		}
	}

	rcu_read_lock();
	for_each_process_thread(group, task) {
		u64 cpu_time;
		u64 memory_bytes = 0;
		struct mm_struct *mm;
		int task_state;

		if (faisal_task_get_lineage(task) != session->session_id)
			continue;
		state.thread_count++;
		if (thread_group_leader(task))
			state.process_count++;
		task_state = task_state_index(task);
		if (task_state == TASK_RUNNING || READ_ONCE(task->on_rq))
			state.runnable_count++;
		else
			state.blocked_count++;
		if (faisal_task_cancelled(task))
			state.cancelled_count++;
		cpu_time = READ_ONCE(task->se.sum_exec_runtime);
		state.cpu_time_ns += cpu_time;
		state.voluntary_context_switches += READ_ONCE(task->nvcsw);
		state.involuntary_context_switches += READ_ONCE(task->nivcsw);
		state.minor_faults += READ_ONCE(task->min_flt);
		state.major_faults += READ_ONCE(task->maj_flt);
		if (cpu_time > top_cpu_time_ns) {
			top_cpu_time_ns = cpu_time;
			state.top_cpu_pid = task_pid_nr(task);
		}
		mm = READ_ONCE(task->mm);
		if (mm)
			memory_bytes = (u64)get_mm_rss(mm) << PAGE_SHIFT;
		state.memory_bytes += memory_bytes;
		if (memory_bytes > top_memory_bytes) {
			top_memory_bytes = memory_bytes;
			state.top_memory_tgid = task_tgid_nr(task);
		}
	}
	rcu_read_unlock();
	state.top_cpu_time_ns = top_cpu_time_ns;
	state.top_memory_bytes = top_memory_bytes;
	state.online_cpus = num_online_cpus();
	state.possible_cpus = num_possible_cpus();
	state.resource_flags = AGI_LC_SELF_RESOURCE_UPSTREAM;
#ifdef CONFIG_PSI
	state.resource_flags |= AGI_LC_SELF_RESOURCE_PSI;
#endif
#if IS_ENABLED(CONFIG_CGROUPS)
	state.resource_flags |= AGI_LC_SELF_RESOURCE_CGROUP;
#endif
	if (copy_to_user((void __user *)arg, &state, sizeof(state)))
		return -EFAULT;
	return 0;
}

static bool agi_lc_memory_behavior_valid(u32 behavior)
{
	switch (behavior) {
	case MADV_WILLNEED:
	case MADV_COLD:
	case MADV_PAGEOUT:
	case MADV_HUGEPAGE:
	case MADV_NOHUGEPAGE:
		return true;
	default:
		return false;
	}
}

static int agi_lc_memory_hint(struct agi_lc_session *session,
				      unsigned long arg)
{
	struct agi_lc_memory_hint hint;
	int ret;

	if (copy_from_user(&hint, (void __user *)arg, sizeof(hint)))
		return -EFAULT;
	if (hint.size != sizeof(hint) || hint.flags || hint.reserved ||
	    hint.reserved2[0] || hint.reserved2[1] ||
	    !agi_lc_memory_behavior_valid(hint.behavior))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!current->mm)
		return -EINVAL;

	ret = do_madvise(current->mm, hint.start, hint.length, hint.behavior);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_MEMORY_HINT, 0,
					  hint.correlation, hint.behavior);
}

static int agi_lc_set_perf(struct agi_lc_session *session,
				   unsigned long arg)
{
#ifdef CONFIG_UCLAMP_TASK
	struct agi_lc_perf perf;
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = -1,
		.sched_flags = SCHED_FLAG_UTIL_CLAMP_MIN |
				       SCHED_FLAG_UTIL_CLAMP_MAX,
	};
	int ret;

	if (copy_from_user(&perf, (void __user *)arg, sizeof(perf)))
		return -EFAULT;
	if (perf.size != sizeof(perf) || perf.flags || perf.reserved[0] ||
	    perf.reserved[1] || perf.util_min > SCHED_CAPACITY_SCALE ||
	    perf.util_max > SCHED_CAPACITY_SCALE || perf.util_min > perf.util_max)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	attr.sched_util_min = perf.util_min;
	attr.sched_util_max = perf.util_max;
	ret = sched_setattr_nocheck(current, &attr);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_PERF, 0,
					  perf.correlation,
					  ((u64)perf.util_min << 32) | perf.util_max);
#else
	return -EOPNOTSUPP;
#endif
}

static bool agi_lc_message_matches(const struct agi_lc_message *message,
						 u64 agent_id)
{
	return message->target_agent == agent_id;
}

static bool agi_lc_has_message_for_agent(struct agi_lc_session *session,
						 u64 agent_id)
{
	unsigned long flags;
	u32 i;
	bool found = false;

	spin_lock_irqsave(&session->queue_lock, flags);
	for (i = 0; i < session->msg_count; i++) {
		u32 index = (session->msg_head + i) % AGI_LC_MESSAGE_SLOTS;

		if (agi_lc_message_matches(&session->messages[index], agent_id)) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return found || READ_ONCE(session->revoked);
}

static int agi_lc_register_agent(struct agi_lc_session *session,
					 u64 agent_id, u64 parent_agent,
					 pid_t owner_tgid)
{
	u32 i;

	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		if (session->agents[i].valid &&
		    session->agents[i].agent_id == agent_id)
			return -EEXIST;
	}
	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		if (!session->agents[i].valid) {
			session->agents[i].valid = true;
			session->agents[i].agent_id = agent_id;
							session->agents[i].parent_agent = parent_agent;
				session->agents[i].owner_tgid = owner_tgid;
				session->agents[i].creator_pid = task_pid_nr(current);
				session->agents[i].creator_tgid = owner_tgid;
						agi_lc_get_current_parent_pid_t(
						&session->agents[i].parent_pid,
						&session->agents[i].parent_tgid);

				session->agents[i].creator_uid =
					from_kuid_munged(current_user_ns(), current_uid());
				session->agents[i].creator_euid =
					from_kuid_munged(current_user_ns(), current_euid());
				return 0;

		}
	}
	return -ENOSPC;
}

static void agi_lc_unregister_agent(struct agi_lc_session *session,
					    u64 agent_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		if (session->agents[i].valid &&
		    session->agents[i].agent_id == agent_id) {
			session->agents[i].valid = false;
			return;
		}
	}
}

static int agi_lc_get_agent(struct agi_lc_session *session,
				    unsigned long arg)
{
	struct agi_lc_agent_query query;
	u32 i;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || !query.agent_id ||
	    query.parent_agent || query.owner_tgid || query.active ||
	    query.reserved || query.correlation || query.reserved2[0] ||
	    query.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		if (session->agents[i].valid &&
		    session->agents[i].agent_id == query.agent_id) {
			query.parent_agent = session->agents[i].parent_agent;
			query.owner_tgid = session->agents[i].owner_tgid;
			query.active = 1;
			if (copy_to_user((void __user *)arg, &query,
					 sizeof(query)))
				return -EFAULT;
			return 0;
		}
	}
	return -ENOENT;
}

static struct agi_lc_agent_record *
agi_lc_find_agent(struct agi_lc_session *session, u64 agent_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++)
		if (session->agents[i].valid &&
		    session->agents[i].agent_id == agent_id)
			return &session->agents[i];
	return NULL;
}

static struct agi_lc_light_agent_record *
agi_lc_find_light_agent(struct agi_lc_session *session, u64 agent_id,
				u64 capability)
{
	if (!session->light_agents || !agent_id || agent_id > AGI_LC_LIGHT_AGENT_MAX ||
	    !capability || !session->light_agents[agent_id - 1].valid ||
	    session->light_agents[agent_id - 1].capability != capability)
		return NULL;
	return &session->light_agents[agent_id - 1];
}

static bool agi_lc_current_light_agent_owns(
		struct agi_lc_session *session, u64 agent_id, u64 capability)
{
	/* A token is not an identity: bind it to the calling task as well. */
	return agent_id && capability &&
		faisal_task_get_agent(current) == agent_id &&
		agi_lc_find_light_agent(session, agent_id, capability);
}

static int agi_lc_light_common_validate(struct agi_lc_session *session)
{
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	return 0;
}

static int agi_lc_light_register(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_light_agent agent;
	struct agi_lc_light_agent_record *record;
	u64 capability;
	u32 i;
	int ret;

	if (copy_from_user(&agent, (void __user *)arg, sizeof(agent)))
		return -EFAULT;
	if (agent.size != sizeof(agent) || agent.flags || agent.agent_id ||
	    (agent.parent_agent && !agent.parent_capability) ||
	    (!agent.parent_agent && agent.parent_capability) || agent.capability ||
	    !agent.role || agent.role > AGI_LC_LIGHT_AGENT_ROLE_MAX ||
	    agent.state || agent.workload > AGI_LC_WORKLOAD_MAX ||
	    agent.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    agent.resource_mask & ~AGI_LC_RESOURCE_ALL || agent.generation ||
	    agent.messages_sent || agent.messages_received || agent.dropped_messages ||
	    agent.events_delivered || agent.last_event_sequence || agent.reserved32 ||
	    agent.reserved[0] || agent.reserved[1] || !agent.correlation)
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (agent.parent_agent &&
		(faisal_task_get_agent(current) != agent.parent_agent ||
		 !agi_lc_find_light_agent(session, agent.parent_agent,
						 agent.parent_capability)))
		return -EACCES;
	if (!session->light_agents) {
		session->light_agents = kcalloc(AGI_LC_LIGHT_AGENT_MAX,
						 sizeof(*session->light_agents), GFP_KERNEL);
		if (!session->light_agents)
			return -ENOMEM;
	}
	for (i = 0; i < AGI_LC_LIGHT_AGENT_MAX; i++)
		if (!session->light_agents[i].valid)
			break;
	if (i == AGI_LC_LIGHT_AGENT_MAX)
		return -ENOSPC;
	capability = get_random_u64();
	while (!capability)
		capability = get_random_u64();
	record = &session->light_agents[i];
	memset(record, 0, sizeof(*record));
	record->valid = true;
	record->agent_id = i + 1;
	record->parent_agent = agent.parent_agent;
	record->capability = capability;
	record->creator_pid = task_pid_nr(current);
	record->creator_tgid = task_tgid_nr(current);
	agi_lc_get_current_parent_pid_t(&record->parent_pid,
								&record->parent_tgid);
	record->creator_uid =
		from_kuid_munged(current_user_ns(), current_uid());
	record->creator_euid =
		from_kuid_munged(current_user_ns(), current_euid());
	record->role = agent.role;
	record->state = AGI_LC_LIGHT_AGENT_STATE_READY;
	record->workload = agent.workload;
	record->priority = agent.priority;
	record->resource_mask = agent.resource_mask;
	record->event_mask = agent.event_mask;
	record->generation = 1;
	session->light_agent_count++;
	agent.agent_id = record->agent_id;
	agent.parent_capability = 0;
	agent.capability = capability;
	agent.state = record->state;
	agent.generation = record->generation;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_LIGHT_AGENT, 0,
				 agent.correlation, agent.agent_id);
	if (ret) {
		record->valid = false;
		session->light_agent_count--;
		return ret;
	}
	if (session->light_agents[agent.agent_id - 1].generation > agent.generation)
		agent.generation = session->light_agents[agent.agent_id - 1].generation;
	if (copy_to_user((void __user *)arg, &agent, sizeof(agent)))
		return -EFAULT;
	return 0;
}

static int agi_lc_light_unregister(struct agi_lc_session *session,
					   unsigned long arg)
{
	struct agi_lc_light_agent agent;
	struct agi_lc_light_agent_record *record;
	int ret;

	if (copy_from_user(&agent, (void __user *)arg, sizeof(agent)))
		return -EFAULT;
	if (agent.size != sizeof(agent) || agent.flags || !agent.agent_id ||
	    !agent.capability || agent.parent_agent || agent.parent_capability ||
	    agent.role || agent.state || agent.workload || agent.priority ||
	    agent.resource_mask || agent.reserved32 || agent.event_mask ||
	    agent.generation || agent.messages_sent || agent.messages_received ||
	    agent.dropped_messages || agent.events_delivered ||
	    agent.last_event_sequence || !agent.correlation || agent.reserved[0] ||
	    agent.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	record = agi_lc_find_light_agent(session, agent.agent_id, agent.capability);
	if (!record)
		return -EACCES;
	memset(record, 0, sizeof(*record));
	if (session->light_agent_count)
		session->light_agent_count--;
	wake_up_interruptible(&session->light_wait);
	return agi_lc_push_record(session, AGI_LC_EVENT_LIGHT_AGENT, 0,
				  agent.correlation, agent.agent_id);
}

static int agi_lc_light_get(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_agent query;
	struct agi_lc_light_agent_record *record;
	int ret;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || !query.agent_id ||
	    !query.capability || query.parent_agent || query.parent_capability ||
	    query.role || query.state || query.workload || query.priority ||
	    query.resource_mask || query.reserved32 || query.event_mask ||
	    query.generation || query.messages_sent || query.messages_received ||
	    query.dropped_messages || query.events_delivered ||
	    query.last_event_sequence || query.correlation || query.reserved[0] ||
	    query.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	record = agi_lc_find_light_agent(session, query.agent_id, query.capability);
	if (!record)
		return -EACCES;
	query.parent_agent = record->parent_agent;
	query.role = record->role;
	query.state = record->state;
	query.workload = record->workload;
	query.priority = record->priority;
	query.resource_mask = record->resource_mask;
	query.event_mask = record->event_mask;
	query.generation = record->generation;
	query.messages_sent = record->messages_sent;
	query.messages_received = record->messages_received;
	query.dropped_messages = record->dropped_messages;
	query.events_delivered = record->events_delivered;
	query.last_event_sequence = record->last_event_sequence;
	if (copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return 0;
}

static int agi_lc_light_update(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_agent update;
	struct agi_lc_light_agent_record *record;
	int ret;

	if (copy_from_user(&update, (void __user *)arg, sizeof(update)))
		return -EFAULT;
	if (update.size != sizeof(update) || update.flags || !update.agent_id ||
	    !update.capability || update.parent_agent || update.parent_capability ||
	    update.role || update.generation || update.messages_sent ||
	    update.messages_received || update.dropped_messages ||
	    update.events_delivered || update.last_event_sequence ||
	    update.reserved32 || !update.correlation || update.reserved[0] ||
	    update.reserved[1] || update.state > AGI_LC_LIGHT_AGENT_STATE_MAX ||
	    update.workload > AGI_LC_WORKLOAD_MAX ||
	    update.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    update.resource_mask & ~AGI_LC_RESOURCE_ALL)
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	record = agi_lc_find_light_agent(session, update.agent_id,
						 update.capability);
	if (!record)
		return -EACCES;
	record->state = update.state;
	record->workload = update.workload;
	record->priority = update.priority;
	record->resource_mask = update.resource_mask;
	record->event_mask = update.event_mask;
	record->generation++;
	update.parent_agent = record->parent_agent;
	update.role = record->role;
	update.generation = record->generation;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_LIGHT_AGENT, 0,
				 update.correlation, update.agent_id);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &update, sizeof(update)))
		return -EFAULT;
	wake_up_interruptible(&session->light_wait);
	return 0;
}

static int agi_lc_light_send(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_message message;
	struct agi_lc_light_agent_record *sender;
	struct agi_lc_light_agent_record *target;
	unsigned long flags;
	int ret;

	if (copy_from_user(&message, (void __user *)arg, sizeof(message)))
		return -EFAULT;
	if (message.size != sizeof(message) || message.flags ||
	    !message.length || message.length > AGI_LC_LIGHT_AGENT_MESSAGE_MAX ||
	    message.reserved32 || message.timeout_ns || !message.sender_agent ||
	    !message.sender_capability || !message.target_agent ||
	    !message.target_capability || message.sequence ||
	    !message.correlation || memchr_inv(message.payload + message.length, 0,
						 AGI_LC_LIGHT_AGENT_MESSAGE_MAX - message.length) ||
	    message.reserved[0] || message.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (!agi_lc_current_light_agent_owns(session, message.sender_agent,
						 message.sender_capability))
		return -EACCES;
	spin_lock_irqsave(&session->queue_lock, flags);
	sender = agi_lc_find_light_agent(session, message.sender_agent,
						 message.sender_capability);
	target = agi_lc_find_light_agent(session, message.target_agent,
						 message.target_capability);
	if (!sender || !target) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (target->msg_count == AGI_LC_LIGHT_AGENT_MAILBOX_SLOTS) {
		target->dropped_messages++;
		target->generation++;
		ret = -EAGAIN;
		goto out_unlock;
	}
	message.sequence = ++target->generation;
	target->messages[target->msg_tail] = message;
	target->msg_tail = (target->msg_tail + 1) % AGI_LC_LIGHT_AGENT_MAILBOX_SLOTS;
	target->msg_count++;
	sender->messages_sent++;
	ret = 0;
out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	wake_up_interruptible(&session->light_wait);
	if (copy_to_user((void __user *)arg, &message, sizeof(message)))
		return -EFAULT;
	return 0;
}

static bool agi_lc_light_has_message(struct agi_lc_session *session, u64 id,
					 u64 capability)
{
	struct agi_lc_light_agent_record *record;
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&session->queue_lock, flags);
	record = agi_lc_find_light_agent(session, id, capability);
	ready = record && record->msg_count;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return ready || READ_ONCE(session->revoked);
}

static int agi_lc_light_recv(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_message request;
	struct agi_lc_light_agent_record *target;
	unsigned long flags;
	long timeout;
	long ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || request.flags || request.length ||
	    request.reserved32 || request.sender_agent || request.sender_capability ||
	    !request.target_agent || !request.target_capability || request.sequence ||
	    !request.correlation || memchr_inv(request.payload, 0, sizeof(request.payload)) ||
	    request.reserved[0] || request.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	timeout = request.timeout_ns ? nsecs_to_jiffies(request.timeout_ns) :
				  MAX_SCHEDULE_TIMEOUT;
	ret = wait_event_interruptible_timeout(session->light_wait,
				agi_lc_light_has_message(session, request.target_agent,
							 request.target_capability), timeout);
	if (ret < 0)
		return ret;
	spin_lock_irqsave(&session->queue_lock, flags);
	target = agi_lc_find_light_agent(session, request.target_agent,
					 request.target_capability);
	if (!target) {
		ret = -EACCES;
		goto out_unlock;
	}
	if (!target->msg_count) {
		ret = ret ? -EAGAIN : -ETIMEDOUT;
		goto out_unlock;
	}
	request = target->messages[target->msg_head];
	target->messages[target->msg_head].length = 0;
	target->msg_head = (target->msg_head + 1) % AGI_LC_LIGHT_AGENT_MAILBOX_SLOTS;
	target->msg_count--;
	target->messages_received++;
	ret = 0;
out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static int agi_lc_light_wait(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_wait wait;
	struct agi_lc_light_agent_record *record;
	unsigned long flags;
	long timeout;
	long ret;

	if (copy_from_user(&wait, (void __user *)arg, sizeof(wait)))
		return -EFAULT;
	if (wait.size != sizeof(wait) || wait.flags || !wait.agent_id ||
		    !wait.capability || wait.generation || wait.state || wait.status ||
		    !wait.correlation || wait.reserved[0] || wait.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	timeout = wait.timeout_ns ? nsecs_to_jiffies(wait.timeout_ns) :
				  MAX_SCHEDULE_TIMEOUT;
	ret = wait_event_interruptible_timeout(session->light_wait, ({
				bool changed;

				spin_lock_irqsave(&session->queue_lock, flags);
			record = agi_lc_find_light_agent(session, wait.agent_id,
							wait.capability);
			changed = record && record->generation != wait.expected_generation;
			spin_unlock_irqrestore(&session->queue_lock, flags);
			changed || READ_ONCE(session->revoked);
		}), timeout);
	if (ret < 0)
		return ret;
	spin_lock_irqsave(&session->queue_lock, flags);
	record = agi_lc_find_light_agent(session, wait.agent_id, wait.capability);
	if (!record) {
		spin_unlock_irqrestore(&session->queue_lock, flags);
		return -EACCES;
	}
	wait.generation = record->generation;
	wait.state = record->state;
	wait.status = ret ? 0 : -ETIMEDOUT;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &wait, sizeof(wait)))
		return -EFAULT;
	return 0;
}

static int agi_lc_light_list(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_light_list list;
	u32 i;
	int ret;

	if (copy_from_user(&list, (void __user *)arg, sizeof(list)))
		return -EFAULT;
	if (list.size != sizeof(list) || list.flags || list.agent_id ||
	    list.next_agent_id || !list.correlation || list.reserved[0] ||
	    list.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (!session->light_agents)
		return -ENOENT;
	for (i = 0; i < AGI_LC_LIGHT_AGENT_MAX; i++)
		if (session->light_agents[i].valid &&
		    session->light_agents[i].agent_id > list.cursor)
			break;
	if (i == AGI_LC_LIGHT_AGENT_MAX)
		return -ENOENT;
	list.agent_id = session->light_agents[i].agent_id;
	for (i++; i < AGI_LC_LIGHT_AGENT_MAX; i++)
		if (session->light_agents[i].valid) {
			list.next_agent_id = session->light_agents[i].agent_id;
			break;
		}
	if (copy_to_user((void __user *)arg, &list, sizeof(list)))
		return -EFAULT;
	return 0;
}

static int agi_lc_ipc_ensure_channels(struct agi_lc_session *session)
{
	struct agi_lc_ipc_channel_record *channels;
	unsigned long flags;

	if (READ_ONCE(session->ipc_channels))
		return 0;
	channels = kcalloc(AGI_LC_IPC_CHANNELS, sizeof(*channels),
				 GFP_KERNEL_ACCOUNT);
	if (!channels)
		return -ENOMEM;
	spin_lock_irqsave(&session->queue_lock, flags);
	if (!session->ipc_channels)
		WRITE_ONCE(session->ipc_channels, channels);
	else
		kfree(channels);
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return 0;
}

static struct agi_lc_ipc_channel_record *
agi_lc_ipc_find(struct agi_lc_session *session, u64 channel_id, u64 capability)
{
	u32 i;
	struct agi_lc_ipc_channel_record *channels =
		READ_ONCE(session->ipc_channels);

	if (!channels)
		return NULL;
	for (i = 0; i < AGI_LC_IPC_CHANNELS; i++) {
		struct agi_lc_ipc_channel_record *channel =
			&channels[i];

		if (channel->valid && channel->channel_id == channel_id &&
		    channel->capability == capability)
			return channel;
	}
	return NULL;
}

static bool agi_lc_ipc_endpoint(struct agi_lc_ipc_channel_record *channel,
					u64 agent, u64 capability, bool source)
{
	return source ? (channel->source_agent == agent &&
				 channel->source_capability == capability) :
			       (channel->target_agent == agent &&
				 channel->target_capability == capability);
}

static void agi_lc_ipc_remove_locked(struct agi_lc_ipc_channel_record *channel,
					     u32 position)
{
	u32 i;

	for (i = position; i + 1 < channel->count; i++) {
		u32 current_index = (channel->head + i) % AGI_LC_IPC_QUEUE_MAX;
		u32 next = (channel->head + i + 1) % AGI_LC_IPC_QUEUE_MAX;

		channel->messages[current_index] = channel->messages[next];
	}
	if (channel->count) {
		u32 last = (channel->head + channel->count - 1) %
			AGI_LC_IPC_QUEUE_MAX;

		memset(&channel->messages[last], 0, sizeof(channel->messages[last]));
		channel->count--;
	}
}

static bool agi_lc_ipc_has_space(struct agi_lc_session *session,
					 u64 channel_id, u64 capability)
{
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, channel_id, capability);
	ready = !channel || channel->closed ||
		channel->count < channel->max_queue;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return ready || READ_ONCE(session->revoked);
}

static bool agi_lc_ipc_has_message(struct agi_lc_session *session,
					   u64 channel_id, u64 capability)
{
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	bool ready;

	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, channel_id, capability);
	ready = !channel || channel->closed || channel->count;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	return ready || READ_ONCE(session->revoked);
}

static int agi_lc_ipc_validate_large(struct agi_lc_session *session,
					 struct agi_lc_ipc_message *message, u64 agent_id)
{
	struct agi_lc_memory_record *region;
	u64 end;
	int ret = 0;

	if (check_add_overflow(message->memory_offset, (u64)message->length, &end))
		return -EOVERFLOW;
	mutex_lock(&agi_lc_memory_lock);
	region = agi_lc_memory_find_locked(session, message->memory_region_id);
	if (!region || !agi_lc_memory_authorized_agent_locked(session, region,
						message->memory_capability,
						AGI_LC_MEMORY_ACCESS_READ, agent_id) ||
	    end > region->size_bytes)
		ret = -EACCES;
	mutex_unlock(&agi_lc_memory_lock);
	return ret;
}

static int agi_lc_ipc_channel_create(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_ipc_channel input;
	struct agi_lc_ipc_channel_record *channel = NULL;
	struct agi_lc_ipc_channel_record *channels;
	unsigned long flags;
	u64 capability;
	u32 i;
	int ret;

	if (copy_from_user(&input, (void __user *)arg, sizeof(input)))
		return -EFAULT;
	if (input.size != sizeof(input) || input.flags || input.channel_id ||
	    input.channel_capability || !input.source_agent ||
	    !input.source_capability || !input.target_agent ||
	    !input.target_capability || input.source_agent == input.target_agent ||
	    !input.max_queue || input.max_queue > AGI_LC_IPC_QUEUE_MAX ||
	    input.queue_depth || input.generation || input.messages_sent ||
	    input.messages_received || input.messages_cancelled ||
	    input.messages_dropped || !input.correlation || input.reserved[0] ||
	    input.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (faisal_task_get_agent(current) != input.source_agent)
		return -EACCES;
	ret = agi_lc_ipc_ensure_channels(session);
	if (ret)
		return ret;
	channels = READ_ONCE(session->ipc_channels);
	if (!channels)
		return -ENOMEM;
	spin_lock_irqsave(&session->queue_lock, flags);
	if (!agi_lc_find_light_agent(session, input.source_agent,
					     input.source_capability) ||
	    !agi_lc_find_light_agent(session, input.target_agent,
					     input.target_capability)) {
		ret = -EACCES;
		goto out_unlock;
	}
	for (i = 0; i < AGI_LC_IPC_CHANNELS; i++)
		if (!channels[i].valid)
			break;
	if (i == AGI_LC_IPC_CHANNELS) {
		ret = -ENOSPC;
		goto out_unlock;
	}
	if (session->ipc_next_id == U64_MAX) {
		ret = -EOVERFLOW;
		goto out_unlock;
	}
	capability = get_random_u64();
	while (!capability)
		capability = get_random_u64();
	channel = &channels[i];
	memset(channel, 0, sizeof(*channel));
	channel->valid = true;
	channel->channel_id = ++session->ipc_next_id;
	channel->capability = capability;
	channel->source_agent = input.source_agent;
	channel->source_capability = input.source_capability;
	channel->target_agent = input.target_agent;
	channel->target_capability = input.target_capability;
	channel->max_queue = input.max_queue;
	channel->generation = 1;
	input.channel_id = channel->channel_id;
	input.channel_capability = capability;
	input.queue_depth = 0;
	input.generation = channel->generation;
	input.messages_sent = 0;
	input.messages_received = 0;
	input.messages_cancelled = 0;
	input.messages_dropped = 0;
	ret = 0;
out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	(void)agi_lc_push_record(session, AGI_LC_EVENT_IPC, 0,
				 input.correlation, input.channel_id);
	if (copy_to_user((void __user *)arg, &input, sizeof(input)))
		return -EFAULT;
	wake_up_interruptible(&session->ipc_wait);
	return 0;
}

static int agi_lc_ipc_channel_close(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_ipc_channel input;
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	u32 i;
	int ret;

	if (copy_from_user(&input, (void __user *)arg, sizeof(input)))
		return -EFAULT;
	if (input.size != sizeof(input) || input.flags || !input.channel_id ||
	    !input.channel_capability || !input.source_agent ||
	    !input.source_capability || input.target_agent ||
	    input.target_capability || input.max_queue || input.queue_depth ||
	    input.generation || input.messages_sent || input.messages_received ||
	    input.messages_cancelled || input.messages_dropped || !input.correlation ||
	    input.reserved[0] || input.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (faisal_task_get_agent(current) != input.source_agent)
		return -EACCES;
	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, input.channel_id,
					  input.channel_capability);
	if (!channel || !agi_lc_ipc_endpoint(channel, input.source_agent,
						     input.source_capability, true)) {
		ret = -EACCES;
		goto out_unlock;
	}
	channel->closed = true;
	for (i = 0; i < AGI_LC_IPC_QUEUE_MAX; i++)
		channel->messages[i].valid = false;
	channel->count = 0;
	channel->generation++;
	channel->valid = false;
	ret = 0;
out_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	(void)agi_lc_push_record(session, AGI_LC_EVENT_IPC, 0,
				 input.correlation, input.channel_id);
	wake_up_interruptible(&session->ipc_wait);
	return 0;
}

static int agi_lc_ipc_send(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_ipc_message message;
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	long timeout;
	long wait_ret;
	int ret;

	if (copy_from_user(&message, (void __user *)arg, sizeof(message)))
		return -EFAULT;
	if (message.size != sizeof(message) ||
	    message.flags & ~(AGI_LC_IPC_MSG_NONBLOCK |
				      AGI_LC_IPC_MSG_STREAM_BEGIN |
				      AGI_LC_IPC_MSG_STREAM_MORE |
				      AGI_LC_IPC_MSG_STREAM_END |
				      AGI_LC_IPC_MSG_LARGE) ||
	    !message.length || message.priority > AGI_LC_IPC_PRIORITY_MAX ||
	    !message.type || !message.schema || message.status || message.reserved32 ||
	    !message.channel_id || !message.channel_capability ||
	    !message.sender_agent || !message.sender_capability ||
	    !message.target_agent || !message.target_capability || message.message_id ||
	    message.sequence || !message.correlation || message.timeout_ns > NSEC_PER_SEC * 60 ||
	    message.reserved[0] || message.reserved[1])
		return -EINVAL;
	if (message.flags & AGI_LC_IPC_MSG_LARGE) {
		if (!message.memory_region_id || !message.memory_capability ||
		    memchr_inv(message.payload, 0, sizeof(message.payload)))
			return -EINVAL;
		ret = agi_lc_ipc_validate_large(session, &message,
						faisal_task_get_agent(current));
		if (ret)
			return ret;
	} else if (message.length > AGI_LC_IPC_INLINE_MAX ||
		   message.memory_region_id || message.memory_capability ||
		   message.memory_offset ||
		   memchr_inv(message.payload + message.length, 0,
			      AGI_LC_IPC_INLINE_MAX - message.length)) {
		return -EINVAL;
	}
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (faisal_task_get_agent(current) != message.sender_agent)
		return -EACCES;
	if (!(message.flags & AGI_LC_IPC_MSG_LARGE) && message.length > AGI_LC_IPC_INLINE_MAX)
		return -EMSGSIZE;
	if (message.flags & AGI_LC_IPC_MSG_NONBLOCK)
		wait_ret = 0;
	else {
		timeout = message.timeout_ns ? nsecs_to_jiffies(message.timeout_ns) :
			MAX_SCHEDULE_TIMEOUT;
		wait_ret = wait_event_interruptible_timeout(session->ipc_wait,
				agi_lc_ipc_has_space(session, message.channel_id,
						     message.channel_capability), timeout);
	}
	if (wait_ret < 0)
		return wait_ret;
	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, message.channel_id,
					  message.channel_capability);
	if (!channel || channel->closed ||
	    !agi_lc_ipc_endpoint(channel, message.sender_agent,
					 message.sender_capability, true) ||
	    !agi_lc_ipc_endpoint(channel, message.target_agent,
					 message.target_capability, false)) {
		ret = -EACCES;
		goto send_unlock;
	}
	if (channel->count == channel->max_queue) {
		channel->messages_dropped++;
		ret = (message.flags & AGI_LC_IPC_MSG_NONBLOCK) || !message.timeout_ns ?
			-EAGAIN : -ETIMEDOUT;
		goto send_unlock;
	}
	message.message_id = ++session->ipc_next_message_id;
	if (!message.message_id)
		message.message_id = ++session->ipc_next_message_id;
	message.sequence = ++channel->generation;
	{
		u32 index = (channel->head + channel->count) % AGI_LC_IPC_QUEUE_MAX;

		channel->messages[index].valid = true;
		channel->messages[index].message = message;
		channel->count++;
	}
	channel->messages_sent++;
	ret = 0;
send_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	(void)agi_lc_push_record(session, AGI_LC_EVENT_IPC, 0,
				 message.correlation, message.message_id);
	wake_up_interruptible(&session->ipc_wait);
	if (copy_to_user((void __user *)arg, &message, sizeof(message)))
		return -EFAULT;
	return 0;
}

static int agi_lc_ipc_recv(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_ipc_message request;
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	long timeout;
	long wait_ret;
	u32 i, selected = 0;
	bool found = false;
	int ret;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) ||
	    request.flags & ~AGI_LC_IPC_MSG_NONBLOCK || !request.channel_id ||
	    !request.channel_capability || request.length || request.priority ||
	    request.type || request.schema || request.status || request.reserved32 ||
	    request.sender_agent || request.sender_capability || !request.target_agent ||
	    !request.target_capability || request.message_id || request.sequence ||
	    !request.correlation || request.parent_message_id || request.stream_id ||
	    request.stream_sequence || request.memory_region_id ||
	    request.memory_capability || request.memory_offset ||
	    memchr_inv(request.payload, 0, sizeof(request.payload)) ||
	    request.reserved[0] || request.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (request.flags & AGI_LC_IPC_MSG_NONBLOCK)
		wait_ret = 0;
	else {
		timeout = request.timeout_ns ? nsecs_to_jiffies(request.timeout_ns) :
			MAX_SCHEDULE_TIMEOUT;
		wait_ret = wait_event_interruptible_timeout(session->ipc_wait,
			agi_lc_ipc_has_message(session, request.channel_id,
						       request.channel_capability), timeout);
	}
	if (wait_ret < 0)
		return wait_ret;
	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, request.channel_id,
					  request.channel_capability);
	if (!channel || channel->closed ||
	    !agi_lc_ipc_endpoint(channel, request.target_agent,
					 request.target_capability, false)) {
		ret = -EACCES;
		goto recv_unlock;
	}
	if (!channel->count) {
		ret = (request.flags & AGI_LC_IPC_MSG_NONBLOCK) || !request.timeout_ns ?
			-EAGAIN : -ETIMEDOUT;
		goto recv_unlock;
	}
	for (i = 0; i < channel->count; i++) {
		u32 index = (channel->head + i) % AGI_LC_IPC_QUEUE_MAX;

		if (!channel->messages[index].valid)
			continue;
		if (!found || channel->messages[index].message.priority >
			channel->messages[selected].message.priority) {
			selected = i;
			found = true;
		}
	}
	if (!found) {
		ret = -EAGAIN;
		goto recv_unlock;
	}
	request = channel->messages[(channel->head + selected) % AGI_LC_IPC_QUEUE_MAX].message;
	agi_lc_ipc_remove_locked(channel, selected);
	channel->messages_received++;
	ret = 0;
recv_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	(void)agi_lc_push_record(session, AGI_LC_EVENT_IPC, 0,
				 request.correlation, request.message_id);
	wake_up_interruptible(&session->ipc_wait);
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return 0;
}

static int agi_lc_ipc_cancel(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_ipc_cancel cancel;
	struct agi_lc_ipc_channel_record *channel;
	unsigned long flags;
	u32 i;
	int ret;

	if (copy_from_user(&cancel, (void __user *)arg, sizeof(cancel)))
		return -EFAULT;
	if (cancel.size != sizeof(cancel) || cancel.flags & ~AGI_LC_CANCEL_NONBLOCK ||
	    !cancel.channel_id || !cancel.channel_capability || !cancel.sender_agent ||
	    !cancel.sender_capability || !cancel.message_id || cancel.status ||
	    cancel.reserved32 || !cancel.correlation || cancel.reserved[0] ||
	    cancel.reserved[1])
		return -EINVAL;
	ret = agi_lc_light_common_validate(session);
	if (ret)
		return ret;
	if (faisal_task_get_agent(current) != cancel.sender_agent)
		return -EACCES;
	spin_lock_irqsave(&session->queue_lock, flags);
	channel = agi_lc_ipc_find(session, cancel.channel_id,
					  cancel.channel_capability);
	if (!channel || channel->closed ||
	    !agi_lc_ipc_endpoint(channel, cancel.sender_agent,
					 cancel.sender_capability, true)) {
		ret = -EACCES;
		goto cancel_unlock;
	}
	for (i = 0; i < channel->count; i++) {
		u32 index = (channel->head + i) % AGI_LC_IPC_QUEUE_MAX;

		if (channel->messages[index].valid &&
		    channel->messages[index].message.message_id == cancel.message_id)
			break;
	}
	if (i == channel->count) {
		ret = -ENOENT;
		goto cancel_unlock;
	}
	agi_lc_ipc_remove_locked(channel, i);
	channel->messages_cancelled++;
	cancel.status = -ECANCELED;
	ret = 0;
cancel_unlock:
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	(void)agi_lc_push_record(session, AGI_LC_EVENT_IPC, cancel.status,
				 cancel.correlation, cancel.message_id);
	wake_up_interruptible(&session->ipc_wait);
	if (copy_to_user((void __user *)arg, &cancel, sizeof(cancel)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_capability_record *
agi_lc_find_capability(struct agi_lc_session *session, u64 grant_id,
			       u64 capability, bool include_revoked)
{
	u32 i;

	for (i = 0; i < AGI_LC_CAPABILITY_RECORDS; i++) {
		struct agi_lc_capability_record *record = &session->capabilities[i];

		if (!record->valid || record->grant.grant_id != grant_id ||
		    record->grant.capability != capability)
			continue;
		if (!include_revoked && record->grant.status != AGI_LC_CAP_STATUS_ACTIVE)
			continue;
		return record;
	}
	return NULL;
}

static int agi_lc_capability_common_validate(struct agi_lc_session *session)
{
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	return 0;
}

static int agi_lc_trusted_authority_validate(struct agi_lc_session *session)
{
	int ret;

	ret = agi_lc_capability_common_validate(session);
	if (ret)
		return ret;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* Model output is data; only a kernel-bound agent may delegate authority. */
	if (!faisal_task_get_agent(current) ||
	    !agi_lc_find_agent(session, faisal_task_get_agent(current)))
		return -EACCES;
	return 0;
}

static int agi_lc_capability_grant(struct agi_lc_session *session,
						   unsigned long arg)
{
	struct agi_lc_capability_grant grant;
	struct agi_lc_capability_record *record = NULL;
	struct agi_lc_light_agent_record *agent;
	u64 token;
	u64 sequence = 0;
	u32 i;
	int ret;

	if (copy_from_user(&grant, (void __user *)arg, sizeof(grant)))
		return -EFAULT;
	if (grant.size != sizeof(grant) || grant.flags || grant.grant_id ||
	    !grant.agent_id || !grant.agent_capability || grant.capability ||
	    !grant.rights || (grant.rights & ~AGI_LC_CAP_RIGHTS_ALL) ||
	    (grant.sandbox_flags & ~AGI_LC_CAP_SANDBOX_ALL) ||
	    grant.enforced_sandbox_flags || grant.status || grant.reserved32 ||
	    grant.generation || grant.created_at_ns || grant.revoked_at_ns ||
	    grant.last_check_sequence || !grant.correlation || grant.reserved[0] ||
	    grant.reserved[1])
		return -EINVAL;
	ret = agi_lc_trusted_authority_validate(session);
	if (ret)
		return ret;
	agent = agi_lc_find_light_agent(session, grant.agent_id,
					grant.agent_capability);
	if (!agent)
		return -EACCES;
	for (i = 0; i < AGI_LC_CAPABILITY_RECORDS; i++)
		if (!session->capabilities[i].valid ||
		    session->capabilities[i].grant.status != AGI_LC_CAP_STATUS_ACTIVE) {
			record = &session->capabilities[i];
			break;
		}
	if (!record)
		return -ENOSPC;
	token = get_random_u64();
	while (!token)
		token = get_random_u64();
	memset(record, 0, sizeof(*record));
	record->valid = true;
	record->grant = grant;
	record->grant.grant_id = ++session->capability_next_id;
	if (!record->grant.grant_id)
		record->grant.grant_id = ++session->capability_next_id;
	record->grant.capability = token;
	record->grant.status = AGI_LC_CAP_STATUS_ACTIVE;
	record->grant.generation = 1;
	record->grant.created_at_ns = ktime_get_ns();
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_SECURITY_CAPABILITY, 0,
					grant.correlation, record->grant.grant_id,
					&sequence);
	if (ret && ret != -EAGAIN) {
		record->valid = false;
		return ret;
	}
	if (copy_to_user((void __user *)arg, &record->grant,
			 sizeof(record->grant)))
		return -EFAULT;
	return 0;
}

static int agi_lc_capability_revoke(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_capability_grant revoke;
	struct agi_lc_capability_record *record;
	int ret;

	if (copy_from_user(&revoke, (void __user *)arg, sizeof(revoke)))
		return -EFAULT;
	if (revoke.size != sizeof(revoke) || revoke.flags || !revoke.grant_id ||
	    !revoke.capability || revoke.agent_id || revoke.agent_capability ||
	    revoke.rights || revoke.sandbox_flags || revoke.enforced_sandbox_flags ||
	    revoke.status || revoke.reserved32 || revoke.generation ||
	    revoke.created_at_ns || revoke.revoked_at_ns || revoke.last_check_sequence ||
	    !revoke.correlation || revoke.reserved[0] || revoke.reserved[1])
		return -EINVAL;
	ret = agi_lc_trusted_authority_validate(session);
	if (ret)
		return ret;
	record = agi_lc_find_capability(session, revoke.grant_id,
					 revoke.capability, false);
	if (!record)
		return -EACCES;
	record->grant.status = AGI_LC_CAP_STATUS_REVOKED;
	record->grant.generation++;
	record->grant.revoked_at_ns = ktime_get_ns();
	ret = agi_lc_push_record(session, AGI_LC_EVENT_SECURITY_CAPABILITY, 0,
				 revoke.correlation, revoke.grant_id);
	if (ret)
		return ret;
	return 0;
}

static int agi_lc_capability_get(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_capability_grant query;
	struct agi_lc_capability_record *record;
	int ret;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || !query.grant_id ||
	    !query.capability || query.agent_id || query.agent_capability ||
	    query.rights || query.sandbox_flags || query.enforced_sandbox_flags ||
	    query.status || query.reserved32 || query.generation ||
	    query.created_at_ns || query.revoked_at_ns || query.last_check_sequence ||
	    query.correlation || query.reserved[0] || query.reserved[1])
		return -EINVAL;
	ret = agi_lc_trusted_authority_validate(session);
	if (ret)
		return ret;
	record = agi_lc_find_capability(session, query.grant_id,
					 query.capability, true);
	if (!record)
		return -EACCES;
	query = record->grant;
	if (copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return 0;
}

static int agi_lc_capability_check(struct agi_lc_session *session,
					   unsigned long arg)
{
	struct agi_lc_capability_check check;
	struct agi_lc_capability_record *record;
	struct agi_lc_light_agent_record *agent;
	u64 sequence = 0;
	bool allowed;
	int ret;

	if (copy_from_user(&check, (void __user *)arg, sizeof(check)))
		return -EFAULT;
	if (check.size != sizeof(check) || check.flags || !check.grant_id ||
	    !check.capability || !check.agent_id || !check.agent_capability ||
	    !check.requested_rights ||
	    (check.requested_rights & ~AGI_LC_CAP_RIGHTS_ALL) ||
	    check.allowed_rights || check.sandbox_flags || check.status ||
	    check.audit_sequence || !check.correlation || check.reserved[0] ||
	    check.reserved[1])
		return -EINVAL;
	ret = agi_lc_capability_common_validate(session);
	if (ret)
		return ret;
	agent = agi_lc_find_light_agent(session, check.agent_id,
					check.agent_capability);
	record = agi_lc_find_capability(session, check.grant_id,
					check.capability, false);
	allowed = agent && record && record->grant.agent_id == check.agent_id &&
			record->grant.agent_capability == check.agent_capability &&
			(check.requested_rights & ~record->grant.rights) == 0;
	check.allowed_rights = allowed ?
		check.requested_rights & record->grant.rights : 0;
	check.status = allowed ? AGI_LC_CAP_STATUS_ACTIVE : AGI_LC_CAP_STATUS_DENIED;
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_SECURITY_CAPABILITY,
					allowed ? 0 : -EACCES, check.correlation,
					check.grant_id, &sequence);
	if (ret == -ESHUTDOWN)
		return ret;
	check.audit_sequence = sequence;
	if (record && allowed)
		record->grant.last_check_sequence = sequence;
	if (copy_to_user((void __user *)arg, &check, sizeof(check)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_browser_record *
agi_lc_browser_find(struct agi_lc_session *session, u64 browser_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_BROWSER_SESSIONS_LOCAL; i++)
		if (session->browser_records[i].valid &&
		    session->browser_records[i].browser.session_id == browser_id)
			return &session->browser_records[i];
	return NULL;
}

static bool agi_lc_browser_authorized(struct agi_lc_session *session,
					 const struct agi_lc_browser_session *browser,
					 u32 required_rights)
{
	struct agi_lc_capability_record *record;
	u64 agent_id;

	if (agi_lc_capability_common_validate(session))
		return false;
	if (!browser->authority_grant_id || !browser->authority_capability ||
	    !browser->authority_agent_capability)
		return false;
	agent_id = faisal_task_get_agent(current);
	record = agi_lc_find_capability(session, browser->authority_grant_id,
					browser->authority_capability, false);
	return record && record->grant.agent_id == agent_id &&
		record->grant.agent_capability == browser->authority_agent_capability &&
		(required_rights & ~record->grant.rights) == 0;
}

static u32 agi_lc_browser_required_rights(u32 kind)
{
	switch (kind) {
	case AGI_LC_BROWSER_KIND_NAVIGATE:
		return AGI_LC_CAP_BROWSER_CONTROL | AGI_LC_CAP_NET_CONNECT;
	case AGI_LC_BROWSER_KIND_DOWNLOAD:
		return AGI_LC_CAP_BROWSER_CONTROL | AGI_LC_CAP_FS_READ;
	case AGI_LC_BROWSER_KIND_UPLOAD:
		return AGI_LC_CAP_BROWSER_CONTROL | AGI_LC_CAP_FS_WRITE;
	default:
		return AGI_LC_CAP_BROWSER_CONTROL;
	}
}

static void agi_lc_browser_refresh(struct agi_lc_browser_record *record)
{
	struct agi_lc_browser_session *browser = &record->browser;
	u64 now = ktime_get_boottime_ns();

	if (browser->state == AGI_LC_BROWSER_STATE_OPEN &&
	    browser->deadline_ns && now >= browser->deadline_ns) {
		browser->state = AGI_LC_BROWSER_STATE_CANCELLED;
		browser->status = -ETIMEDOUT;
		browser->finished_realtime_ns = ktime_get_real_ns();
		browser->finished_boottime_ns = now;
		browser->generation++;
	}
}

static int agi_lc_browser_control(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_browser_session browser;
	struct agi_lc_browser_record *record = NULL;
	u64 now_real, now_boot, sequence = 0;
	u64 browser_id;
	u32 i;
	int ret = 0;

	if (copy_from_user(&browser, (void __user *)arg, sizeof(browser)))
		return -EFAULT;
	if (browser.size != sizeof(browser) ||
	    browser.operation < AGI_LC_BROWSER_OPEN ||
	    browser.operation > AGI_LC_BROWSER_CANCEL ||
	    browser.flags || browser.reserved32 || browser.reserved[0] ||
	    browser.reserved[1] || browser.status || browser.state ||
	    browser.action_count || browser.semantic_count ||
	    browser.coordinate_fallback_count || browser.download_count ||
	    browser.upload_count || browser.navigation_count || browser.dom_count ||
	    browser.screenshot_count || browser.page_state_count ||
	    browser.started_realtime_ns || browser.started_boottime_ns ||
	    browser.finished_realtime_ns || browser.finished_boottime_ns ||
	    browser.generation || browser.last_event_sequence || browser.target_pid ||
	    browser.target_tgid || browser.agent_id || browser.lineage_id ||
	    browser.creator_pid || browser.creator_tgid)
		return -EINVAL;
	if (browser.interaction_kind > AGI_LC_BROWSER_KIND_MAX ||
	    browser.interaction_flags & ~(AGI_LC_BROWSER_FLAG_SEMANTIC |
					  AGI_LC_BROWSER_FLAG_COORDINATE_FALLBACK |
					  AGI_LC_BROWSER_FLAG_USER_CONFIRMATION |
					  AGI_LC_BROWSER_FLAG_VERIFIED))
		return -EINVAL;
	if (browser.interaction_kind && !browser.interaction_flags)
		return -EINVAL;
	if (agi_lc_capability_common_validate(session))
		return -EPERM;

	now_real = ktime_get_real_ns();
	now_boot = ktime_get_boottime_ns();
	if (browser.deadline_ns && browser.deadline_ns <= now_boot &&
	    browser.operation == AGI_LC_BROWSER_OPEN)
		return -EINVAL;

	if (browser.operation == AGI_LC_BROWSER_OPEN) {
		if (browser.session_id || browser.action_id || !browser.authority_grant_id ||
		    !browser.authority_capability || !browser.authority_agent_capability ||
		    !agi_lc_browser_authorized(session, &browser,
			AGI_LC_CAP_BROWSER_CONTROL))
			return -EACCES;
		for (i = 0; i < AGI_LC_BROWSER_SESSIONS_LOCAL; i++)
			if (!session->browser_records[i].valid)
				break;
		if (i == AGI_LC_BROWSER_SESSIONS_LOCAL ||
		    session->browser_next_id == U64_MAX)
			return -ENOSPC;
		record = &session->browser_records[i];
		memset(record, 0, sizeof(*record));
		record->valid = true;
		browser_id = ++session->browser_next_id;
		record->browser = browser;
		record->browser.session_id = browser_id;
		record->browser.state = AGI_LC_BROWSER_STATE_OPEN;
		record->browser.started_realtime_ns = now_real;
		record->browser.started_boottime_ns = now_boot;
		record->browser.generation = 1;
		record->browser.target_pid = task_pid_nr(current);
		record->browser.target_tgid = task_tgid_nr(current);
		record->browser.agent_id = faisal_task_get_agent(current);
		record->browser.lineage_id = faisal_task_get_lineage(current);
		record->browser.creator_pid = task_pid_nr(current);
		record->browser.creator_tgid = task_tgid_nr(current);
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_BROWSER, 0,
					browser.correlation, browser_id, &sequence);
		record->browser.last_event_sequence = sequence;
		browser = record->browser;
		goto out_copy;
	}

	if (!browser.session_id || !agi_lc_browser_authorized(session, &browser,
				AGI_LC_CAP_BROWSER_CONTROL))
		return -EACCES;
	record = agi_lc_browser_find(session, browser.session_id);
	if (!record)
		return -ENOENT;
	if (record->browser.authority_grant_id != browser.authority_grant_id ||
	    record->browser.authority_capability != browser.authority_capability ||
	    record->browser.authority_agent_capability != browser.authority_agent_capability)
		return -EACCES;
	agi_lc_browser_refresh(record);

	switch (browser.operation) {
	case AGI_LC_BROWSER_RECORD:
		if (record->browser.state != AGI_LC_BROWSER_STATE_OPEN ||
		    !browser.interaction_kind || browser.action_id ||
		    browser.deadline_ns || !agi_lc_browser_authorized(session, &browser,
			agi_lc_browser_required_rights(browser.interaction_kind)))
			return record->browser.state == AGI_LC_BROWSER_STATE_CANCELLED ?
				-ECANCELED : -EACCES;
		if (record->browser.action_count >= AGI_LC_BROWSER_MAX_ACTIONS)
			return -EOVERFLOW;
		record->browser.action_count++;
		record->browser.generation++;
		record->browser.interaction_kind = browser.interaction_kind;
		record->browser.interaction_flags = browser.interaction_flags;
		record->browser.page_id = browser.page_id;
		record->browser.locator_hash = browser.locator_hash;
		record->browser.input_hash = browser.input_hash;
		record->browser.observation_hash = browser.observation_hash;
		record->browser.result_hash = browser.result_hash;
		record->browser.artifact_id = browser.artifact_id;
		record->browser.started_realtime_ns = ktime_get_real_ns();
		record->browser.started_boottime_ns = ktime_get_boottime_ns();
		record->browser.finished_realtime_ns = record->browser.started_realtime_ns;
		record->browser.finished_boottime_ns = record->browser.started_boottime_ns;
		if (browser.interaction_flags & AGI_LC_BROWSER_FLAG_SEMANTIC)
			record->browser.semantic_count++;
		if (browser.interaction_flags & AGI_LC_BROWSER_FLAG_COORDINATE_FALLBACK)
			record->browser.coordinate_fallback_count++;
		switch (browser.interaction_kind) {
		case AGI_LC_BROWSER_KIND_DOWNLOAD:
			record->browser.download_count++;
			break;
		case AGI_LC_BROWSER_KIND_UPLOAD:
			record->browser.upload_count++;
			break;
		case AGI_LC_BROWSER_KIND_NAVIGATE:
			record->browser.navigation_count++;
			break;
		case AGI_LC_BROWSER_KIND_DOM:
		case AGI_LC_BROWSER_KIND_ACCESSIBILITY:
			record->browser.dom_count++;
			break;
		case AGI_LC_BROWSER_KIND_SCREENSHOT:
			record->browser.screenshot_count++;
			break;
		case AGI_LC_BROWSER_KIND_PAGE_STATE:
			record->browser.page_state_count++;
			break;
		default:
			break;
		}
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_BROWSER, 0,
					browser.correlation, record->browser.action_count,
					&sequence);
		record->browser.last_event_sequence = sequence;
		browser = record->browser;
		browser.action_id = record->browser.action_count;
		break;
	case AGI_LC_BROWSER_QUERY:
		browser = record->browser;
		break;
	case AGI_LC_BROWSER_CLOSE:
		if (record->browser.state != AGI_LC_BROWSER_STATE_OPEN)
			return -EALREADY;
		record->browser.state = AGI_LC_BROWSER_STATE_COMPLETED;
		record->browser.finished_realtime_ns = now_real;
		record->browser.finished_boottime_ns = now_boot;
		record->browser.generation++;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_BROWSER, 0,
					browser.correlation, record->browser.session_id,
					&sequence);
		record->browser.last_event_sequence = sequence;
		browser = record->browser;
		break;
	case AGI_LC_BROWSER_CANCEL:
		if (record->browser.state != AGI_LC_BROWSER_STATE_OPEN)
			return -EALREADY;
		record->browser.state = AGI_LC_BROWSER_STATE_CANCELLED;
		record->browser.status = -ECANCELED;
		record->browser.finished_realtime_ns = now_real;
		record->browser.finished_boottime_ns = now_boot;
		record->browser.generation++;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_BROWSER, -ECANCELED,
					browser.correlation, record->browser.session_id,
					&sequence);
		record->browser.last_event_sequence = sequence;
		browser = record->browser;
		break;
	default:
		return -EINVAL;
	}

out_copy:
	if (copy_to_user((void __user *)arg, &browser, sizeof(browser)))
		return -EFAULT;
	return ret;
}

static struct agi_lc_knowledge_record *
agi_lc_knowledge_find(struct agi_lc_session *session, u64 record_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_KNOWLEDGE_RECORDS_LOCAL; i++)
		if (session->knowledge_records[i].valid &&
		    session->knowledge_records[i].knowledge.record_id == record_id)
			return &session->knowledge_records[i];
	return NULL;
}

static void agi_lc_knowledge_refresh(struct agi_lc_knowledge_record *record)
{
	struct agi_lc_verified_knowledge *knowledge = &record->knowledge;
	u64 now = ktime_get_boottime_ns();

	if (!knowledge->freshness_ttl_ns) {
		knowledge->freshness_state = AGI_LC_KNOWLEDGE_FRESHNESS_UNKNOWN;
		return;
	}
	if (now >= knowledge->retrieval_boottime_ns + knowledge->freshness_ttl_ns) {
		knowledge->freshness_state = AGI_LC_KNOWLEDGE_EXPIRED;
		if (knowledge->verification_state == AGI_LC_KNOWLEDGE_VERIFY_VERIFIED)
			knowledge->verification_state = AGI_LC_KNOWLEDGE_VERIFY_STALE;
	} else {
		knowledge->freshness_state = AGI_LC_KNOWLEDGE_FRESH;
	}
}

static int agi_lc_knowledge_control(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_verified_knowledge knowledge;
	struct agi_lc_knowledge_record *record = NULL;
	struct agi_lc_knowledge_record *related = NULL;
	u64 now_real, now_boot, sequence = 0;
	u32 i;
	int ret = 0;

	if (copy_from_user(&knowledge, (void __user *)arg, sizeof(knowledge)))
		return -EFAULT;
	if (knowledge.size != sizeof(knowledge) ||
	    knowledge.operation < AGI_LC_KNOWLEDGE_PUBLISH ||
	    knowledge.operation > AGI_LC_KNOWLEDGE_VALIDATE ||
	    knowledge.flags & ~(AGI_LC_KNOWLEDGE_FLAG_PRIMARY |
				AGI_LC_KNOWLEDGE_FLAG_SECONDARY |
				AGI_LC_KNOWLEDGE_FLAG_SIGNED |
				AGI_LC_KNOWLEDGE_FLAG_INTEGRITY_MEASURED |
				AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED) ||
	    knowledge.source_kind > AGI_LC_KNOWLEDGE_SOURCE_SECONDARY ||
	    knowledge.source_rank > AGI_LC_KNOWLEDGE_CONFIDENCE_MAX ||
	    knowledge.confidence_ppm > AGI_LC_KNOWLEDGE_CONFIDENCE_MAX ||
	    knowledge.freshness_ttl_ns > AGI_LC_KNOWLEDGE_MAX_TTL_NS ||
	    knowledge.reserved[0] || knowledge.reserved[1] ||
	    !session->session_id || READ_ONCE(session->revoked))
		return -EINVAL;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	now_real = ktime_get_real_ns();
	now_boot = ktime_get_boottime_ns();
	if (knowledge.publication_realtime_ns > now_real)
		return -EINVAL;

	switch (knowledge.operation) {
	case AGI_LC_KNOWLEDGE_PUBLISH:
		if (knowledge.record_id || knowledge.related_record_id ||
		    !knowledge.source_id || !knowledge.source_uri_hash ||
		    !knowledge.confidence_ppm ||
		    knowledge.status || knowledge.verification_state ||
		    knowledge.conflict_state || knowledge.freshness_state ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.evidence_sequence ||
		    knowledge.parent_record_id || knowledge.generation ||
		    knowledge.session_id || knowledge.lineage_id || knowledge.agent_id ||
		    knowledge.task_id || knowledge.tgid || knowledge.creator_pid ||
		    knowledge.creator_tgid || knowledge.creator_uid || knowledge.creator_euid ||
		    !memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    !memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		break;
	case AGI_LC_KNOWLEDGE_QUERY:
		if (!knowledge.record_id || knowledge.related_record_id ||
		    knowledge.source_id || knowledge.source_uri_hash ||
		    knowledge.source_rank || knowledge.source_kind ||
		    knowledge.verification_state || knowledge.conflict_state ||
		    knowledge.freshness_state || knowledge.confidence_ppm ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.publication_realtime_ns || knowledge.freshness_ttl_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.evidence_sequence ||
		    knowledge.parent_record_id || knowledge.generation ||
		    knowledge.session_id || knowledge.lineage_id || knowledge.agent_id ||
		    knowledge.task_id || knowledge.tgid || knowledge.creator_pid ||
		    knowledge.creator_tgid || knowledge.creator_uid || knowledge.creator_euid ||
		    memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		record = agi_lc_knowledge_find(session, knowledge.record_id);
		if (!record)
			return -ENOENT;
		agi_lc_knowledge_refresh(record);
		knowledge = record->knowledge;
		goto out_copy;
	case AGI_LC_KNOWLEDGE_CROSSCHECK:
		if (!knowledge.record_id || !knowledge.related_record_id ||
		    knowledge.record_id == knowledge.related_record_id ||
		    knowledge.status || knowledge.flags || knowledge.source_id ||
		    knowledge.source_uri_hash || knowledge.source_rank || knowledge.source_kind ||
		    knowledge.verification_state || knowledge.conflict_state ||
		    knowledge.freshness_state || knowledge.confidence_ppm ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.publication_realtime_ns || knowledge.freshness_ttl_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.evidence_sequence ||
		    knowledge.parent_record_id || knowledge.generation || knowledge.session_id ||
		    knowledge.lineage_id || knowledge.agent_id || knowledge.task_id || knowledge.tgid ||
		    knowledge.creator_pid || knowledge.creator_tgid || knowledge.creator_uid ||
		    knowledge.creator_euid ||
		    memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		record = agi_lc_knowledge_find(session, knowledge.record_id);
		related = agi_lc_knowledge_find(session, knowledge.related_record_id);
		if (!record || !related)
			return -ENOENT;
		if (record->knowledge.source_id == related->knowledge.source_id)
			return -EINVAL;
		agi_lc_knowledge_refresh(record);
		agi_lc_knowledge_refresh(related);
		record->knowledge.crosscheck_count++;
		related->knowledge.crosscheck_count++;
		if (memcmp(record->knowledge.content_digest,
			   related->knowledge.content_digest, AGI_LC_DIGEST_SIZE)) {
			record->knowledge.conflict_state = AGI_LC_KNOWLEDGE_CONFLICT_DETECTED;
			related->knowledge.conflict_state = AGI_LC_KNOWLEDGE_CONFLICT_DETECTED;
			record->knowledge.verification_state = AGI_LC_KNOWLEDGE_VERIFY_CONFLICT;
			related->knowledge.verification_state = AGI_LC_KNOWLEDGE_VERIFY_CONFLICT;
			record->knowledge.conflict_count++;
			related->knowledge.conflict_count++;
		} else if (record->knowledge.conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED ||
			   related->knowledge.conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED) {
			record->knowledge.conflict_state = AGI_LC_KNOWLEDGE_CONFLICT_RESOLVED;
			related->knowledge.conflict_state = AGI_LC_KNOWLEDGE_CONFLICT_RESOLVED;
		}
		now_real = ktime_get_real_ns();
		record->knowledge.checked_realtime_ns = now_real;
		related->knowledge.checked_realtime_ns = now_real;
		record->knowledge.generation++;
		related->knowledge.generation++;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_KNOWLEDGE,
					memcmp(record->knowledge.content_digest,
					       related->knowledge.content_digest,
					       AGI_LC_DIGEST_SIZE) ? -EUCLEAN : 0,
					knowledge.correlation, record->knowledge.record_id,
					&sequence);
		record->knowledge.evidence_sequence = sequence;
		related->knowledge.evidence_sequence = sequence;
		knowledge = record->knowledge;
		knowledge.related_record_id = related->knowledge.record_id;
		goto out_copy;
	case AGI_LC_KNOWLEDGE_VERIFY:
		if (!knowledge.record_id ||
		    (knowledge.verification_state != AGI_LC_KNOWLEDGE_VERIFY_VERIFIED &&
		     knowledge.verification_state != AGI_LC_KNOWLEDGE_VERIFY_REJECTED) ||
		    !memchr_inv(knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    knowledge.related_record_id || knowledge.source_id ||
		    knowledge.source_uri_hash || knowledge.source_rank || knowledge.source_kind ||
		    knowledge.conflict_state || knowledge.freshness_state || knowledge.confidence_ppm ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.publication_realtime_ns || knowledge.freshness_ttl_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.parent_record_id || knowledge.generation ||
		    knowledge.session_id || knowledge.lineage_id || knowledge.agent_id ||
		    knowledge.task_id || knowledge.tgid || knowledge.creator_pid || knowledge.creator_tgid ||
		    knowledge.creator_uid || knowledge.creator_euid ||
		    memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		record = agi_lc_knowledge_find(session, knowledge.record_id);
		if (!record)
			return -ENOENT;
		agi_lc_knowledge_refresh(record);
		if (knowledge.verification_state == AGI_LC_KNOWLEDGE_VERIFY_VERIFIED &&
		    (record->knowledge.conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED ||
		     record->knowledge.freshness_state == AGI_LC_KNOWLEDGE_EXPIRED))
			return -EAGAIN;
		record->knowledge.verification_state = knowledge.verification_state;
		record->knowledge.evidence_digest[0] = knowledge.evidence_digest[0];
		memcpy(record->knowledge.evidence_digest, knowledge.evidence_digest,
		       AGI_LC_DIGEST_SIZE);
		record->knowledge.checked_realtime_ns = now_real;
		record->knowledge.generation++;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_KNOWLEDGE,
					knowledge.verification_state == AGI_LC_KNOWLEDGE_VERIFY_VERIFIED ? 0 : -EACCES,
					knowledge.correlation, record->knowledge.record_id,
					&sequence);
		record->knowledge.evidence_sequence = sequence;
		knowledge = record->knowledge;
		goto out_copy;
	case AGI_LC_KNOWLEDGE_VALIDATE:
		/*
		 * Precision gate: this is an observation-validity query only.
		 * It never authorizes an action and never treats model output as
		 * evidence.  The caller supplies a minimum confidence threshold
		 * and may require freshness; the kernel checks its own journaled
		 * verification, conflict, digest, and monotonic freshness state.
		 */
		if (!knowledge.record_id ||
		    (knowledge.flags & ~(AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED)) ||
		    knowledge.source_id || knowledge.source_uri_hash || knowledge.source_rank ||
		    knowledge.source_kind || knowledge.verification_state ||
		    knowledge.conflict_state || knowledge.freshness_state ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.publication_realtime_ns || knowledge.freshness_ttl_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.evidence_sequence ||
		    knowledge.parent_record_id || knowledge.generation || knowledge.session_id ||
		    knowledge.lineage_id || knowledge.agent_id || knowledge.task_id ||
		    knowledge.tgid || knowledge.creator_pid || knowledge.creator_tgid ||
		    knowledge.creator_uid || knowledge.creator_euid ||
		    memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    memchr_inv(knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		record = agi_lc_knowledge_find(session, knowledge.record_id);
		if (!record)
			return -ENOENT;
		agi_lc_knowledge_refresh(record);
		ret = 0;
		if (record->knowledge.verification_state != AGI_LC_KNOWLEDGE_VERIFY_VERIFIED ||
		    record->knowledge.conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED ||
		    !memchr_inv(record->knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    !memchr_inv(record->knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    record->knowledge.confidence_ppm < knowledge.confidence_ppm)
			ret = -EACCES;
		else if ((knowledge.flags & AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED) &&
			 record->knowledge.freshness_state != AGI_LC_KNOWLEDGE_FRESH)
			ret = -EAGAIN;
		knowledge = record->knowledge;
		knowledge.operation = AGI_LC_KNOWLEDGE_VALIDATE;
		knowledge.status = ret;
		goto out_copy;
	case AGI_LC_KNOWLEDGE_UPDATE:
		if (!knowledge.record_id || !knowledge.source_id || !knowledge.source_uri_hash ||
		    !knowledge.confidence_ppm || !memchr_inv(knowledge.source_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    !memchr_inv(knowledge.content_digest, 0, AGI_LC_DIGEST_SIZE) ||
		    knowledge.related_record_id || knowledge.verification_state ||
		    knowledge.conflict_state || knowledge.freshness_state ||
		    knowledge.retrieval_realtime_ns || knowledge.retrieval_boottime_ns ||
		    knowledge.expires_realtime_ns || knowledge.checked_realtime_ns ||
		    knowledge.crosscheck_count || knowledge.conflict_count ||
		    knowledge.provenance_sequence || knowledge.evidence_sequence ||
		    knowledge.parent_record_id || knowledge.generation || knowledge.session_id ||
		    knowledge.lineage_id || knowledge.agent_id || knowledge.task_id || knowledge.tgid ||
		    knowledge.creator_pid || knowledge.creator_tgid || knowledge.creator_uid || knowledge.creator_euid ||
		    memchr_inv(knowledge.evidence_digest, 0, AGI_LC_DIGEST_SIZE))
			return -EINVAL;
		record = agi_lc_knowledge_find(session, knowledge.record_id);
		if (!record)
			return -ENOENT;
		record->knowledge.flags = knowledge.flags;
		record->knowledge.source_id = knowledge.source_id;
		record->knowledge.source_uri_hash = knowledge.source_uri_hash;
		record->knowledge.source_rank = knowledge.source_rank;
		record->knowledge.source_kind = knowledge.source_kind;
		record->knowledge.confidence_ppm = knowledge.confidence_ppm;
		record->knowledge.publication_realtime_ns = knowledge.publication_realtime_ns;
		record->knowledge.freshness_ttl_ns = knowledge.freshness_ttl_ns;
		memcpy(record->knowledge.source_digest, knowledge.source_digest,
		       AGI_LC_DIGEST_SIZE);
		memcpy(record->knowledge.content_digest, knowledge.content_digest,
		       AGI_LC_DIGEST_SIZE);
		record->knowledge.retrieval_realtime_ns = now_real;
		record->knowledge.retrieval_boottime_ns = now_boot;
		record->knowledge.expires_realtime_ns = knowledge.freshness_ttl_ns &&
			(now_real <= U64_MAX - knowledge.freshness_ttl_ns) ?
			now_real + knowledge.freshness_ttl_ns : U64_MAX;
		record->knowledge.verification_state = AGI_LC_KNOWLEDGE_VERIFY_UNVERIFIED;
		record->knowledge.conflict_state = AGI_LC_KNOWLEDGE_CONFLICT_NONE;
		record->knowledge.generation++;
		agi_lc_knowledge_refresh(record);
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_KNOWLEDGE, 0,
					knowledge.correlation, record->knowledge.record_id,
					&sequence);
		record->knowledge.evidence_sequence = sequence;
		knowledge = record->knowledge;
		goto out_copy;
	default:
		return -EINVAL;
	}

	for (i = 0; i < AGI_LC_KNOWLEDGE_RECORDS_LOCAL; i++)
		if (!session->knowledge_records[i].valid)
			break;
	if (i == AGI_LC_KNOWLEDGE_RECORDS_LOCAL ||
	    session->knowledge_next_id == U64_MAX)
		return -ENOSPC;
	record = &session->knowledge_records[i];
	memset(record, 0, sizeof(*record));
	record->valid = true;
	record->knowledge = knowledge;
	record->knowledge.record_id = ++session->knowledge_next_id;
	record->knowledge.status = 0;
	record->knowledge.retrieval_realtime_ns = now_real;
	record->knowledge.retrieval_boottime_ns = now_boot;
	record->knowledge.expires_realtime_ns = knowledge.freshness_ttl_ns &&
		(now_real <= U64_MAX - knowledge.freshness_ttl_ns) ?
		now_real + knowledge.freshness_ttl_ns : U64_MAX;
	record->knowledge.freshness_state = knowledge.freshness_ttl_ns ?
		AGI_LC_KNOWLEDGE_FRESH : AGI_LC_KNOWLEDGE_FRESHNESS_UNKNOWN;
	record->knowledge.session_id = session->session_id;
	record->knowledge.lineage_id = faisal_task_get_lineage(current);
	record->knowledge.agent_id = faisal_task_get_agent(current);
	record->knowledge.task_id = task_pid_nr(current);
	record->knowledge.tgid = task_tgid_nr(current);
	record->knowledge.creator_pid = task_pid_nr(current);
	record->knowledge.creator_tgid = task_tgid_nr(current);
	record->knowledge.creator_uid = from_kuid_munged(current_user_ns(), current_uid());
	record->knowledge.creator_euid = from_kuid_munged(current_user_ns(), current_euid());
	record->knowledge.generation = 1;
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_KNOWLEDGE, 0,
				knowledge.correlation, record->knowledge.record_id,
				&sequence);
	if (ret && ret != -EAGAIN) {
		record->valid = false;
		return ret;
	}
	record->knowledge.provenance_sequence = sequence;
	record->knowledge.evidence_sequence = sequence;
	knowledge = record->knowledge;
out_copy:
	if (copy_to_user((void __user *)arg, &knowledge, sizeof(knowledge)))
		return -EFAULT;
	return ret;
}

static struct agi_lc_network_policy_record *
agi_lc_network_policy_find(struct agi_lc_session *session, u64 policy_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_NET_POLICY_RECORDS; i++)
		if (session->network_policies[i].valid &&
		    session->network_policies[i].policy.policy_id == policy_id)
			return &session->network_policies[i];
	return NULL;
}

static bool agi_lc_network_policy_authorized(
		struct agi_lc_session *session,
		const struct agi_lc_network_policy *policy,
		struct task_struct *target)
{
	struct agi_lc_capability_record *record;
	u64 agent_id = faisal_task_get_agent(current);

	if (target == current || capable(CAP_SYS_ADMIN))
		return true;
	if (!policy->authority_grant_id || !policy->authority_capability ||
	    !policy->authority_agent_capability)
		return false;
	record = agi_lc_find_capability(session, policy->authority_grant_id,
					policy->authority_capability, false);
	return record && record->grant.agent_id == agent_id &&
		record->grant.agent_capability == policy->authority_agent_capability &&
		(record->grant.rights & AGI_LC_CAP_PROCESS_CONTROL);
}

static void agi_lc_network_policy_refresh(
		struct agi_lc_network_policy_record *record,
		struct task_struct *target)
{
	struct agi_lc_network_policy *policy = &record->policy;
	u64 active_policy_id;

	faisal_task_net_policy_get(target, &active_policy_id,
					   &policy->family_mask, &policy->type_mask,
					   &policy->operation_mask, &policy->policy_flags,
					   &policy->max_sockets, &policy->max_tx_bytes,
					   &policy->max_rx_bytes, &policy->socket_count,
					   &policy->tx_bytes, &policy->rx_bytes,
					   &policy->socket_creates, &policy->denied,
					   &policy->generation);
	policy->state = active_policy_id ? AGI_LC_NET_POLICY_STATE_ACTIVE :
			AGI_LC_NET_POLICY_STATE_REVOKED;
}

static int agi_lc_network_policy_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_network_policy policy;
	struct agi_lc_network_policy_record *record = NULL;
	struct task_struct *target = NULL;
	struct pid *pid = NULL;
	u64 sequence = 0;
	u32 i;
	int ret = 0;

	if (copy_from_user(&policy, (void __user *)arg, sizeof(policy)))
		return -EFAULT;
	if (policy.size != sizeof(policy) ||
	    !policy.flags || (policy.flags & ~(AGI_LC_NET_POLICY_APPLY |
					AGI_LC_NET_POLICY_QUERY |
					AGI_LC_NET_POLICY_REVOKE)) ||
	    (policy.flags & (policy.flags - 1)) || policy.reserved[0] ||
	    policy.reserved[1] || !session->session_id ||
	    READ_ONCE(session->revoked) ||
	    faisal_task_get_lineage(current) != session->session_id)
		return -EINVAL;

	if (policy.flags == AGI_LC_NET_POLICY_APPLY) {
		if (policy.policy_id || !policy.family_mask || !policy.type_mask ||
		    !policy.operation_mask ||
		    (policy.policy_flags & ~((1U << 4) - 1)) ||
		    policy.max_sockets > AGI_LC_NET_POLICY_MAX_SOCKETS ||
		    policy.state || policy.status || policy.generation ||
		    policy.socket_count || policy.tx_bytes || policy.rx_bytes ||
		    policy.socket_creates || policy.denied || policy.audit_sequence)
			return -EINVAL;
	} else if (!policy.policy_id || policy.target_pid < 0 ||
	   policy.family_mask || policy.type_mask || policy.operation_mask ||
	   policy.policy_flags || policy.max_sockets || policy.max_tx_bytes ||
	   policy.max_rx_bytes || policy.socket_count || policy.tx_bytes ||
	   policy.rx_bytes || policy.socket_creates || policy.denied ||
	   policy.audit_sequence)
		return -EINVAL;

	if (policy.target_pid <= 0)
		policy.target_pid = task_pid_nr(current);
	pid = find_get_pid(policy.target_pid);
	if (pid)
		target = get_pid_task(pid, PIDTYPE_PID);
	if (pid)
		put_pid(pid);

	if (policy.flags == AGI_LC_NET_POLICY_APPLY) {
		if (!target)
			return -ESRCH;
		if (faisal_task_get_lineage(target) != session->session_id ||
		    (policy.target_tgid &&
		     policy.target_tgid != task_tgid_nr(target)) ||
		    (policy.target_agent &&
		     policy.target_agent != faisal_task_get_agent(target)) ||
		    !agi_lc_network_policy_authorized(session, &policy, target)) {
			ret = -EPERM;
			goto out;
		}
		for (i = 0; i < AGI_LC_NET_POLICY_RECORDS; i++)
			if (!session->network_policies[i].valid)
				break;
		if (i == AGI_LC_NET_POLICY_RECORDS) {
			ret = -ENOSPC;
			goto out;
		}
		if (++session->network_policy_next_id == U64_MAX) {
			ret = -EOVERFLOW;
			goto out;
		}
		record = &session->network_policies[i];
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->policy = policy;
		record->policy.policy_id = session->network_policy_next_id;
		record->policy.target_tgid = task_tgid_nr(target);
		record->policy.target_agent = faisal_task_get_agent(target);
		record->policy.state = AGI_LC_NET_POLICY_STATE_ACTIVE;
		ret = faisal_task_net_policy_apply(target, record->policy.policy_id,
						  policy.family_mask, policy.type_mask,
						  policy.operation_mask,
						  policy.policy_flags,
						  policy.max_sockets,
						  policy.max_tx_bytes,
						  policy.max_rx_bytes);
		if (ret)
			goto out_record;
		agi_lc_network_policy_refresh(record, target);
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_NETWORK_POLICY,
						0, policy.correlation, record->policy.policy_id,
						&sequence);
		record->policy.audit_sequence = sequence;
		record->policy.status = ret;
		policy = record->policy;
		goto out_copy;
	}

	record = agi_lc_network_policy_find(session, policy.policy_id);
	if (!record) {
		ret = -ENOENT;
		goto out;
	}
	if (!target || faisal_task_get_lineage(target) != session->session_id ||
	    !agi_lc_network_policy_authorized(session, &policy, target)) {
		ret = -EPERM;
		goto out;
	}
	agi_lc_network_policy_refresh(record, target);
	if (policy.flags == AGI_LC_NET_POLICY_REVOKE) {
		if (!target || faisal_task_get_lineage(target) != session->session_id ||
		    !agi_lc_network_policy_authorized(session, &policy, target)) {
			ret = -EPERM;
			goto out;
		}
		faisal_task_net_policy_revoke(target);
		agi_lc_network_policy_refresh(record, target);
		record->policy.state = AGI_LC_NET_POLICY_STATE_REVOKED;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_NETWORK_POLICY,
						0, policy.correlation, record->policy.policy_id,
						&sequence);
		record->policy.audit_sequence = sequence;
		record->policy.status = ret;
	}
	policy = record->policy;
	goto out_copy;

out_record:
	record->valid = false;
out:
	if (target)
		put_task_struct(target);
	return ret;
out_copy:
	if (target)
		put_task_struct(target);
	if (copy_to_user((void __user *)arg, &policy, sizeof(policy)))
		return -EFAULT;
	return ret;
}

static struct agi_lc_cancel_record *
agi_lc_cancel_find(struct agi_lc_session *session, u64 request_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_CANCEL_REQUESTS; i++)
		if (session->cancel_requests[i].valid &&
		    session->cancel_requests[i].control.request_id == request_id)
			return &session->cancel_requests[i];
	return NULL;
}

static void agi_lc_cancel_refresh(struct agi_lc_cancel_record *record)
{
	if (record->control.deadline_ns &&
	    ktime_get_ns() >= record->control.deadline_ns &&
	    record->control.state == AGI_LC_CANCEL_STATE_GRACEFUL) {
		record->control.state = AGI_LC_CANCEL_STATE_EXPIRED;
		record->control.generation++;
	}
}

static bool agi_lc_cancel_agent_descendant(struct agi_lc_session *session,
						   u64 candidate, u64 ancestor)
{
	u32 i, depth;
	u64 parent;

	if (!candidate || !ancestor)
		return false;
	if (candidate == ancestor)
		return true;
	for (depth = 0; depth < AGI_LC_AGENT_RECORDS; depth++) {
		parent = 0;
		for (i = 0; i < AGI_LC_AGENT_RECORDS; i++)
			if (session->agents[i].valid &&
			    session->agents[i].agent_id == candidate) {
				parent = session->agents[i].parent_agent;
				break;
			}
		if (!parent && session->light_agents && candidate <= AGI_LC_LIGHT_AGENT_MAX)
			if (session->light_agents[candidate - 1].valid)
				parent = session->light_agents[candidate - 1].parent_agent;
		if (!parent || parent == candidate)
			return false;
		if (parent == ancestor)
			return true;
		candidate = parent;
	}
	return false;
}

static bool agi_lc_cancel_task_matches(struct agi_lc_session *session,
						struct task_struct *task,
						struct task_struct *target,
						const struct agi_lc_cancel_control *control)
{
	struct task_struct *parent;
	struct task_struct *real_parent;

	if (task == target)
		return true;
	if (control->scope == AGI_LC_CANCEL_SCOPE_TASK)
		return false;
	if (faisal_task_get_lineage(task) != session->session_id)
		return false;
	if (control->scope == AGI_LC_CANCEL_SCOPE_LINEAGE)
		return true;
	if (control->scope == AGI_LC_CANCEL_SCOPE_DEPENDENTS) {
		if (control->target_agent &&
		    agi_lc_cancel_agent_descendant(session,
			faisal_task_get_agent(task), control->target_agent))
			return true;
		real_parent = rcu_dereference(task->real_parent);
		return control->dependency_policy == AGI_LC_CANCEL_DEPENDENCY_CHILDREN &&
			(real_parent == target);
	}
	parent = rcu_dereference(task->real_parent);
	while (parent && parent != task) {
		if (parent == target)
			return true;
		if (parent == rcu_dereference(parent->real_parent))
			break;
		parent = rcu_dereference(parent->real_parent);
	}
	return false;
}

static bool agi_lc_cancel_authorized(struct agi_lc_session *session,
					 const struct agi_lc_cancel_control *control,
					 struct task_struct *target)
{
	struct agi_lc_capability_record *record;
	u64 agent_id = faisal_task_get_agent(current);

	if (target == current || capable(CAP_SYS_ADMIN))
		return true;
	if (!control->authority_grant_id || !control->authority_capability ||
	    !control->authority_agent_capability)
		return false;
	record = agi_lc_find_capability(session, control->authority_grant_id,
					control->authority_capability, false);
	return record && record->grant.agent_id == agent_id &&
		record->grant.agent_capability == control->authority_agent_capability &&
		(record->grant.rights & AGI_LC_CAP_PROCESS_CONTROL);
}

static void agi_lc_cancel_revoke_resources(struct agi_lc_session *session,
						struct task_struct *task)
{
	u64 agent_id = faisal_task_get_agent(task);
	u32 i, j;

	faisal_task_revoke_resources(task);
	for (i = 0; i < AGI_LC_LEASE_MAX; i++)
		if (session->leases[i].active &&
		    (session->leases[i].owner_agent == agent_id ||
		     session->leases[i].owner_agent == faisal_task_get_agent(current)))
			session->leases[i].active = false;
	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++)
		if (session->agents[i].valid && session->agents[i].agent_id == agent_id) {
			session->agents[i].resource_demand_valid = false;
			session->agents[i].accel_workload_valid = false;
		}
	if (!session->light_agents)
		goto revoke_memory;
	for (i = 0; i < AGI_LC_LIGHT_AGENT_MAX; i++)
		if (session->light_agents[i].valid &&
		    session->light_agents[i].agent_id == agent_id)
			session->light_agents[i].state = AGI_LC_LIGHT_AGENT_STATE_FAILED;
revoke_memory:
	mutex_lock(&agi_lc_memory_lock);
	for (i = 0; i < AGI_LC_MEMORY_REGIONS; i++) {
		struct agi_lc_memory_record *record = &agi_lc_memory_records[i];

		if (!record->valid || record->session_id != session->session_id ||
		    (record->owner_agent != agent_id &&
		     record->owner_tgid != task_tgid_nr(task)))
			continue;
		record->revoked = true;
		for (j = 0; j < AGI_LC_MEMORY_SHARES; j++)
			record->shares[j].active = false;
	}
	mutex_unlock(&agi_lc_memory_lock);
}

static int agi_lc_cancel_deprioritize(struct task_struct *task, u32 priority)
{
#ifdef CONFIG_UCLAMP_TASK
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = -1,
		.sched_flags = SCHED_FLAG_UTIL_CLAMP_MIN |
				       SCHED_FLAG_UTIL_CLAMP_MAX,
		.sched_util_min = 0,
		.sched_util_max = priority,
	};

	return sched_setattr_nocheck(task, &attr);
#else
	return -EOPNOTSUPP;
#endif
}

static int agi_lc_cancel_apply(struct agi_lc_session *session,
				       struct agi_lc_cancel_record *record,
				       struct task_struct *target)
{
	struct task_struct *targets[AGI_LC_AGENT_RECORDS];
	struct task_struct *group;
	struct task_struct *task;
	u32 count = 0;

	u32 i;

	int signal;
	int ret = 0;

	rcu_read_lock();
	for_each_process_thread(group, task) {
		if (!agi_lc_cancel_task_matches(session, task, target,
							&record->control))
			continue;
		if (count == ARRAY_SIZE(targets))
			break;
		get_task_struct(task);
		targets[count++] = task;
	}
	rcu_read_unlock();
	if (!count)
		return -ESRCH;
	record->control.state = AGI_LC_CANCEL_STATE_PROPAGATING;
	for (i = 0; i < count; i++) {
		struct task_struct *affected = targets[i];

		faisal_task_request_cancel_ex(affected, record->control.mode,
				record->control.deadline_ns, record->control.priority,
				!!(record->control.cancel_flags &
				   AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES));
		if (record->control.cancel_flags & AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES)
			agi_lc_cancel_revoke_resources(session, affected);
		if (record->control.cancel_flags & AGI_LC_CANCEL_FLAG_DEPRIORITIZE) {
			int priority_ret = agi_lc_cancel_deprioritize(affected,
				record->control.priority);

			if (priority_ret && priority_ret != -EOPNOTSUPP && !ret)
				ret = priority_ret;
		}
		signal = record->control.mode == AGI_LC_CANCEL_MODE_FORCED ?
			SIGKILL : SIGTERM;
		if (send_sig(signal, affected, 0) && !ret)
			ret = -ESRCH;
		put_task_struct(affected);
	}
	record->control.propagated = count;
	record->control.resources_revoked =
		!!(record->control.cancel_flags & AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES);
	record->control.checkpoint_requested =
		!!(record->control.cancel_flags & AGI_LC_CANCEL_FLAG_CHECKPOINT);
	record->control.checkpoint_sequence =
		(record->control.checkpoint_requested && session->checkpoint_valid) ?
		session->checkpoint_sequence : 0;
	record->control.state = ret ? AGI_LC_CANCEL_STATE_FAILED :
		(record->control.mode == AGI_LC_CANCEL_MODE_FORCED ?
		 AGI_LC_CANCEL_STATE_FORCED : AGI_LC_CANCEL_STATE_GRACEFUL);
	record->control.generation++;
	if (ret)
		return ret;
	return 0;
}

static int agi_lc_cancel_control(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_cancel_control control;
	struct agi_lc_cancel_record *record = NULL;
	struct task_struct *target = NULL;
	struct pid *pid;
	unsigned long now = ktime_get_ns();
	u32 i;
	int ret = 0;

	if (copy_from_user(&control, (void __user *)arg, sizeof(control)))
		return -EFAULT;
	if (control.size != sizeof(control) ||
	    control.flags & ~(AGI_LC_CANCEL_CONTROL_REQUEST |
				      AGI_LC_CANCEL_CONTROL_QUERY |
				      AGI_LC_CANCEL_CONTROL_ESCALATE |
				      AGI_LC_CANCEL_CONTROL_ACKNOWLEDGE) ||
	    control.reserved32 || control.reserved[0] || control.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (control.flags & AGI_LC_CANCEL_CONTROL_QUERY) {
		if (control.flags & ~(AGI_LC_CANCEL_CONTROL_QUERY |
					      AGI_LC_CANCEL_CONTROL_ACKNOWLEDGE) ||
		    !control.request_id || control.correlation)
			return -EINVAL;
		record = agi_lc_cancel_find(session, control.request_id);
		if (!record)
			return -ENOENT;
		agi_lc_cancel_refresh(record);
		if (control.flags & AGI_LC_CANCEL_CONTROL_ACKNOWLEDGE)
			record->control.generation++;
		control = record->control;
		if (copy_to_user((void __user *)arg, &control, sizeof(control)))
			return -EFAULT;
		return 0;
	}
	if (!(control.flags & (AGI_LC_CANCEL_CONTROL_REQUEST |
				       AGI_LC_CANCEL_CONTROL_ESCALATE)) ||
	    !control.correlation)
		return -EINVAL;
	if (control.flags & AGI_LC_CANCEL_CONTROL_ESCALATE) {
		if (control.flags != AGI_LC_CANCEL_CONTROL_ESCALATE ||
		    !control.request_id || control.target_pid || control.target_tgid ||
		    control.target_agent || control.parent_request_id)
			return -EINVAL;
		record = agi_lc_cancel_find(session, control.request_id);
		if (!record)
			return -ENOENT;
		agi_lc_cancel_refresh(record);
		if (!capable(CAP_SYS_ADMIN) && record->control.creator_pid != task_pid_nr(current))
			return -EPERM;
		record->control.mode = AGI_LC_CANCEL_MODE_FORCED;
		record->control.cancel_flags |= AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES;
		record->control.state = AGI_LC_CANCEL_STATE_FORCED;
		pid = find_get_pid(record->control.target_pid);
		target = pid ? get_pid_task(pid, PIDTYPE_PID) : NULL;
		if (pid)
			put_pid(pid);
		if (!target)
			return -ESRCH;
		if (faisal_task_get_lineage(target) != session->session_id) {
			put_task_struct(target);
			return -EPERM;
		}
		ret = agi_lc_cancel_apply(session, record, target);
		put_task_struct(target);
		if (ret)
			return ret;
		(void)agi_lc_push_record(session, AGI_LC_EVENT_CANCEL, 0,
					 control.correlation, record->control.request_id);
		control = record->control;
		if (copy_to_user((void __user *)arg, &control, sizeof(control)))
			return -EFAULT;
		return 0;
	}
	if (control.flags != AGI_LC_CANCEL_CONTROL_REQUEST ||
	    control.request_id || control.mode > AGI_LC_CANCEL_MODE_FORCED ||
	    control.scope > AGI_LC_CANCEL_SCOPE_DEPENDENTS ||
	    control.dependency_policy > AGI_LC_CANCEL_DEPENDENCY_AGENT_TREE ||
	    control.cancel_flags & ~(AGI_LC_CANCEL_FLAG_CHECKPOINT |
					      AGI_LC_CANCEL_FLAG_REVOKE_RESOURCES |
					      AGI_LC_CANCEL_FLAG_DEPRIORITIZE) ||
	    control.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    control.state || control.propagated || control.resources_revoked ||
	    control.checkpoint_requested || control.checkpoint_sequence ||
	    control.generation || control.creator_pid || control.creator_tgid ||
	    control.creator_uid || control.creator_euid ||
	    (control.escalation_deadline_ns &&
	     control.escalation_deadline_ns < control.deadline_ns) ||
	    (control.deadline_ns && control.deadline_ns < now) ||
	    (control.escalation_deadline_ns && control.escalation_deadline_ns < now))
		return -EINVAL;
	if (control.parent_request_id &&
	    !agi_lc_cancel_find(session, control.parent_request_id))
		return -ENOENT;
	if (control.scope == AGI_LC_CANCEL_SCOPE_DEPENDENTS &&
	    control.dependency_policy == AGI_LC_CANCEL_DEPENDENCY_NONE)
		return -EINVAL;
	if (control.target_pid <= 0)
		control.target_pid = task_pid_nr(current);
	pid = find_get_pid(control.target_pid);
	if (!pid)
		return -ESRCH;
	target = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (!target)
		return -ESRCH;
	if (faisal_task_get_lineage(target) != session->session_id ||
	    (control.target_tgid && control.target_tgid != task_tgid_nr(target)) ||
	    (control.target_agent && control.target_agent != faisal_task_get_agent(target)) ||
	    !agi_lc_cancel_authorized(session, &control, target)) {
		ret = -EPERM;
		goto out_target;
	}
	for (i = 0; i < AGI_LC_CANCEL_REQUESTS; i++)
		if (!session->cancel_requests[i].valid)
			break;
	if (i == AGI_LC_CANCEL_REQUESTS) {
		ret = -ENOSPC;
		goto out_target;
	}
	if (session->cancel_next_id == U64_MAX) {
		ret = -EOVERFLOW;
		goto out_target;
	}
	record = &session->cancel_requests[i];
	memset(record, 0, sizeof(*record));
	record->valid = true;
	record->control = control;
	record->control.request_id = ++session->cancel_next_id;
	record->control.target_tgid = task_tgid_nr(target);
	record->control.target_agent = faisal_task_get_agent(target);
	record->control.creator_pid = task_pid_nr(current);
	record->control.creator_tgid = task_tgid_nr(current);
	record->control.creator_uid = from_kuid_munged(current_user_ns(), current_uid());
	record->control.creator_euid = from_kuid_munged(current_user_ns(), current_euid());
	record->control.priority = control.priority;
	ret = agi_lc_cancel_apply(session, record, target);
	if (!ret)
		ret = agi_lc_push_record(session, AGI_LC_EVENT_CANCEL,
					 record->control.state == AGI_LC_CANCEL_STATE_FAILED ?
					 -EIO : 0, record->control.correlation,
					 record->control.request_id);
	if (ret && ret != -EAGAIN)
		record->control.state = AGI_LC_CANCEL_STATE_FAILED;
	control = record->control;
	if (!ret && copy_to_user((void __user *)arg, &control, sizeof(control)))
		ret = -EFAULT;
out_target:
	if (target)
		put_task_struct(target);
	return ret;
}

static int agi_lc_get_identity(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_identity identity;
	struct agi_lc_agent_record *agent = NULL;
	struct agi_lc_light_agent_record *light = NULL;
	u64 budget_ns, elapsed_ns, limit_pages, current_pages;
	bool budget_exhausted, memory_exceeded;
	u64 agent_id;
	u32 i;
	int ret;

	if (copy_from_user(&identity, (void __user *)arg, sizeof(identity)))
		return -EFAULT;
	if (identity.size != sizeof(identity) || identity.flags ||
	    identity.session_id || identity.lineage_id || identity.parent_agent ||
	    identity.task_id || identity.tgid ||
	    identity.parent_task_id || identity.parent_tgid || identity.creator_pid ||
	    identity.creator_tgid || identity.creator_uid || identity.creator_euid ||
	    identity.capabilities_effective || identity.capabilities_permitted ||
	    identity.capabilities_inheritable || identity.capabilities_bounding ||
	    identity.authority_rights || identity.authority_generation ||
	    identity.active_grants || identity.cpu_budget_ns || identity.cpu_elapsed_ns ||
	    identity.memory_limit_pages || identity.memory_current_pages ||
	    identity.security_context_id || identity.sandbox_flags || identity.phase ||
	    identity.state || identity.cancelled || identity.budget_exhausted ||
	    identity.memory_exceeded || identity.reserved32 || identity.sampled_at_ns ||
	    identity.reserved[0] || identity.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	agent_id = identity.agent_id ? identity.agent_id : faisal_task_get_agent(current);
	if (!agent_id)
		return -ENOENT;
	if (identity.agent_id && identity.agent_capability)
		light = agi_lc_find_light_agent(session, agent_id,
						identity.agent_capability);
	else if (agent_id == faisal_task_get_agent(current))
		agent = agi_lc_find_agent(session, agent_id);
	if (!agent && !light)
		return -EACCES;
	identity.session_id = session->session_id;
	identity.lineage_id = session->session_id;
	identity.agent_id = agent_id;
	identity.task_id = task_pid_nr(current);
	identity.tgid = task_tgid_nr(current);
	agi_lc_get_current_parent_ids(&identity.parent_task_id,
				       &identity.parent_tgid);
	identity.capabilities_effective =
		agi_lc_capability_mask(current_cred()->cap_effective);
	identity.capabilities_permitted =
		agi_lc_capability_mask(current_cred()->cap_permitted);
	identity.capabilities_inheritable =
		agi_lc_capability_mask(current_cred()->cap_inheritable);
	identity.capabilities_bounding =
		agi_lc_capability_mask(current_cred()->cap_bset);
	identity.phase = faisal_task_get_phase(current);
	identity.cancelled = faisal_task_cancelled(current);
	faisal_task_get_budget(current, &budget_ns, &elapsed_ns, &budget_exhausted);
	faisal_task_get_memory_limit(current, &limit_pages, &current_pages,
					 &memory_exceeded);
	identity.cpu_budget_ns = budget_ns;
	identity.cpu_elapsed_ns = elapsed_ns;
	identity.memory_limit_pages = limit_pages;
	identity.memory_current_pages = current_pages;
	identity.budget_exhausted = budget_exhausted;
	identity.memory_exceeded = memory_exceeded;
	identity.state = agent ? agent->state : light->state;
	identity.parent_agent = agent ? agent->parent_agent : light->parent_agent;
	identity.agent_capability = light ? light->capability : 0;
	identity.creator_pid = agent ? agent->creator_pid : light->creator_pid;
	identity.creator_tgid = agent ? agent->creator_tgid : light->creator_tgid;
	identity.parent_task_id = agent ? agent->parent_pid : light->parent_pid;
	identity.parent_tgid = agent ? agent->parent_tgid : light->parent_tgid;
	identity.creator_uid = agent ? agent->creator_uid : light->creator_uid;
	identity.creator_euid = agent ? agent->creator_euid : light->creator_euid;
	for (i = 0; i < AGI_LC_CAPABILITY_RECORDS; i++) {
		struct agi_lc_capability_record *grant = &session->capabilities[i];

		if (!grant->valid || grant->grant.status != AGI_LC_CAP_STATUS_ACTIVE ||
		    grant->grant.agent_id != agent_id)
			continue;
		identity.authority_rights |= grant->grant.rights;
		identity.sandbox_flags |= grant->grant.sandbox_flags;
		identity.active_grants++;
		identity.authority_generation = max_t(u64,
					identity.authority_generation,
					grant->grant.generation);
	}
	identity.sampled_at_ns = ktime_get_ns();
	identity.correlation = identity.correlation;
	ret = copy_to_user((void __user *)arg, &identity, sizeof(identity));
	return ret ? -EFAULT : 0;
}

static int agi_lc_get_attribution(struct agi_lc_session *session,
					  unsigned long arg)
{
	struct agi_lc_attribution query;
	unsigned long flags;
	u64 sequence;
	int ret;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || !query.sequence ||
	    query.action_type || query.reserved16 || query.status || query.phase ||
	    query.session_id || query.lineage_id || query.agent_id ||
	    query.parent_agent || query.task_id || query.tgid || query.parent_task_id ||
	    query.parent_tgid || query.creator_pid || query.creator_tgid ||
	    query.creator_uid || query.creator_euid || query.capabilities_effective ||
	    query.capabilities_permitted || query.authority_rights ||
	    query.authority_generation || query.active_grants || query.cpu_budget_ns ||
	    query.cpu_elapsed_ns || query.memory_limit_pages || query.memory_current_pages ||
	    query.security_context_id || query.sandbox_flags || query.state ||
	    query.correlation || query.metadata || query.recorded_at_ns ||
	    query.reserved[0] || query.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	sequence = query.sequence;
	spin_lock_irqsave(&session->queue_lock, flags);
	query = session->attributions[sequence % AGI_LC_RING_SIZE];
	if (query.sequence != sequence || query.session_id != session->session_id)
		ret = -ENOENT;
	else
		ret = 0;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return 0;
}

static bool agi_lc_digest_present(const u8 *digest)
{
	u32 i;

	for (i = 0; i < AGI_LC_DIGEST_SIZE; i++)
		if (digest[i])
			return true;
	return false;
}

static void agi_lc_provenance_fill_action(struct agi_lc_session *session,
						 struct agi_lc_provenance *provenance)
{
	struct agi_lc_attribution *attribution =
		&session->attributions[provenance->action_sequence % AGI_LC_RING_SIZE];
	u64 compute_ns, memory_bytes, submissions;

	provenance->session_id = attribution->session_id;
	provenance->lineage_id = attribution->lineage_id;
	provenance->agent_id = attribution->agent_id;
	provenance->parent_agent = attribution->parent_agent;
	provenance->task_id = attribution->task_id;
	provenance->tgid = attribution->tgid;
	provenance->parent_task_id = attribution->parent_task_id;
	provenance->parent_tgid = attribution->parent_tgid;
	provenance->creator_pid = attribution->creator_pid;
	provenance->creator_tgid = attribution->creator_tgid;
	provenance->creator_uid = attribution->creator_uid;
	provenance->creator_euid = attribution->creator_euid;
	provenance->authority_rights = attribution->authority_rights;
	provenance->authority_generation = attribution->authority_generation;
	provenance->active_grants = attribution->active_grants;
	provenance->action_cpu_budget_ns = attribution->cpu_budget_ns;
	provenance->action_cpu_elapsed_ns = attribution->cpu_elapsed_ns;
	provenance->action_memory_limit_pages = attribution->memory_limit_pages;
	provenance->action_memory_current_pages = attribution->memory_current_pages;
	provenance->capabilities_effective = attribution->capabilities_effective;
	provenance->capabilities_permitted = attribution->capabilities_permitted;
	provenance->sandbox_flags = attribution->sandbox_flags;
	provenance->phase = attribution->phase;
	provenance->state = attribution->state;
	faisal_task_accel_get(current, &compute_ns, &memory_bytes, &submissions);
	provenance->action_accel_compute_ns = compute_ns;
	provenance->action_accel_memory_bytes = memory_bytes;
	provenance->action_accel_submissions = submissions;
	provenance->action_recorded_at_ns = attribution->recorded_at_ns;
}

static struct agi_lc_provenance_record *
agi_lc_find_provenance(struct agi_lc_session *session, u64 provenance_id,
			       u64 action_sequence)
{
	struct agi_lc_provenance_record *record =
		&session->provenance[provenance_id % AGI_LC_PROVENANCE_RECORDS];

	if (!record->valid || record->provenance.provenance_id != provenance_id ||
	    record->provenance.action_sequence != action_sequence)
		return NULL;
	return record;
}

static bool agi_lc_provenance_sequence_present(struct agi_lc_session *session,
						 u64 sequence)
{
	u32 i;

	if (!sequence)
		return true;
	for (i = 0; i < AGI_LC_PROVENANCE_RECORDS; i++) {
		struct agi_lc_provenance_record *record = &session->provenance[i];

		if (record->valid &&
		    (record->provenance.action_sequence == sequence ||
		     record->provenance.result_sequence == sequence))
			return true;
	}
	return false;
}

static int agi_lc_provenance_publish(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_provenance input;
	struct agi_lc_provenance_record *record;
	u64 elapsed_ns, current_pages, ignored_budget, ignored_limit;
	u64 compute_ns, memory_bytes, submissions;
	bool ignored_budget_exhausted, ignored_memory_exceeded;
	u64 sequence;
	int ret;

	if (copy_from_user(&input, (void __user *)arg, sizeof(input)))
		return -EFAULT;
	if (input.size != sizeof(input) || input.flags || !input.operation ||
	    input.operation > AGI_LC_PROVENANCE_PUBLISH_RESULT ||
	    input.reserved[0] || input.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!faisal_task_get_agent(current))
		return -EACCES;

	if (input.operation == AGI_LC_PROVENANCE_PUBLISH_ACTION) {
		if (input.status || input.provenance_id || input.action_sequence ||
		    input.result_sequence || !input.correlation ||
		    !agi_lc_digest_present(input.action_digest) ||
		    agi_lc_digest_present(input.result_digest) || input.result_status ||
		    input.result_kind || input.session_id ||
		    input.lineage_id || input.agent_id || input.parent_agent ||
		    input.task_id || input.tgid || input.parent_task_id || input.parent_tgid ||
		    input.creator_pid || input.creator_tgid || input.creator_uid ||
		    input.creator_euid || input.authority_rights ||
		    input.authority_generation || input.active_grants ||
		    input.action_cpu_budget_ns || input.action_cpu_elapsed_ns ||
		    input.action_memory_limit_pages || input.action_memory_current_pages ||
		    input.action_accel_compute_ns || input.action_accel_memory_bytes ||
		    input.action_accel_submissions || input.result_task_id || input.result_tgid ||
		    input.result_cpu_elapsed_ns || input.result_memory_current_pages ||
		    input.result_accel_compute_ns || input.result_accel_memory_bytes ||
		    input.result_accel_submissions || input.capabilities_effective ||
		    input.capabilities_permitted || input.sandbox_flags || input.phase ||
		    input.state || input.action_recorded_at_ns || input.result_recorded_at_ns)
			return -EINVAL;
		if (!agi_lc_provenance_sequence_present(session,
						       input.parent_sequence))
			return -ENOENT;
		if (session->provenance_next_id == U64_MAX)
			return -EOVERFLOW;
		record = &session->provenance[
			(++session->provenance_next_id) % AGI_LC_PROVENANCE_RECORDS];
		memset(record, 0, sizeof(*record));
		record->valid = true;
		record->provenance = input;
		record->provenance.provenance_id = session->provenance_next_id;
		ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_PROVENANCE, 0,
					input.correlation, record->provenance.provenance_id,
					&sequence);
		if (ret) {
			record->valid = false;
			return ret;
		}
		record->provenance.action_sequence = sequence;
		agi_lc_provenance_fill_action(session, &record->provenance);
		record->provenance.parent_sequence = input.parent_sequence;
		memcpy(record->provenance.action_digest, input.action_digest,
		       AGI_LC_DIGEST_SIZE);
		if (copy_to_user((void __user *)arg, &record->provenance,
				 sizeof(record->provenance)))
			return -EFAULT;
		return 0;
	}

	if (!input.provenance_id || !input.action_sequence || input.result_sequence ||
	    input.status || !input.correlation ||
	    !agi_lc_digest_present(input.result_digest) ||
	    agi_lc_digest_present(input.action_digest) || input.parent_sequence ||
	    input.session_id || input.lineage_id || input.agent_id || input.parent_agent ||
	    input.task_id || input.tgid || input.parent_task_id || input.parent_tgid ||
	    input.creator_pid || input.creator_tgid || input.creator_uid ||
	    input.creator_euid || input.authority_rights || input.authority_generation ||
	    input.active_grants || input.action_cpu_budget_ns || input.action_cpu_elapsed_ns ||
	    input.action_memory_limit_pages || input.action_memory_current_pages ||
	    input.action_accel_compute_ns || input.action_accel_memory_bytes ||
	    input.action_accel_submissions || input.result_task_id || input.result_tgid ||
	    input.result_cpu_elapsed_ns || input.result_memory_current_pages ||
	    input.result_accel_compute_ns || input.result_accel_memory_bytes ||
	    input.result_accel_submissions || input.capabilities_effective ||
	    input.capabilities_permitted || input.sandbox_flags || input.phase ||
	    input.state || input.action_recorded_at_ns || input.result_recorded_at_ns)
		return -EINVAL;
	record = agi_lc_find_provenance(session, input.provenance_id,
					input.action_sequence);
	if (!record || record->provenance.result_sequence ||
	    record->provenance.agent_id != faisal_task_get_agent(current))
		return -EACCES;
	ret = agi_lc_push_record_ex(session, AGI_LC_EVENT_PROVENANCE,
					input.result_status, input.correlation,
					record->provenance.provenance_id, &sequence);
	if (ret)
		return ret;
	faisal_task_get_budget(current, &ignored_budget, &elapsed_ns,
					 &ignored_budget_exhausted);
	faisal_task_get_memory_limit(current, &ignored_limit, &current_pages,
					 &ignored_memory_exceeded);
	(void)ignored_budget;
	(void)ignored_limit;
	(void)ignored_budget_exhausted;
	(void)ignored_memory_exceeded;
	faisal_task_accel_get(current, &compute_ns, &memory_bytes, &submissions);
	record->provenance.result_sequence = sequence;
	record->provenance.result_status = input.result_status;
	record->provenance.result_kind = input.result_kind;
	record->provenance.result_task_id = task_pid_nr(current);
	record->provenance.result_tgid = task_tgid_nr(current);
	record->provenance.result_cpu_elapsed_ns = elapsed_ns;
	record->provenance.result_memory_current_pages = current_pages;
	record->provenance.result_accel_compute_ns = compute_ns;
	record->provenance.result_accel_memory_bytes = memory_bytes;
	record->provenance.result_accel_submissions = submissions;
	record->provenance.result_recorded_at_ns = ktime_get_ns();
	memcpy(record->provenance.result_digest, input.result_digest,
	       AGI_LC_DIGEST_SIZE);
	if (copy_to_user((void __user *)arg, &record->provenance,
			 sizeof(record->provenance)))
		return -EFAULT;
	return 0;
}

static int agi_lc_provenance_query(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_provenance query;
	struct agi_lc_provenance_record *record;
	int ret;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.operation || query.status ||
	    query.flags || !query.provenance_id ||
	    query.result_sequence || query.parent_sequence || query.session_id ||
	    query.lineage_id || query.agent_id || query.parent_agent || query.task_id ||

	    query.tgid || query.parent_task_id || query.parent_tgid || query.creator_pid ||
	    query.creator_tgid || query.creator_uid || query.creator_euid ||
	    query.authority_rights || query.authority_generation || query.active_grants ||
	    query.action_cpu_budget_ns || query.action_cpu_elapsed_ns ||
	    query.action_memory_limit_pages || query.action_memory_current_pages ||
	    query.action_accel_compute_ns || query.action_accel_memory_bytes ||
	    query.action_accel_submissions || query.result_task_id || query.result_tgid ||
	    query.result_cpu_elapsed_ns || query.result_memory_current_pages ||
	    query.result_accel_compute_ns || query.result_accel_memory_bytes ||
	    query.result_accel_submissions || query.capabilities_effective ||
	    query.capabilities_permitted || query.sandbox_flags || query.phase ||
	    query.state || query.result_status || query.result_kind ||
	    agi_lc_digest_present(query.action_digest) ||
	    agi_lc_digest_present(query.result_digest) || query.action_recorded_at_ns ||
	    query.result_recorded_at_ns || query.correlation || query.reserved[0] ||
	    query.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	record = &session->provenance[
		query.provenance_id % AGI_LC_PROVENANCE_RECORDS];
	if (!record->valid || record->provenance.provenance_id != query.provenance_id)
		return -ENOENT;
	if (query.action_sequence &&
	    record->provenance.action_sequence != query.action_sequence)
		return -ESTALE;
	query = record->provenance;
	ret = copy_to_user((void __user *)arg, &query, sizeof(query));
	return ret ? -EFAULT : 0;
}

static void agi_lc_resource_observe(struct agi_lc_resource_demand *demand)
{
	u64 memory_limit_pages;
	u64 memory_current_pages;
	u64 accel_compute_ns;
	u64 accel_memory_bytes;
	u64 accel_submissions;
	bool memory_exceeded;

	demand->observed_cpu_time_ns = READ_ONCE(current->se.sum_exec_runtime);
	faisal_task_get_memory_limit(current, &memory_limit_pages,
				     &memory_current_pages, &memory_exceeded);
	demand->observed_memory_bytes = memory_current_pages << PAGE_SHIFT;
	faisal_task_accel_get(current, &accel_compute_ns, &accel_memory_bytes,
			      &accel_submissions);
	demand->observed_accel_compute_ns = accel_compute_ns;
	demand->observed_accel_memory_bytes = accel_memory_bytes;
	demand->observed_accel_submissions = accel_submissions;
}

static int agi_lc_get_resource_snapshot(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_resource_snapshot snapshot;
	struct agi_lc_agent_record *record;
	struct agi_lc_accel_record *device;
	unsigned long flags;
	u64 memory_limit_pages;
	u64 memory_current_pages;
	u64 cpu_budget_ns;
	u64 cpu_elapsed_ns;
	u64 network_tx_bytes;
	u64 network_rx_bytes;
	u64 network_socket_creates;
	u64 network_denied;
	u64 correlation;
	bool budget_exhausted;
	bool memory_exceeded;
	bool network_available;

	if (copy_from_user(&snapshot, (void __user *)arg, sizeof(snapshot)))
		return -EFAULT;
	if (snapshot.size != sizeof(snapshot) || snapshot.flags ||
	    snapshot.session_id || snapshot.lineage_id || snapshot.agent_id ||
	    snapshot.task_id || snapshot.tgid || snapshot.sampled_at_ns ||
	    snapshot.generation || snapshot.measured_mask ||
	    snapshot.unavailable_mask || snapshot.unsupported_mask ||
	    snapshot.accelerator_type || snapshot.energy_flags ||
	    snapshot.reserved32 || snapshot.cpu_time_ns || snapshot.cpu_budget_ns ||
	    snapshot.cpu_elapsed_ns || snapshot.memory_rss_bytes ||
	    snapshot.memory_limit_bytes || snapshot.memory_current_bytes ||
	    snapshot.network_tx_bytes || snapshot.network_rx_bytes ||
	    snapshot.network_socket_creates || snapshot.network_denied ||
	    snapshot.storage_read_bytes || snapshot.storage_write_bytes ||
	    snapshot.storage_cancelled_write_bytes || snapshot.io_read_chars ||
	    snapshot.io_write_chars || snapshot.io_read_syscalls ||
	    snapshot.io_write_syscalls || snapshot.accel_compute_ns ||
	    snapshot.accel_memory_bytes || snapshot.accel_submissions ||
	    snapshot.energy_uj || snapshot.reserved[0] || snapshot.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	correlation = snapshot.correlation;
	memset((u8 *)&snapshot + offsetof(struct agi_lc_resource_snapshot,
					 session_id), 0,
	       sizeof(snapshot) - offsetof(struct agi_lc_resource_snapshot,
						 session_id));
	snapshot.size = sizeof(snapshot);
	snapshot.correlation = correlation;
	snapshot.session_id = session->session_id;
	snapshot.lineage_id = faisal_task_get_lineage(current);
	snapshot.agent_id = faisal_task_get_agent(current);
	snapshot.task_id = task_pid_nr(current);
	snapshot.tgid = task_tgid_nr(current);
	snapshot.sampled_at_ns = ktime_get_ns();
	snapshot.cpu_time_ns = READ_ONCE(current->se.sum_exec_runtime);
	snapshot.measured_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM;
	faisal_task_get_budget(current, &cpu_budget_ns, &cpu_elapsed_ns,
			       &budget_exhausted);
	faisal_task_get_memory_limit(current, &memory_limit_pages,
				     &memory_current_pages, &memory_exceeded);
	snapshot.cpu_budget_ns = cpu_budget_ns;
	snapshot.cpu_elapsed_ns = cpu_elapsed_ns;
	snapshot.memory_limit_bytes = memory_limit_pages << PAGE_SHIFT;
	snapshot.memory_current_bytes = memory_current_pages << PAGE_SHIFT;
	if (current->mm)
		snapshot.memory_rss_bytes =
			(u64)get_mm_rss(current->mm) << PAGE_SHIFT;

	faisal_task_net_usage_get(current, &network_tx_bytes, &network_rx_bytes,
				  &network_socket_creates, &network_denied,
				  &network_available);
	if (network_available) {
		snapshot.measured_mask |= AGI_LC_RESOURCE_NETWORK;
		snapshot.network_tx_bytes = network_tx_bytes;
		snapshot.network_rx_bytes = network_rx_bytes;
		snapshot.network_socket_creates = network_socket_creates;
		snapshot.network_denied = network_denied;
	} else {
		snapshot.unavailable_mask |= AGI_LC_RESOURCE_NETWORK;
	}

#ifdef CONFIG_TASK_IO_ACCOUNTING
	snapshot.measured_mask |= AGI_LC_RESOURCE_STORAGE;
	snapshot.storage_read_bytes = READ_ONCE(current->ioac.read_bytes);
	snapshot.storage_write_bytes = READ_ONCE(current->ioac.write_bytes);
	snapshot.storage_cancelled_write_bytes =
		READ_ONCE(current->ioac.cancelled_write_bytes);
#else
	snapshot.unsupported_mask |= AGI_LC_RESOURCE_STORAGE;
#endif
#ifdef CONFIG_TASK_XACCT
	snapshot.measured_mask |= AGI_LC_RESOURCE_IO;
	snapshot.io_read_chars = READ_ONCE(current->ioac.rchar);
	snapshot.io_write_chars = READ_ONCE(current->ioac.wchar);
	snapshot.io_read_syscalls = READ_ONCE(current->ioac.syscr);
	snapshot.io_write_syscalls = READ_ONCE(current->ioac.syscw);
#else
	snapshot.unsupported_mask |= AGI_LC_RESOURCE_IO;
#endif

	faisal_task_accel_get(current, &snapshot.accel_compute_ns,
			      &snapshot.accel_memory_bytes,
			      &snapshot.accel_submissions);
	record = agi_lc_find_agent(session, snapshot.agent_id);
	if (!record || !record->accel_workload_valid) {
		snapshot.unavailable_mask |= AGI_LC_RESOURCE_GPU |
			AGI_LC_RESOURCE_NPU | AGI_LC_RESOURCE_VRAM;
	} else {
		mutex_lock(&agi_lc_accel_lock);
		device = agi_lc_find_accel_locked(record->accel_workload.device_id);
		if (!device) {
			snapshot.unavailable_mask |= AGI_LC_RESOURCE_GPU |
				AGI_LC_RESOURCE_NPU | AGI_LC_RESOURCE_VRAM;
		} else {
			snapshot.accelerator_type = device->device.type;
			if (device->device.type == AGI_LC_ACCEL_TYPE_GPU)
				snapshot.measured_mask |= AGI_LC_RESOURCE_GPU;
			else if (device->device.type == AGI_LC_ACCEL_TYPE_NPU)
				snapshot.measured_mask |= AGI_LC_RESOURCE_NPU;
			else
				snapshot.unsupported_mask |= AGI_LC_RESOURCE_GPU |
					AGI_LC_RESOURCE_NPU;
			if (device->device.capabilities & AGI_LC_ACCEL_CAP_DEVICE_MEMORY)
				snapshot.measured_mask |= AGI_LC_RESOURCE_VRAM;
			else
				snapshot.unsupported_mask |= AGI_LC_RESOURCE_VRAM;
		}
		mutex_unlock(&agi_lc_accel_lock);
	}

	spin_lock_irqsave(&session->queue_lock, flags);
	snapshot.generation = session->change_generation;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &snapshot, sizeof(snapshot)))
		return -EFAULT;
	return 0;
}

static u64 agi_lc_sat_add_u64(u64 left, u64 right)
{
	if (U64_MAX - left < right)
		return U64_MAX;
	return left + right;
}

static int agi_lc_tenant_cpu_policy_control(
		struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_tenant_cpu_policy policy;
	struct cgroup_subsys_state *css;
	u64 period_us, burst_us, throttled_usec;
	s64 quota_us;
	int ret;

	if (copy_from_user(&policy, (void __user *)arg, sizeof(policy)))
		return -EFAULT;
	if (policy.size != sizeof(policy) ||
	    (policy.flags & ~AGI_LC_TENANT_CPU_FLAGS_ALL) ||
	    policy.status || policy.reserved32 || policy.generation ||
	    policy.throttled_usec || policy.reserved[0] || policy.reserved[1])
		return -EINVAL;
	if (policy.operation != AGI_LC_TENANT_CPU_OP_SET &&
	    policy.operation != AGI_LC_TENANT_CPU_OP_QUERY &&
	    policy.operation != AGI_LC_TENANT_CPU_OP_CLEAR)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if ((policy.flags & AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP) &&
	    !session->tenant_cgroup)
		return -EPERM;
	if (!session->tenant_cgroup)
		return -EPERM;
	if (!agi_lc_tenant_cgroup_matches_current(session))
		return -EXDEV;
	if (policy.operation == AGI_LC_TENANT_CPU_OP_SET) {
		u64 max_quota;

		if (policy.mode != AGI_LC_TENANT_CPU_MODE_HARD_THROTTLE ||
		    policy.period_us < 1000 || policy.period_us > 1000000 ||
		    policy.quota_us <= 0 || policy.burst_us > policy.period_us)
			return -EINVAL;
		if (policy.expected_generation != session->tenant_cpu_policy.generation)
			return -EAGAIN;
		max_quota = policy.period_us * num_online_cpus();
		if (policy.quota_us > max_quota)
			return -EINVAL;
	} else if (policy.operation == AGI_LC_TENANT_CPU_OP_QUERY) {
		if (policy.mode || policy.period_us || policy.quota_us ||
		    policy.burst_us || policy.expected_generation)
			return -EINVAL;
	} else {
		if (policy.mode || policy.period_us || policy.quota_us ||
		    policy.burst_us ||
		    policy.expected_generation != session->tenant_cpu_policy.generation)
			return -EINVAL;
		if (!session->tenant_cpu_policy_valid)
			return -ENOENT;
	}

	rcu_read_lock();
	css = cgroup_css(session->tenant_cgroup, &cpu_cgrp_subsys);
	if (!css || !css_tryget_online(css))
		css = NULL;
	rcu_read_unlock();
	if (!css)
		return -ENODEV;

	if (policy.operation == AGI_LC_TENANT_CPU_OP_SET) {
		ret = faisal_sched_group_set_cpu_bandwidth(css, policy.period_us,
				policy.quota_us, policy.burst_us);
		if (!ret) {
			session->tenant_cpu_policy = policy;
			session->tenant_cpu_policy.generation++;
			session->tenant_cpu_policy.status =
			AGI_LC_TENANT_CPU_STATUS_ACTIVE;
			session->tenant_cpu_policy_valid = true;
			policy = session->tenant_cpu_policy;
		}
	} else {
		ret = faisal_sched_group_get_cpu_bandwidth(css, &period_us,
				&quota_us, &burst_us, &throttled_usec);
		if (!ret) {
			policy.period_us = period_us;
			policy.quota_us = quota_us;
			policy.burst_us = burst_us;
			policy.throttled_usec = throttled_usec;
			if (policy.operation == AGI_LC_TENANT_CPU_OP_CLEAR) {
				ret = faisal_sched_group_set_cpu_bandwidth(css,
					period_us, -1, 0);
				if (!ret) {
					session->tenant_cpu_policy_valid = false;
					session->tenant_cpu_policy.generation++;
					policy.status = AGI_LC_TENANT_CPU_STATUS_CLEARED;
					policy.generation =
						session->tenant_cpu_policy.generation;
				} else {
					policy.status = AGI_LC_TENANT_CPU_STATUS_UNSUPPORTED;
				}
			} else {
				policy.status = session->tenant_cpu_policy_valid ?
					AGI_LC_TENANT_CPU_STATUS_ACTIVE :
					AGI_LC_TENANT_CPU_STATUS_UNSET;
				policy.generation =
					session->tenant_cpu_policy.generation;
			}
		}
	}
	css_put(css);
	if (ret)
		return ret == -EOPNOTSUPP ? -EOPNOTSUPP : ret;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_RESOURCE_DEMAND, 0,
				policy.correlation, policy.generation);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &policy, sizeof(policy)))
		return -EFAULT;
	return 0;
}

static int agi_lc_tenant_cgroup_control(struct agi_lc_session *session,
						unsigned long arg)
{
	struct agi_lc_tenant_cgroup request;
	struct cgroup *target = NULL;
	struct cgroup *current_cgroup;
	u64 cgroup_id_value = 0;
	u64 parent_id = 0;
	int ret = 0;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) ||
	    (request.flags & ~AGI_LC_TENANT_CGROUP_FLAGS_ALL) ||
	    request.status || request.reserved32 || request.session_id ||
	    request.cgroup_id || request.parent_cgroup_id ||
	    request.hierarchy_owner_id || request.generation ||
	    request.reserved[0] || request.reserved[1])
		return -EINVAL;
	if (request.operation != AGI_LC_TENANT_CGROUP_BIND &&
	    request.operation != AGI_LC_TENANT_CGROUP_QUERY &&
	    request.operation != AGI_LC_TENANT_CGROUP_RELEASE)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (request.operation == AGI_LC_TENANT_CGROUP_BIND) {
		if (request.cgroup_fd < 0 || session->tenant_cgroup)
			return session->tenant_cgroup ? -EALREADY : -EINVAL;
		if ((request.flags & AGI_LC_TENANT_CGROUP_FLAG_REQUIRE_SANDBOX) &&
		    (!session->sandbox_bound ||
		     session->sandbox_state != AGI_LC_SANDBOX_STATE_BOUND ||
		     !agi_lc_sandbox_matches_current(&session->sandbox_binding)))
			return -EPERM;
		target = cgroup_get_from_fd(request.cgroup_fd);
		if (IS_ERR(target))
			return PTR_ERR(target);
		current_cgroup = task_dfl_cgroup(current);
		if (!cgroup_parent(target) ||
		    cgroup_parent(target) != current_cgroup ||
		    !cgroup_is_descendant(target, current_cgroup)) {
			cgroup_put(target);
			return -EXDEV;
		}
		cgroup_id_value = cgroup_id(target);
		parent_id = cgroup_id(current_cgroup);
		if (!cgroup_id_value || !parent_id) {
			cgroup_put(target);
			return -EOPNOTSUPP;
		}
		session->tenant_cgroup = target;
		session->tenant_cgroup_id = cgroup_id_value;
		session->tenant_cgroup_parent_id = parent_id;
		session->tenant_cgroup_generation++;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_SECURITY_CAPABILITY,
					 0, request.correlation, cgroup_id_value);
		if (ret) {
			session->tenant_cgroup = NULL;
			session->tenant_cgroup_id = 0;
			session->tenant_cgroup_parent_id = 0;
			cgroup_put(target);
			return ret;
		}
		request.status = AGI_LC_TENANT_CGROUP_STATUS_BOUND;
	} else if (request.operation == AGI_LC_TENANT_CGROUP_QUERY) {
		if (request.cgroup_fd != -1 || !session->tenant_cgroup)
			return -ENOENT;
		if (!agi_lc_tenant_cgroup_matches_current(session))
			return -EXDEV;
		request.status = AGI_LC_TENANT_CGROUP_STATUS_BOUND;
	} else {
		if (request.cgroup_fd != -1 || !session->tenant_cgroup)
			return -ENOENT;
		if (!agi_lc_tenant_cgroup_matches_current(session))
			return -EXDEV;
		cgroup_id_value = session->tenant_cgroup_id;
		parent_id = session->tenant_cgroup_parent_id;
		target = session->tenant_cgroup;
		session->tenant_cgroup = NULL;
		session->tenant_cgroup_id = 0;
		session->tenant_cgroup_parent_id = 0;
		session->tenant_cgroup_generation++;
		cgroup_put(target);
		request.status = AGI_LC_TENANT_CGROUP_STATUS_REVOKED;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_SECURITY_CAPABILITY,
					 0, request.correlation, cgroup_id_value);
	}
	request.session_id = session->session_id;
	request.cgroup_id = session->tenant_cgroup_id;
	request.parent_cgroup_id = session->tenant_cgroup_parent_id;
	request.hierarchy_owner_id = session->session_id;
	request.generation = session->tenant_cgroup_generation;
	if (request.status == AGI_LC_TENANT_CGROUP_STATUS_REVOKED) {
		request.cgroup_id = cgroup_id_value;
		request.parent_cgroup_id = parent_id;
	}
	if (copy_to_user((void __user *)arg, &request, sizeof(request)))
		return -EFAULT;
	return ret;
}

static int agi_lc_tenant_budget_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_tenant_budget budget;
	u64 observed_cpu = 0;
	u64 observed_memory = 0;
	u32 i;
	int ret;

	if (copy_from_user(&budget, (void __user *)arg, sizeof(budget)))
		return -EFAULT;
	if (budget.size != sizeof(budget) ||
	    (budget.flags & ~AGI_LC_TENANT_BUDGET_FLAGS_ALL) ||
	    budget.reserved32 || budget.session_id || budget.sandbox_binding_id ||
	    budget.generation || budget.enforced_mask || budget.over_budget_mask ||
	    budget.status || budget.reserved[0] ||
	    budget.reserved[1])
		return -EINVAL;
	if (budget.operation != AGI_LC_TENANT_BUDGET_OP_SET &&
	    budget.operation != AGI_LC_TENANT_BUDGET_OP_QUERY &&
	    budget.operation != AGI_LC_TENANT_BUDGET_OP_CLEAR)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if ((budget.flags & AGI_LC_TENANT_BUDGET_FLAG_REQUIRE_SANDBOX) &&
	    (!READ_ONCE(session->sandbox_bound) ||
	     READ_ONCE(session->sandbox_state) != AGI_LC_SANDBOX_STATE_BOUND))
		return -EPERM;
	if ((budget.flags & AGI_LC_TENANT_BUDGET_FLAG_REQUIRE_CGROUP) &&
	    !session->tenant_cgroup)
		return -EPERM;
	if (budget.operation == AGI_LC_TENANT_BUDGET_OP_SET) {
		if (!budget.resource_mask ||
		    (budget.resource_mask & ~AGI_LC_TENANT_BUDGET_SUPPORTED_MASK))
			return -EOPNOTSUPP;
		if ((budget.resource_mask & AGI_LC_RESOURCE_CPU) &&
		    !budget.cpu_budget_ns)
			return -EINVAL;
		if ((budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
		    (!budget.memory_limit_bytes ||
		     (budget.memory_limit_bytes & (PAGE_SIZE - 1))))
			return -EINVAL;
		if (!(budget.resource_mask & AGI_LC_RESOURCE_CPU) &&
		    budget.cpu_budget_ns)
			return -EINVAL;
		if (!(budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
		    budget.memory_limit_bytes)
			return -EINVAL;
	}
	if (budget.operation == AGI_LC_TENANT_BUDGET_OP_QUERY ||
	    budget.operation == AGI_LC_TENANT_BUDGET_OP_CLEAR) {
		if (budget.resource_mask || budget.cpu_budget_ns ||
		    budget.memory_limit_bytes)
			return -EINVAL;
	}

	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		struct agi_lc_agent_record *record = &session->agents[i];

		if (!record->valid || !record->resource_demand_valid)
			continue;
		observed_cpu = agi_lc_sat_add_u64(observed_cpu,
						 record->resource_demand.observed_cpu_time_ns);
		observed_memory = agi_lc_sat_add_u64(observed_memory,
						   record->resource_demand.observed_memory_bytes);
	}
	if (budget.operation == AGI_LC_TENANT_BUDGET_OP_SET) {
		if ((budget.resource_mask & AGI_LC_RESOURCE_CPU) &&
		    observed_cpu > budget.cpu_budget_ns)
			return -EDQUOT;
		if ((budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
		    observed_memory > budget.memory_limit_bytes)
			return -EDQUOT;
		session->tenant_budget = budget;
		session->tenant_budget_valid = true;
	} else if (budget.operation == AGI_LC_TENANT_BUDGET_OP_CLEAR) {
		memset(&session->tenant_budget, 0, sizeof(session->tenant_budget));
		session->tenant_budget_valid = false;
	}
	if (budget.operation != AGI_LC_TENANT_BUDGET_OP_QUERY) {
		spin_lock_irq(&session->queue_lock);
		session->change_generation++;
		spin_unlock_irq(&session->queue_lock);
		ret = agi_lc_push_record(session, AGI_LC_EVENT_RESOURCE_DEMAND, 0,
					 budget.correlation, budget.resource_mask);
		if (ret)
			return ret;
	}
	budget.session_id = session->session_id;
	budget.sandbox_binding_id = READ_ONCE(session->sandbox_bound) ?
		READ_ONCE(session->sandbox_binding_id) : 0;
	budget.generation = READ_ONCE(session->change_generation);
	if (session->tenant_budget_valid) {
		budget.resource_mask = session->tenant_budget.resource_mask;
		budget.enforced_mask = budget.resource_mask;
		budget.cpu_budget_ns = session->tenant_budget.cpu_budget_ns;
		budget.memory_limit_bytes = session->tenant_budget.memory_limit_bytes;
		budget.flags = session->tenant_budget.flags;
		budget.status = AGI_LC_TENANT_BUDGET_STATUS_ACTIVE;
		if ((budget.resource_mask & AGI_LC_RESOURCE_CPU) &&
		    observed_cpu > budget.cpu_budget_ns)
			budget.over_budget_mask |= AGI_LC_RESOURCE_CPU;
		if ((budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
		    observed_memory > budget.memory_limit_bytes)
			budget.over_budget_mask |= AGI_LC_RESOURCE_RAM;
	} else {
		budget.status = budget.operation == AGI_LC_TENANT_BUDGET_OP_CLEAR ?
			AGI_LC_TENANT_BUDGET_STATUS_CLEARED :
			AGI_LC_TENANT_BUDGET_STATUS_UNSET;
	}
	if (copy_to_user((void __user *)arg, &budget, sizeof(budget)))
		return -EFAULT;
	return 0;
}

static int agi_lc_get_tenant_snapshot(struct agi_lc_session *session,
					       unsigned long arg)
{
	struct agi_lc_tenant_snapshot snapshot;
	unsigned long flags;
	u32 i;

	if (copy_from_user(&snapshot, (void __user *)arg, sizeof(snapshot)))
		return -EFAULT;
	if (snapshot.size != sizeof(snapshot) ||
	    (snapshot.flags & ~AGI_LC_TENANT_FLAGS_ALL) ||
	    snapshot.session_id || snapshot.sandbox_binding_id ||
	    snapshot.sampled_at_ns || snapshot.generation || snapshot.resource_mask ||
	    snapshot.measured_mask || snapshot.unsupported_mask ||
	    snapshot.over_budget_mask || snapshot.agent_count ||
	    snapshot.active_agent_count || snapshot.light_agent_count ||
	    snapshot.reserved32 || snapshot.cpu_time_ns || snapshot.cpu_budget_ns ||
	    snapshot.cpu_elapsed_ns || snapshot.memory_rss_bytes ||
	    snapshot.memory_limit_bytes || snapshot.memory_current_bytes ||
	    snapshot.network_tx_bytes || snapshot.network_rx_bytes ||
	    snapshot.storage_read_bytes || snapshot.storage_write_bytes ||
	    snapshot.io_read_chars || snapshot.io_write_chars ||
	    snapshot.accel_compute_ns || snapshot.accel_memory_bytes ||
	    snapshot.accel_submissions || snapshot.correlation ||
	    snapshot.reserved[0] || snapshot.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if ((snapshot.flags & AGI_LC_TENANT_FLAG_REQUIRE_SANDBOX) &&
	    (!READ_ONCE(session->sandbox_bound) ||
	     READ_ONCE(session->sandbox_state) != AGI_LC_SANDBOX_STATE_BOUND))
		return -EPERM;

	snapshot.session_id = session->session_id;
	snapshot.sandbox_binding_id = READ_ONCE(session->sandbox_bound) ?
		READ_ONCE(session->sandbox_binding_id) : 0;
	snapshot.sampled_at_ns = ktime_get_ns();
	for (i = 0; i < AGI_LC_AGENT_RECORDS; i++) {
		struct agi_lc_agent_record *record = &session->agents[i];
		struct agi_lc_resource_demand *demand;

		if (!record->valid)
			continue;
		snapshot.agent_count++;
		if (record->state != AGI_LC_AGENT_STATE_COMPLETED)
			snapshot.active_agent_count++;
		if (!record->resource_demand_valid)
			continue;
		demand = &record->resource_demand;
		snapshot.resource_mask |= demand->resource_mask;
		snapshot.measured_mask |= demand->enforced_mask;
		snapshot.unsupported_mask |= demand->unsupported_mask;
		snapshot.cpu_time_ns = agi_lc_sat_add_u64(snapshot.cpu_time_ns,
						  demand->observed_cpu_time_ns);
		snapshot.cpu_elapsed_ns = agi_lc_sat_add_u64(snapshot.cpu_elapsed_ns,
						     demand->observed_cpu_time_ns);
		snapshot.memory_current_bytes = agi_lc_sat_add_u64(
			snapshot.memory_current_bytes, demand->observed_memory_bytes);
		if (demand->memory_max_bytes)
			snapshot.memory_limit_bytes = agi_lc_sat_add_u64(
				snapshot.memory_limit_bytes, demand->memory_max_bytes);
		if (demand->memory_max_bytes &&
		    demand->observed_memory_bytes > demand->memory_max_bytes)
			snapshot.over_budget_mask |= AGI_LC_RESOURCE_RAM;
		snapshot.accel_compute_ns = agi_lc_sat_add_u64(
			snapshot.accel_compute_ns, demand->observed_accel_compute_ns);
		snapshot.accel_memory_bytes = agi_lc_sat_add_u64(
			snapshot.accel_memory_bytes, demand->observed_accel_memory_bytes);
		snapshot.accel_submissions = agi_lc_sat_add_u64(
			snapshot.accel_submissions, demand->observed_accel_submissions);
	}
	if (session->tenant_budget_valid) {
		snapshot.cpu_budget_ns = session->tenant_budget.cpu_budget_ns;
		if (session->tenant_budget.resource_mask & AGI_LC_RESOURCE_RAM)
			snapshot.memory_limit_bytes = session->tenant_budget.memory_limit_bytes;
		if ((session->tenant_budget.resource_mask & AGI_LC_RESOURCE_CPU) &&
		    snapshot.cpu_time_ns > session->tenant_budget.cpu_budget_ns)
			snapshot.over_budget_mask |= AGI_LC_RESOURCE_CPU;
		if ((session->tenant_budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
		    snapshot.memory_current_bytes > session->tenant_budget.memory_limit_bytes)
			snapshot.over_budget_mask |= AGI_LC_RESOURCE_RAM;
	}
	if (snapshot.flags & AGI_LC_TENANT_FLAG_INCLUDE_LIGHT_AGENTS)
		snapshot.light_agent_count = READ_ONCE(session->light_agent_count);
	spin_lock_irqsave(&session->queue_lock, flags);
	snapshot.generation = session->change_generation;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	if (copy_to_user((void __user *)arg, &snapshot, sizeof(snapshot)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_resource_demand(struct agi_lc_session *session,
						      unsigned long arg)

{
	struct agi_lc_resource_demand demand;
	struct agi_lc_agent_record *record;
	u32 enforced_mask = 0;
	u32 unsupported_mask = 0;
	u64 agent_id;
	int ret;

	if (copy_from_user(&demand, (void __user *)arg, sizeof(demand)))
		return -EFAULT;
	if (demand.size != sizeof(demand) || demand.flags || demand.agent_id ||
	    !demand.workload || demand.workload > AGI_LC_WORKLOAD_MAX ||
	    !demand.resource_mask ||
	    (demand.resource_mask & ~AGI_LC_RESOURCE_ALL) ||
	    demand.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    demand.latency_sensitive > 1 ||
	    demand.cpu_util_min > demand.cpu_util_max ||
	    demand.cpu_util_max > SCHED_CAPACITY_SCALE ||
	    demand.memory_min_bytes > demand.memory_max_bytes ||
	    demand.accel_min_bytes > demand.accel_max_bytes ||
	    demand.status || demand.enforced_mask || demand.unsupported_mask ||
	    demand.reserved32 || demand.observed_cpu_time_ns ||
	    demand.observed_memory_bytes || demand.observed_accel_compute_ns ||
	    demand.observed_accel_memory_bytes || demand.observed_accel_submissions ||
	    demand.generation || demand.reserved[0] || demand.reserved[1])
		return -EINVAL;
	if ((demand.resource_mask & AGI_LC_RESOURCE_CPU) &&
	    !demand.cpu_util_max)
		return -EINVAL;
	if ((demand.resource_mask & AGI_LC_RESOURCE_RAM) &&
	    demand.memory_max_bytes &&
	    (demand.memory_max_bytes & (PAGE_SIZE - 1)))
		return -EINVAL;
	if (!(demand.resource_mask & AGI_LC_RESOURCE_CPU) &&
	    (demand.cpu_util_min || demand.cpu_util_max))
		return -EINVAL;
	if (!(demand.resource_mask & AGI_LC_RESOURCE_RAM) &&
	    (demand.memory_min_bytes || demand.memory_max_bytes))
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	agent_id = faisal_task_get_agent(current);
	record = agi_lc_find_agent(session, agent_id);
	if (!record)
		return -ENOENT;

	if (session->tenant_budget_valid &&
	    (session->tenant_budget.resource_mask & AGI_LC_RESOURCE_RAM) &&
	    (demand.resource_mask & AGI_LC_RESOURCE_RAM) &&
	    demand.memory_max_bytes > session->tenant_budget.memory_limit_bytes)
		return -EDQUOT;

	if (demand.resource_mask & AGI_LC_RESOURCE_CPU) {
#ifdef CONFIG_UCLAMP_TASK
		struct sched_attr attr = {
			.size = sizeof(attr),
			.sched_policy = -1,
			.sched_flags = SCHED_FLAG_UTIL_CLAMP_MIN |
				       SCHED_FLAG_UTIL_CLAMP_MAX,
			.sched_util_min = demand.cpu_util_min,
			.sched_util_max = demand.cpu_util_max,
		};

		ret = sched_setattr_nocheck(current, &attr);
		if (ret)
			return ret;
		enforced_mask |= AGI_LC_RESOURCE_CPU;
#else
		unsupported_mask |= AGI_LC_RESOURCE_CPU;
#endif
	}

	if (demand.resource_mask & AGI_LC_RESOURCE_RAM) {
		if (demand.memory_max_bytes) {
			ret = faisal_task_set_memory_limit(current,
							 demand.memory_max_bytes >> PAGE_SHIFT);
			if (ret)
				return ret;
			enforced_mask |= AGI_LC_RESOURCE_RAM;
		} else {
			unsupported_mask |= AGI_LC_RESOURCE_RAM;
		}
	}

	unsupported_mask |= demand.resource_mask &
		(AGI_LC_RESOURCE_GPU | AGI_LC_RESOURCE_NPU |
		 AGI_LC_RESOURCE_VRAM | AGI_LC_RESOURCE_STORAGE |
		 AGI_LC_RESOURCE_NETWORK | AGI_LC_RESOURCE_IO);

	record->resource_demand = demand;
	record->resource_demand.agent_id = agent_id;
	record->resource_demand.enforced_mask = enforced_mask;
	record->resource_demand.unsupported_mask = unsupported_mask;
	record->resource_demand.status =
		!unsupported_mask && enforced_mask == demand.resource_mask ?
		AGI_LC_RESOURCE_STATUS_ENFORCED :
		(enforced_mask ? AGI_LC_RESOURCE_STATUS_PARTIAL :
		 AGI_LC_RESOURCE_STATUS_UNSUPPORTED);
	record->resource_demand.generation++;
	agi_lc_resource_observe(&record->resource_demand);
	record->resource_demand_valid = true;
	demand = record->resource_demand;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_RESOURCE_DEMAND, 0,
				 demand.correlation, demand.resource_mask);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &demand, sizeof(demand)))
		return -EFAULT;
	return 0;
}

static int agi_lc_get_resource_demand(struct agi_lc_session *session,
					      unsigned long arg)
{
	struct agi_lc_resource_demand demand;
	struct agi_lc_agent_record *record;

	if (copy_from_user(&demand, (void __user *)arg, sizeof(demand)))
		return -EFAULT;
	if (demand.size != sizeof(demand) || demand.flags || demand.agent_id ||
	    demand.workload || demand.resource_mask || demand.priority ||
	    demand.latency_sensitive || demand.deadline_ns || demand.cpu_util_min ||
	    demand.cpu_util_max || demand.memory_min_bytes || demand.memory_max_bytes ||
	    demand.accel_min_bytes || demand.accel_max_bytes || demand.storage_bytes_sec ||
	    demand.network_bytes_sec || demand.io_bytes_sec || demand.status ||
	    demand.enforced_mask || demand.unsupported_mask || demand.reserved32 ||
	    demand.observed_cpu_time_ns || demand.observed_memory_bytes ||
	    demand.observed_accel_compute_ns || demand.observed_accel_memory_bytes ||
	    demand.observed_accel_submissions || demand.generation ||
	    demand.correlation || demand.reserved[0] || demand.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	record = agi_lc_find_agent(session, faisal_task_get_agent(current));
	if (!record || !record->resource_demand_valid)
		return -ENOENT;
	agi_lc_resource_observe(&record->resource_demand);
	demand = record->resource_demand;
	if (copy_to_user((void __user *)arg, &demand, sizeof(demand)))
		return -EFAULT;
	return 0;
}

static struct agi_lc_accel_record *
agi_lc_find_accel_locked(u64 device_id)
{
	u32 i;

	for (i = 0; i < AGI_LC_ACCEL_DEVICES; i++)
		if (agi_lc_accel_devices[i].valid &&
		    agi_lc_accel_devices[i].device.device_id == device_id)
			return &agi_lc_accel_devices[i];
	return NULL;
}

static int agi_lc_accel_register(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_accel_device device;
	struct agi_lc_accel_record *record = NULL;
	u32 i;
	int ret;

	if (copy_from_user(&device, (void __user *)arg, sizeof(device)))
		return -EFAULT;
	if (device.size != sizeof(device) || device.flags || device.device_id ||
	    !device.type || device.type > AGI_LC_ACCEL_TYPE_MAX ||
	    (device.capabilities & ~AGI_LC_ACCEL_CAP_MAX) ||
	    (device.accounting_flags & ~AGI_LC_ACCEL_ACCOUNT_MAX) ||
	    (device.isolation_flags & ~AGI_LC_ACCEL_ISOLATION_MAX) ||
	    (device.coordination_flags & ~AGI_LC_ACCEL_COORD_MAX) ||
	    device.online || device.compute_ns || device.memory_bytes ||
	    device.submissions || device.next_device_id || !device.name[0] ||
	    !device.driver[0] || device.name[sizeof(device.name) - 1] ||
	    device.driver[sizeof(device.driver) - 1] ||
	    device.owner_session_id || device.owner_cgroup_id ||
	    device.owner_cgroup_generation || device.correlation == 0 ||
	    device.reserved[0] || device.reserved[1])
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if ((device.isolation_flags & AGI_LC_ACCEL_ISOLATION_TENANT_MEMORY) &&
	    (!session->tenant_cgroup || !(device.capabilities &
			AGI_LC_ACCEL_CAP_DEVICE_MEMORY) ||
	     !device.total_memory_bytes ||
	     device.available_memory_bytes > device.total_memory_bytes))
		return -EPERM;
	if (!(device.capabilities & AGI_LC_ACCEL_CAP_DEVICE_MEMORY) &&
	    (device.total_memory_bytes || device.available_memory_bytes))
		return -EOPNOTSUPP;

	mutex_lock(&agi_lc_accel_lock);
	for (i = 0; i < AGI_LC_ACCEL_DEVICES; i++)
		if (!agi_lc_accel_devices[i].valid) {
			record = &agi_lc_accel_devices[i];
			break;
		}
	if (!record) {
		ret = -ENOSPC;
		goto out_unlock;
	}
	device.device_id = atomic64_inc_return(&agi_lc_next_accel_device);
	device.online = 1;
	device.owner_session_id = session->session_id;
	device.owner_cgroup_id = session->tenant_cgroup_id;
	device.owner_cgroup_generation = session->tenant_cgroup_generation;
	record->device = device;
	record->accounted_memory_bytes = 0;
	record->valid = true;
	if (copy_to_user((void __user *)arg, &device, sizeof(device))) {
		record->valid = false;
		ret = -EFAULT;
		goto out_unlock;
	}
	ret = 0;
out_unlock:
	mutex_unlock(&agi_lc_accel_lock);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_ACCEL, 0,
					 device.correlation, device.device_id);
}

static int agi_lc_accel_unregister(struct agi_lc_session *session,
					   unsigned long arg)
{
	struct agi_lc_accel_device device;
	struct agi_lc_accel_record *record;
	int ret = 0;

	if (copy_from_user(&device, (void __user *)arg, sizeof(device)))
		return -EFAULT;
	if (device.size != sizeof(device) || device.flags || !device.device_id ||
	    device.type || device.capabilities || device.accounting_flags ||
	    device.isolation_flags || device.coordination_flags || device.online ||
	    device.total_memory_bytes || device.available_memory_bytes ||
	    device.compute_capacity || device.compute_ns || device.memory_bytes ||
	    device.submissions || device.next_device_id ||
	    memchr_inv(device.name, 0, sizeof(device.name)) ||
	    memchr_inv(device.driver, 0, sizeof(device.driver)) ||
	    device.reserved[0] || device.reserved[1])
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	mutex_lock(&agi_lc_accel_lock);
	record = agi_lc_find_accel_locked(device.device_id);
	if (!record) {
		ret = -ENOENT;
		goto out_unlock;
	}
	record->valid = false;
	record->device.online = 0;
	record->accounted_memory_bytes = 0;
out_unlock:
	mutex_unlock(&agi_lc_accel_lock);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_ACCEL, 0,
					 device.correlation, device.device_id);
}

static int agi_lc_accel_get_device(struct agi_lc_session *session,
					    unsigned long arg)
{
	struct agi_lc_accel_device query;
	struct agi_lc_accel_device result;
	u64 cursor;
	u64 next = 0;
	u32 i;
	bool found = false;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags ||
	    query.type || query.capabilities || query.accounting_flags ||
	    query.isolation_flags || query.coordination_flags || query.online ||
	    query.total_memory_bytes || query.available_memory_bytes ||
	    query.compute_capacity || query.compute_ns || query.memory_bytes ||
	    query.submissions || query.next_device_id ||
	    memchr_inv(query.name, 0, sizeof(query.name)) ||
	    memchr_inv(query.driver, 0, sizeof(query.driver)) ||
	    query.correlation || query.reserved[0] || query.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	cursor = query.device_id;
	mutex_lock(&agi_lc_accel_lock);
	for (i = 0; i < AGI_LC_ACCEL_DEVICES; i++) {
		if (!agi_lc_accel_devices[i].valid ||
		    agi_lc_accel_devices[i].device.device_id <= cursor)
			continue;
		if (!found || agi_lc_accel_devices[i].device.device_id <
			    result.device_id) {
			result = agi_lc_accel_devices[i].device;
			found = true;
		}
	}
	if (found)
		for (i = 0; i < AGI_LC_ACCEL_DEVICES; i++)
			if (agi_lc_accel_devices[i].valid &&
			    agi_lc_accel_devices[i].device.device_id > result.device_id &&
			    (!next || agi_lc_accel_devices[i].device.device_id < next))
				next = agi_lc_accel_devices[i].device.device_id;
	mutex_unlock(&agi_lc_accel_lock);
	if (!found)
		return -ENOENT;
	result.next_device_id = next;
	if (copy_to_user((void __user *)arg, &result, sizeof(result)))
		return -EFAULT;
	return 0;
}

static int agi_lc_accel_set_workload(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_accel_workload workload;
	struct agi_lc_accel_record *device;
	struct agi_lc_agent_record *agent;
	u64 agent_id;

	if (copy_from_user(&workload, (void __user *)arg, sizeof(workload)))
		return -EFAULT;
	if (workload.size != sizeof(workload) || workload.flags ||
	    !workload.device_id || workload.agent_id || !workload.workload ||
	    workload.workload > AGI_LC_WORKLOAD_MAX ||
	    workload.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    workload.latency_sensitive > 1 ||
	    (workload.isolation_flags & ~AGI_LC_ACCEL_ISOLATION_MAX) ||
	    (workload.coordination_flags & ~AGI_LC_ACCEL_COORD_MAX) ||
	    workload.state || workload.reserved32 || workload.compute_ns ||
	    workload.memory_bytes || workload.submissions ||
	    workload.tenant_cgroup_id || workload.tenant_cgroup_generation ||
	    workload.reserved[0] ||
	    workload.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	agent_id = faisal_task_get_agent(current);
	agent = agi_lc_find_agent(session, agent_id);
	if (!agent)
		return -ENOENT;
	mutex_lock(&agi_lc_accel_lock);
	device = agi_lc_find_accel_locked(workload.device_id);
	if (!device) {
		mutex_unlock(&agi_lc_accel_lock);
		return -ENODEV;
	}
	if (workload.isolation_flags & ~device->device.isolation_flags ||
	    workload.coordination_flags & ~device->device.coordination_flags) {
		mutex_unlock(&agi_lc_accel_lock);
		return -EOPNOTSUPP;
	}
	if (device->device.isolation_flags &
	    AGI_LC_ACCEL_ISOLATION_TENANT_MEMORY) {
		if (!session->tenant_cgroup ||
		    device->device.owner_session_id != session->session_id ||
		    device->device.owner_cgroup_id != session->tenant_cgroup_id ||
		    device->device.owner_cgroup_generation !=
			 session->tenant_cgroup_generation) {
			mutex_unlock(&agi_lc_accel_lock);
			return -EPERM;
		}
		workload.tenant_cgroup_id = session->tenant_cgroup_id;
		workload.tenant_cgroup_generation =
			session->tenant_cgroup_generation;
	}
	agent->accel_workload = workload;
	agent->accel_workload.agent_id = agent_id;
	agent->accel_workload.state = AGI_LC_ACCEL_WORKLOAD_BOUND;
	agi_lc_resource_observe(&agent->resource_demand);
	faisal_task_accel_get(current, &agent->accel_workload.compute_ns,
				      &agent->accel_workload.memory_bytes,
				      &agent->accel_workload.submissions);
	agent->accel_workload_valid = true;
	workload = agent->accel_workload;
	mutex_unlock(&agi_lc_accel_lock);
	if (copy_to_user((void __user *)arg, &workload, sizeof(workload)))
		return -EFAULT;
	return agi_lc_push_record(session, AGI_LC_EVENT_ACCEL_WORKLOAD, 0,
					 workload.correlation, workload.device_id);
}

static int agi_lc_accel_get_workload(struct agi_lc_session *session,
					     unsigned long arg)
{
	struct agi_lc_accel_workload query;
	struct agi_lc_agent_record *agent;

	if (copy_from_user(&query, (void __user *)arg, sizeof(query)))
		return -EFAULT;
	if (query.size != sizeof(query) || query.flags || query.device_id ||
	    query.agent_id || query.workload || query.queue_class || query.priority ||
	    query.latency_sensitive || query.deadline_ns || query.isolation_flags ||
	    query.coordination_flags || query.state || query.reserved32 ||
	    query.compute_ns || query.memory_bytes || query.submissions ||
	    query.tenant_cgroup_id || query.tenant_cgroup_generation ||
	    query.correlation || query.reserved[0] || query.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	agent = agi_lc_find_agent(session, faisal_task_get_agent(current));
	if (!agent || !agent->accel_workload_valid)
		return -ENOENT;
	faisal_task_accel_get(current, &agent->accel_workload.compute_ns,
				      &agent->accel_workload.memory_bytes,
				      &agent->accel_workload.submissions);
	query = agent->accel_workload;
	if (copy_to_user((void __user *)arg, &query, sizeof(query)))
		return -EFAULT;
	return 0;
}

static int agi_lc_accel_device_account_apply(
	struct agi_lc_session *session,
	struct agi_lc_accel_device_account *account, bool lock_held)
{
	struct agi_lc_accel_record *device;
	u64 agent_id;
	int ret;

	if (account->size != sizeof(*account) ||
	    (account->flags & ~AGI_LC_ACCEL_ACCOUNT_MAX) || !account->device_id ||
	    (!account->flags) ||
	    (!(account->flags & AGI_LC_ACCEL_ACCOUNT_COMPUTE) && account->compute_ns) ||
	    (!(account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) && account->memory_bytes) ||
	    (!(account->flags & AGI_LC_ACCEL_ACCOUNT_SUBMISSIONS) && account->submissions) ||
	    ((account->flags & AGI_LC_ACCEL_ACCOUNT_RELEASE) &&
	     (!(account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) ||
	      (account->flags & (AGI_LC_ACCEL_ACCOUNT_COMPUTE |
				 AGI_LC_ACCEL_ACCOUNT_SUBMISSIONS)))) ||
	    account->agent_id || account->tenant_cgroup_id ||
	    account->tenant_cgroup_generation || account->device_memory_limit_bytes ||
	    account->status || account->reserved32 || account->reserved[0] ||
	    account->reserved[1])
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	agent_id = faisal_task_get_agent(current);
	if (!lock_held)
		mutex_lock(&agi_lc_accel_lock);
	device = agi_lc_find_accel_locked(account->device_id);
	if (!device) {
		if (!lock_held)
			mutex_unlock(&agi_lc_accel_lock);
		return -ENODEV;
	}
	if (device->device.isolation_flags &
	    AGI_LC_ACCEL_ISOLATION_TENANT_MEMORY) {
		if (!session->tenant_cgroup ||
		    device->device.owner_session_id != session->session_id ||
		    device->device.owner_cgroup_id != session->tenant_cgroup_id ||
		    device->device.owner_cgroup_generation !=
			 session->tenant_cgroup_generation) {
			if (!lock_held)
				mutex_unlock(&agi_lc_accel_lock);
			return -EPERM;
		}
		if ((account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) &&
		    (account->flags & AGI_LC_ACCEL_ACCOUNT_RELEASE) &&
		    account->memory_bytes > device->accounted_memory_bytes) {
			account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_RELEASE_DENIED;
			if (!lock_held)
				mutex_unlock(&agi_lc_accel_lock);
			return -ERANGE;
		}
		if ((account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) &&
		    !(account->flags & AGI_LC_ACCEL_ACCOUNT_RELEASE) &&
		    (account->memory_bytes > device->device.total_memory_bytes ||
		     device->accounted_memory_bytes >
			 device->device.total_memory_bytes - account->memory_bytes)) {
			account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_MEMORY_DENIED;
			if (!lock_held)
				mutex_unlock(&agi_lc_accel_lock);
			return -EDQUOT;
		}
		account->tenant_cgroup_id = session->tenant_cgroup_id;
		account->tenant_cgroup_generation =
			session->tenant_cgroup_generation;
		account->device_memory_limit_bytes =
			device->device.total_memory_bytes;
	}
	if ((account->flags & AGI_LC_ACCEL_ACCOUNT_COMPUTE) &&
	    account->compute_ns > U64_MAX - device->device.compute_ns) {
		account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_UNSUPPORTED;
		if (!lock_held)
			mutex_unlock(&agi_lc_accel_lock);
		return -EOVERFLOW;
	}
	if ((account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) &&
	    (!(account->flags & AGI_LC_ACCEL_ACCOUNT_RELEASE) &&
	     (account->memory_bytes > U64_MAX - device->device.memory_bytes ||
	      account->memory_bytes > U64_MAX - device->accounted_memory_bytes))) {
		account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_UNSUPPORTED;
		if (!lock_held)
			mutex_unlock(&agi_lc_accel_lock);
		return -EOVERFLOW;
	}
	if ((account->flags & AGI_LC_ACCEL_ACCOUNT_SUBMISSIONS) &&
	    account->submissions > U64_MAX - device->device.submissions) {
		account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_UNSUPPORTED;
		if (!lock_held)
			mutex_unlock(&agi_lc_accel_lock);
		return -EOVERFLOW;
	}
	if (account->flags & AGI_LC_ACCEL_ACCOUNT_COMPUTE) {
		device->device.compute_ns += account->compute_ns;
		faisal_task_accel_account(current, account->compute_ns, 0, 0);
	}
	if (account->flags & AGI_LC_ACCEL_ACCOUNT_MEMORY) {
		if (account->flags & AGI_LC_ACCEL_ACCOUNT_RELEASE) {
			device->device.memory_bytes -= account->memory_bytes;
			device->accounted_memory_bytes -= account->memory_bytes;
			faisal_task_accel_release(current, 0, account->memory_bytes, 0);
		} else {
			device->device.memory_bytes += account->memory_bytes;
			device->accounted_memory_bytes += account->memory_bytes;
			faisal_task_accel_account(current, 0, account->memory_bytes, 0);
		}
	}
	if (account->flags & AGI_LC_ACCEL_ACCOUNT_SUBMISSIONS) {
		device->device.submissions += account->submissions;
		faisal_task_accel_account(current, 0, 0, account->submissions);
	}
	account->agent_id = agent_id;
	account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_ACCEPTED;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_ACCEL, 0,
				 account->correlation, account->device_id);
	if (ret)
		account->status = AGI_LC_ACCEL_ACCOUNT_STATUS_TELEMETRY_LOST;
	if (!lock_held)
		mutex_unlock(&agi_lc_accel_lock);
	return ret;
}

static int agi_lc_accel_device_account(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_accel_device_account account;
	int ret;

	if (copy_from_user(&account, (void __user *)arg, sizeof(account)))
		return -EFAULT;
	ret = agi_lc_accel_device_account_apply(session, &account, false);
	if (copy_to_user((void __user *)arg, &account, sizeof(account)))
		return -EFAULT;
	return ret;
}

static int agi_lc_accel_device_account_batch(struct agi_lc_session *session,
						unsigned long arg)
{
	struct agi_lc_accel_device_account_batch batch;
	struct agi_lc_accel_device_account *accounts;
	size_t bytes;
	u32 i;
	int ret = 0;

	if (copy_from_user(&batch, (void __user *)arg, sizeof(batch)))
		return -EFAULT;
	if (batch.size != sizeof(batch) || batch.flags || !batch.entries_ptr ||
	    !batch.entry_count ||
	    batch.entry_count > AGI_LC_ACCEL_ACCOUNT_BATCH_MAX ||
	    batch.completed || batch.status || batch.reserved32 ||
	    batch.reserved[0] || batch.reserved[1])
		return -EINVAL;
	bytes = (size_t)batch.entry_count * sizeof(*accounts);
	accounts = memdup_user(u64_to_user_ptr(batch.entries_ptr), bytes);
	if (IS_ERR(accounts))
		return PTR_ERR(accounts);
	mutex_lock(&agi_lc_accel_lock);
	for (i = 0; i < batch.entry_count; i++) {
		ret = agi_lc_accel_device_account_apply(session, &accounts[i], true);
		batch.completed = i + 1;
		if (ret)
			break;
	}
	mutex_unlock(&agi_lc_accel_lock);
	if (batch.completed)
		batch.status = accounts[batch.completed - 1].status;
	if (copy_to_user(u64_to_user_ptr(batch.entries_ptr),
			 accounts, bytes))
		ret = -EFAULT;
	kfree(accounts);
	if (copy_to_user((void __user *)arg, &batch, sizeof(batch)))
		return -EFAULT;
	return ret;
}

#ifdef CONFIG_UCLAMP_TASK
static u32 agi_lc_deadline_urgency(u64 deadline_ns)
{
	u64 now_ns;
	u64 slack_ns;

	if (!deadline_ns)
		return 0;
	now_ns = ktime_get_ns();
	if (deadline_ns <= now_ns)
		return SCHED_CAPACITY_SCALE;
	slack_ns = deadline_ns - now_ns;
	if (slack_ns <= 5ULL * NSEC_PER_MSEC)
		return SCHED_CAPACITY_SCALE;
	if (slack_ns <= 20ULL * NSEC_PER_MSEC)
		return (SCHED_CAPACITY_SCALE * 3U) / 4U;
	if (slack_ns <= 100ULL * NSEC_PER_MSEC)
		return SCHED_CAPACITY_SCALE / 2U;
	return 0;
}
#endif

static int agi_lc_set_sched_hint(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_sched_hint hint;
	struct agi_lc_agent_record *record;
	u64 agent_id;
	int ret;

	if (copy_from_user(&hint, (void __user *)arg, sizeof(hint)))
		return -EFAULT;
	if (hint.size != sizeof(hint) || hint.flags || hint.agent_id ||
	    hint.priority > AGI_LC_SCHED_PRIORITY_MAX ||
	    hint.state > AGI_LC_AGENT_STATE_MAX ||
	    hint.unblock_credit > AGI_LC_SCHED_PRIORITY_MAX ||
	    hint.latency_sensitive > 1 || hint.util_min > hint.util_max ||
	    hint.util_max > SCHED_CAPACITY_SCALE || hint.reserved ||
	    hint.reserved2[0] || hint.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
#ifdef CONFIG_UCLAMP_TASK
	{
		struct sched_attr attr = {
			.size = sizeof(attr),
			.sched_policy = -1,
			.sched_flags = SCHED_FLAG_UTIL_CLAMP_MIN |
					       SCHED_FLAG_UTIL_CLAMP_MAX,
		};
		u32 urgency = agi_lc_deadline_urgency(hint.deadline_ns);

		if (hint.latency_sensitive)
			urgency = max(urgency, SCHED_CAPACITY_SCALE / 2U);
		urgency = max(urgency, hint.unblock_credit);
		attr.sched_util_min = max(hint.util_min, urgency);
		attr.sched_util_max = hint.util_max;
		if (attr.sched_util_min > attr.sched_util_max)
			return -EINVAL;
		ret = sched_setattr_nocheck(current, &attr);
		if (ret)
			return ret;
	}
#else
	return -EOPNOTSUPP;
#endif
	agent_id = faisal_task_get_agent(current);
	record = agi_lc_find_agent(session, agent_id);
	if (!record)
		return -ENOENT;
	record->priority = hint.priority;
	record->state = hint.state;
	record->dependency_count = hint.dependency_count;
	record->unblock_credit = hint.unblock_credit;
	record->deadline_ns = hint.deadline_ns;
	record->latency_sensitive = hint.latency_sensitive;
	record->util_min = hint.util_min;
	record->util_max = hint.util_max;
	hint.agent_id = agent_id;
	ret = agi_lc_push_record(session, AGI_LC_EVENT_SCHED_HINT, 0,
				 hint.correlation,
				 ((u64)hint.priority << 32) | hint.state);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &hint, sizeof(hint)))
		return -EFAULT;
	return 0;
}

static int agi_lc_get_sched_hint(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_sched_hint hint;
	struct agi_lc_agent_record *record;

	if (copy_from_user(&hint, (void __user *)arg, sizeof(hint)))
		return -EFAULT;
	if (hint.size != sizeof(hint) || hint.flags || hint.agent_id ||
	    hint.priority || hint.state || hint.dependency_count ||
	    hint.unblock_credit || hint.deadline_ns || hint.latency_sensitive ||
	    hint.util_min || hint.util_max || hint.reserved ||
	    hint.correlation || hint.reserved2[0] || hint.reserved2[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	record = agi_lc_find_agent(session, faisal_task_get_agent(current));
	if (!record)
		return -ENOENT;
	hint.agent_id = record->agent_id;
	hint.priority = record->priority;
	hint.state = record->state;
	hint.dependency_count = record->dependency_count;
	hint.unblock_credit = record->unblock_credit;
	hint.deadline_ns = record->deadline_ns;
	hint.latency_sensitive = record->latency_sensitive;
	hint.util_min = record->util_min;
	hint.util_max = record->util_max;
	if (copy_to_user((void __user *)arg, &hint, sizeof(hint)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_agent(struct agi_lc_session *session,
					 unsigned long arg)
{
	struct agi_lc_agent agent;
	struct agi_lc_agent_record *existing;
	struct task_struct *group;
	struct task_struct *task;
	int ret;

	if (copy_from_user(&agent, (void __user *)arg, sizeof(agent)))
		return -EFAULT;
	if (agent.size != sizeof(agent) || agent.flags || !agent.agent_id ||
	    agent.parent_agent || agent.reserved[0] || agent.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	existing = agi_lc_find_agent(session, agent.agent_id);
	if (existing) {
		if (existing->owner_tgid != task_tgid_nr(current))
			return -EACCES;
		ret = faisal_task_set_agent(current, agent.agent_id);
		if (ret)
			return ret;
		agent.parent_agent = existing->parent_agent;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_AGENT, 0,
					 agent.correlation, agent.agent_id);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &agent, sizeof(agent)))
			return -EFAULT;
		return 0;
	}

	rcu_read_lock();
	for_each_process_thread(group, task) {
		if (task != current &&
		    faisal_task_get_lineage(task) == session->session_id &&
		    faisal_task_get_agent(task) == agent.agent_id) {
			rcu_read_unlock();
			return -EEXIST;
		}
	}
	rcu_read_unlock();

	agent.parent_agent = faisal_task_get_agent(current);
	ret = agi_lc_register_agent(session, agent.agent_id,
					    agent.parent_agent,
					    task_tgid_nr(current));
	if (ret)
		return ret;
	ret = faisal_task_set_agent(current, agent.agent_id);
	if (ret) {
		agi_lc_unregister_agent(session, agent.agent_id);
		return ret;
	}
	ret = agi_lc_push_record(session, AGI_LC_EVENT_AGENT, 0,
					 agent.correlation, agent.agent_id);
	if (ret)
		return ret;
	if (copy_to_user((void __user *)arg, &agent, sizeof(agent)))
		return -EFAULT;
	return 0;
}

static int agi_lc_send(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_message message;
	unsigned long flags;

	if (copy_from_user(&message, (void __user *)arg, sizeof(message)))
		return -EFAULT;
	if (message.size != sizeof(message) || message.flags ||
	    message.reserved || message.length > AGI_LC_MESSAGE_MAX ||
	    !message.target_agent || message.sender_lineage ||
	    message.sender_agent || message.sender_pid || message.sender_tgid)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!faisal_task_get_agent(current) ||
	    !agi_lc_find_agent(session, message.target_agent))
		return -EACCES;
	message.sender_lineage = session->session_id;
	message.sender_agent = faisal_task_get_agent(current);
	message.sender_pid = task_pid_nr(current);
	message.sender_tgid = task_tgid_nr(current);
	spin_lock_irqsave(&session->queue_lock, flags);
	if (session->msg_count == AGI_LC_MESSAGE_SLOTS) {
		spin_unlock_irqrestore(&session->queue_lock, flags);
		return -EAGAIN;
	}
	session->messages[session->msg_tail] = message;
	session->msg_tail = (session->msg_tail + 1) % AGI_LC_MESSAGE_SLOTS;
	session->msg_count++;
	spin_unlock_irqrestore(&session->queue_lock, flags);
	wake_up_interruptible(&session->msg_wait);
	return agi_lc_push_record(session, AGI_LC_EVENT_MESSAGE, 0,
					  message.correlation, message.length);
}

static int agi_lc_recv(struct agi_lc_session *session, unsigned long arg)
{
	struct agi_lc_message request;
	struct agi_lc_message message;
	unsigned long flags;
	long remaining;
	long timeout;

	if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
		return -EFAULT;
	if (request.size != sizeof(request) || request.flags ||
	    request.length || request.reserved || request.sender_lineage ||
	    request.sender_agent || request.target_agent || request.sender_pid ||
	    request.sender_tgid)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
	if (!faisal_task_get_agent(current))
		return -EACCES;
	timeout = request.timeout_ns ? nsecs_to_jiffies(request.timeout_ns) :
					  MAX_SCHEDULE_TIMEOUT;
	remaining = timeout;
	for (;;) {
		u32 i;
		bool found = false;

		spin_lock_irqsave(&session->queue_lock, flags);
		for (i = 0; i < session->msg_count; i++) {
			u32 index = (session->msg_head + i) %
					AGI_LC_MESSAGE_SLOTS;

			if (!agi_lc_message_matches(&session->messages[index],
							faisal_task_get_agent(current)))
				continue;
			message = session->messages[index];
			while (i + 1 < session->msg_count) {
				u32 next = (index + 1) % AGI_LC_MESSAGE_SLOTS;

				session->messages[index] = session->messages[next];
				index = next;
				i++;
			}
			session->msg_tail = (session->msg_tail +
					AGI_LC_MESSAGE_SLOTS - 1) %
					AGI_LC_MESSAGE_SLOTS;
			session->msg_count--;
			found = true;
			break;
		}
		if (found) {
			spin_unlock_irqrestore(&session->queue_lock, flags);
			break;
		}
		if (session->revoked) {
			spin_unlock_irqrestore(&session->queue_lock, flags);
			return -ESHUTDOWN;
		}
		spin_unlock_irqrestore(&session->queue_lock, flags);

		remaining = wait_event_interruptible_timeout(session->msg_wait,
				agi_lc_has_message_for_agent(session,
							faisal_task_get_agent(current)),
				remaining);
		if (remaining < 0)
			return remaining;
		if (!remaining)
			return -ETIMEDOUT;
	}
	wake_up_interruptible(&session->msg_wait);
	message.timeout_ns = 0;
	if (copy_to_user((void __user *)arg, &message, sizeof(message)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_gate(struct agi_lc_session *session,
				    unsigned long arg)
{
	struct agi_lc_gate gate;

	if (copy_from_user(&gate, (void __user *)arg, sizeof(gate)))
		return -EFAULT;
	if (gate.size != sizeof(gate) || gate.open > 1 || gate.timeout_ns ||
	    gate.reserved[0] || gate.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	WRITE_ONCE(session->gate_open, !!gate.open);
	wake_up_interruptible(&session->gate_wait);
	return agi_lc_push_record(session, AGI_LC_EVENT_GATE, 0,
					  gate.correlation, gate.open);
}

static int agi_lc_wait_gate(struct agi_lc_session *session,
				     unsigned long arg)
{
	struct agi_lc_gate gate;
	long waited;
	long timeout;

	if (copy_from_user(&gate, (void __user *)arg, sizeof(gate)))
		return -EFAULT;
	if (gate.size != sizeof(gate) || gate.open || gate.reserved[0] ||
	    gate.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	timeout = gate.timeout_ns ? nsecs_to_jiffies(gate.timeout_ns) :
					 MAX_SCHEDULE_TIMEOUT;
	waited = wait_event_interruptible_timeout(session->gate_wait,
			READ_ONCE(session->gate_open) || READ_ONCE(session->revoked),
			timeout);
	if (waited < 0)
		return waited;
	if (READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (!waited)
		return -ETIMEDOUT;

	gate.open = 1;
	if (copy_to_user((void __user *)arg, &gate, sizeof(gate)))
		return -EFAULT;
	return 0;
}

static int agi_lc_set_phase(struct agi_lc_session *session,
				    unsigned long arg)
{
	struct agi_lc_phase phase;
	int ret;

	if (copy_from_user(&phase, (void __user *)arg, sizeof(phase)))
		return -EFAULT;
	if (phase.size != sizeof(phase) || phase.flags || phase.reserved ||
	    phase.reserved2[0] || phase.reserved2[1] ||
	    phase.phase > AGI_LC_PHASE_MAX)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	ret = faisal_task_set_phase(current, phase.phase);
	if (ret)
		return ret;
	return agi_lc_push_record(session, AGI_LC_EVENT_PHASE, 0,
					  phase.correlation, phase.phase);
}

static int agi_lc_get_domain(struct agi_lc_session *session,
					unsigned long arg)
{
	struct agi_lc_domain domain;

	if (copy_from_user(&domain, (void __user *)arg, sizeof(domain)))
		return -EFAULT;
	if (domain.size != sizeof(domain) || domain.flags ||
	    domain.cgroup_id || domain.lineage_id || domain.agent_id ||
	    domain.reserved[0] || domain.reserved[1])
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;
#if IS_ENABLED(CONFIG_CGROUPS)
	domain.cgroup_id = cgroup_id(task_dfl_cgroup(current));
#else
	return -EOPNOTSUPP;
#endif
	domain.lineage_id = session->session_id;
	domain.agent_id = faisal_task_get_agent(current);
	if (copy_to_user((void __user *)arg, &domain, sizeof(domain)))
		return -EFAULT;
	return 0;
}

static void agi_lc_domain_mask_from_uapi(cpumask_t *mask,
						 const u64 words[AGI_LC_EXEC_DOMAIN_CPU_WORDS])
{
	u32 cpu;

	cpumask_clear(mask);
	for (cpu = 0; cpu < nr_cpu_ids &&
	     cpu < AGI_LC_EXEC_DOMAIN_CPU_WORDS * 64; cpu++)
		if (words[cpu / 64] & (1ULL << (cpu % 64)))
			cpumask_set_cpu(cpu, mask);
}

static void agi_lc_domain_mask_to_uapi(
		const cpumask_t *mask,
		u64 words[AGI_LC_EXEC_DOMAIN_CPU_WORDS])
{
	u32 cpu;

	memset(words, 0, sizeof(u64) * AGI_LC_EXEC_DOMAIN_CPU_WORDS);
	for_each_cpu(cpu, mask)
		if (cpu < AGI_LC_EXEC_DOMAIN_CPU_WORDS * 64)
			words[cpu / 64] |= 1ULL << (cpu % 64);
}

static int agi_lc_execution_domain_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_execution_domain domain;
	struct agi_lc_execution_domain_record *slot = NULL;
	cpumask_t requested, applied, housekeeping;
	u64 supported_requests = AGI_LC_EXEC_DOMAIN_REQUEST_NOHZ_FULL |
		AGI_LC_EXEC_DOMAIN_REQUEST_IRQ_ISOLATION |
		AGI_LC_EXEC_DOMAIN_REQUEST_PREEMPT_RT |
		AGI_LC_EXEC_DOMAIN_REQUIRE_NOHZ_FULL |
		AGI_LC_EXEC_DOMAIN_REQUIRE_IRQ_ISOLATION |
		AGI_LC_EXEC_DOMAIN_REQUIRE_PREEMPT_RT;
	u64 available = AGI_LC_EXEC_DOMAIN_FEATURE_AFFINITY |
		AGI_LC_EXEC_DOMAIN_FEATURE_HOUSEKEEPING;
	u32 i;
	int ret = 0;

	if (copy_from_user(&domain, (void __user *)arg, sizeof(domain)))
		return -EFAULT;
	if (domain.size != sizeof(domain) || domain.flags ||
	    domain.reserved32 || domain.reserved[0] || domain.reserved[1] ||
	    domain.operation < AGI_LC_EXEC_DOMAIN_CREATE ||
	    domain.operation > AGI_LC_EXEC_DOMAIN_RELEASE ||
	    domain.requested_features & ~supported_requests ||
	    !domain.correlation || !session->session_id ||
	    READ_ONCE(session->revoked))
		return -EINVAL;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	if (domain.operation == AGI_LC_EXEC_DOMAIN_CREATE) {
		if (domain.domain_id || domain.capability || domain.generation ||
		    domain.state || domain.status || domain.owner_agent ||
		    domain.owner_tgid || domain.available_features ||
		    domain.unsupported_features || domain.jitter_sequence)
			return -EINVAL;
		if (nr_cpu_ids > AGI_LC_EXEC_DOMAIN_CPU_WORDS * 64)
			return -E2BIG;
		agi_lc_domain_mask_from_uapi(&requested, domain.requested_cpus);
		if (cpumask_empty(&requested) ||
		    !cpumask_subset(&requested, cpu_online_mask))
			return -EINVAL;
		cpumask_and(&applied, &requested, cpu_online_mask);
		cpumask_andnot(&housekeeping, cpu_online_mask, &applied);
		if (cpumask_empty(&housekeeping))
			return -EINVAL;
		domain.unsupported_features = 0;
		if (domain.requested_features &
		    (AGI_LC_EXEC_DOMAIN_REQUEST_NOHZ_FULL |
		     AGI_LC_EXEC_DOMAIN_REQUIRE_NOHZ_FULL))
			domain.unsupported_features |= AGI_LC_EXEC_DOMAIN_FEATURE_NOHZ_FULL;
		if (domain.requested_features &
		    (AGI_LC_EXEC_DOMAIN_REQUEST_IRQ_ISOLATION |
		     AGI_LC_EXEC_DOMAIN_REQUIRE_IRQ_ISOLATION))
			domain.unsupported_features |= AGI_LC_EXEC_DOMAIN_FEATURE_IRQ_ISOLATION;
		if (domain.requested_features &
		    (AGI_LC_EXEC_DOMAIN_REQUEST_PREEMPT_RT |
		     AGI_LC_EXEC_DOMAIN_REQUIRE_PREEMPT_RT))
			domain.unsupported_features |= AGI_LC_EXEC_DOMAIN_FEATURE_PREEMPT_RT;
		if (domain.requested_features &
		    (AGI_LC_EXEC_DOMAIN_REQUIRE_NOHZ_FULL |
		     AGI_LC_EXEC_DOMAIN_REQUIRE_IRQ_ISOLATION |
		     AGI_LC_EXEC_DOMAIN_REQUIRE_PREEMPT_RT))
			return -EOPNOTSUPP;
		ret = set_cpus_allowed_ptr(current, &applied);
		if (ret)
			return ret;
		for (i = 0; i < AGI_LC_EXECUTION_DOMAIN_RECORDS; i++)
			if (!session->execution_domains[i].valid) {
				slot = &session->execution_domains[i];
				break;
			}
		if (!slot)
			return -ENOSPC;
		if (++session->execution_domain_next_id == U64_MAX)
			return -EOVERFLOW;
		memset(slot, 0, sizeof(*slot));
		slot->valid = true;
		slot->domain = domain;
		slot->domain.domain_id = session->execution_domain_next_id;
		slot->domain.capability = get_random_u64();
		while (!slot->domain.capability)
			slot->domain.capability = get_random_u64();
		slot->domain.generation = 1;
		slot->domain.state = AGI_LC_EXEC_DOMAIN_STATE_ACTIVE;
		slot->domain.status = 0;
		slot->domain.owner_agent = faisal_task_get_agent(current);
		slot->domain.owner_tgid = task_tgid_nr(current);
		slot->domain.available_features = available;
		slot->domain.unsupported_features = domain.unsupported_features;
		agi_lc_domain_mask_to_uapi(&applied,
					    slot->domain.applied_cpus);
		agi_lc_domain_mask_to_uapi(&housekeeping,
					    slot->domain.housekeeping_cpus);
		slot->domain.jitter_sequence = ++session->change_generation;
		domain = slot->domain;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_SCHED_HINT,
					 0, domain.correlation, domain.domain_id);
	} else {
		if (!domain.domain_id || !domain.capability)
			return -EINVAL;
		for (i = 0; i < AGI_LC_EXECUTION_DOMAIN_RECORDS; i++)
			if (session->execution_domains[i].valid &&
			    session->execution_domains[i].domain.domain_id ==
				domain.domain_id &&
			    session->execution_domains[i].domain.capability ==
				domain.capability) {
				slot = &session->execution_domains[i];
				break;
			}
		if (!slot)
			return -EACCES;
		if (domain.operation == AGI_LC_EXEC_DOMAIN_RELEASE) {
			slot->domain.state = AGI_LC_EXEC_DOMAIN_STATE_RELEASED;
			slot->domain.generation++;
			domain = slot->domain;
			slot->valid = false;
			ret = agi_lc_push_record(session, AGI_LC_EVENT_SCHED_HINT,
						 -ECANCELED, domain.correlation,
						 domain.domain_id);
		} else {
			domain = slot->domain;
			domain.operation = AGI_LC_EXEC_DOMAIN_QUERY;
		}
	}
	if (copy_to_user((void __user *)arg, &domain, sizeof(domain)))
		return -EFAULT;
	return ret;
}

static int agi_lc_tensor_transport_control(struct agi_lc_session *session,
						 unsigned long arg)
{
	struct agi_lc_tensor_transport transport;
	struct agi_lc_memory_record *memory;
	struct agi_lc_transport_record *slot = NULL;
	u32 access = AGI_LC_MEMORY_ACCESS_READ;
	u32 i;
	int ret = 0;

	if (copy_from_user(&transport, (void __user *)arg, sizeof(transport)))
		return -EFAULT;
	if (transport.size != sizeof(transport) || transport.reserved[0] ||
	    transport.reserved[1] || transport.flags & ~(
		AGI_LC_TRANSPORT_REQUIRE_ZERO_COPY |
		AGI_LC_TRANSPORT_REQUIRE_INTEGRITY) ||
	    transport.transport_kind < AGI_LC_TRANSPORT_RDMA ||
	    transport.transport_kind > AGI_LC_TRANSPORT_SOCKET_RING ||
	    transport.collective_kind > AGI_LC_TRANSPORT_ALLGATHER ||
	    transport.direction < AGI_LC_TRANSPORT_SEND ||
	    transport.direction > AGI_LC_TRANSPORT_BIDIRECTIONAL ||
	    transport.operation < AGI_LC_TENSOR_TRANSPORT_REGISTER ||
	    transport.operation > AGI_LC_TENSOR_TRANSPORT_REVOKE ||
	    !transport.correlation)
		return -EINVAL;
	if (!session->session_id || READ_ONCE(session->revoked))
		return -ESHUTDOWN;
	if (faisal_task_get_lineage(current) != session->session_id)
		return -EPERM;

	if (transport.operation == AGI_LC_TENSOR_TRANSPORT_REGISTER) {
		if (transport.transport_id || transport.capability ||
		    transport.generation || transport.state || transport.status ||
		    transport.completion_sequence || !transport.region_id ||
		    !transport.region_capability || !transport.region_generation ||
		    !transport.bytes || !transport.chunk_bytes ||
		    transport.chunk_bytes > transport.bytes ||
		    transport.source_device_id == transport.target_device_id ||
		    (transport.collective_kind == AGI_LC_TRANSPORT_COLLECTIVE_NONE &&
		     (transport.participants != 1 || transport.participant_index)) ||
		    (transport.collective_kind != AGI_LC_TRANSPORT_COLLECTIVE_NONE &&
		     (transport.participants < 2 ||
		      transport.participant_index >= transport.participants)))
			return -EINVAL;
		if (transport.flags & AGI_LC_TRANSPORT_REQUIRE_ZERO_COPY)
			return -EOPNOTSUPP;
		if ((transport.flags & AGI_LC_TRANSPORT_REQUIRE_INTEGRITY) &&
		    (!transport.provenance_id || !transport.provenance_sequence))
			return -EINVAL;
		if (transport.direction == AGI_LC_TRANSPORT_RECV)
			access = AGI_LC_MEMORY_ACCESS_WRITE;
		else if (transport.direction == AGI_LC_TRANSPORT_BIDIRECTIONAL)
			access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE;
		mutex_lock(&agi_lc_memory_lock);
		memory = agi_lc_memory_find_locked(session, transport.region_id);
		if (!memory || !memory->tensor_valid || memory->revoked ||
		    memory->generation != transport.region_generation ||
		    transport.bytes > memory->size_bytes ||
		    !agi_lc_memory_authorized_locked(session, memory,
						      transport.region_capability, access)) {
			mutex_unlock(&agi_lc_memory_lock);
			return -EACCES;
		}
		mutex_unlock(&agi_lc_memory_lock);
		for (i = 0; i < AGI_LC_TRANSPORT_RECORDS; i++)
			if (!session->transports[i].valid) {
				slot = &session->transports[i];
				break;
			}
		if (!slot)
			return -ENOSPC;
		if (++session->transport_next_id == U64_MAX)
			return -EOVERFLOW;
		memset(slot, 0, sizeof(*slot));
		slot->valid = true;
		slot->transport = transport;
		slot->transport.transport_id = session->transport_next_id;
		slot->transport.capability = get_random_u64();
		while (!slot->transport.capability)
			slot->transport.capability = get_random_u64();
		slot->transport.generation = 1;
		slot->transport.state = AGI_LC_TRANSPORT_STATE_ACTIVE;
		transport = slot->transport;
		ret = agi_lc_push_record(session, AGI_LC_EVENT_NETWORK_POLICY,
					 0, transport.correlation,
					 transport.transport_id);
	} else {
		if (!transport.transport_id || !transport.capability)
			return -EINVAL;
		for (i = 0; i < AGI_LC_TRANSPORT_RECORDS; i++)
			if (session->transports[i].valid &&
			    session->transports[i].transport.transport_id ==
				transport.transport_id &&
			    session->transports[i].transport.capability ==
				transport.capability) {
				slot = &session->transports[i];
				break;
			}
		if (!slot)
			return -EACCES;
		if (transport.operation == AGI_LC_TENSOR_TRANSPORT_REVOKE) {
			slot->transport.state = AGI_LC_TRANSPORT_STATE_REVOKED;
			slot->transport.generation++;
			transport = slot->transport;
			slot->valid = false;
			ret = agi_lc_push_record(session, AGI_LC_EVENT_NETWORK_POLICY,
						 -ECANCELED, transport.correlation,
						 transport.transport_id);
		} else {
			transport = slot->transport;
			transport.operation = AGI_LC_TENSOR_TRANSPORT_QUERY;
			ret = 0;
		}
	}
	if (copy_to_user((void __user *)arg, &transport, sizeof(transport)))
		return -EFAULT;
	return ret == -ESHUTDOWN ? ret : 0;
}

static long agi_lc_ioctl(struct file *file, unsigned int command,
				 unsigned long arg)
{
	struct agi_lc_session *session = file->private_data;
	unsigned long flags;
	long ret = 0;

	if (_IOC_TYPE(command) != AGI_LC_IOC_MAGIC)
		return -ENOTTY;
	mutex_lock(&session->ioctl_lock);
	if (session->sandbox_bound && command != AGI_LC_SANDBOX &&
	    !agi_lc_sandbox_matches_current(&session->sandbox_binding) &&
	    !agi_lc_tenant_cgroup_matches_current(session)) {
		session->sandbox_state = AGI_LC_SANDBOX_STATE_REVOKED;
		mutex_unlock(&session->ioctl_lock);
		return -EXDEV;
	}
	switch (command) {
	case AGI_LC_SANDBOX:
		ret = agi_lc_sandbox_ioctl(session, arg);
		break;
	case AGI_LC_CREATE: {
		struct agi_lc_create create;

		if (copy_from_user(&create, (void __user *)arg, sizeof(create))) {
			ret = -EFAULT;
			break;
		}
		if (create.size != sizeof(create) || create.flags ||
		    create.reserved[0] || create.reserved[1] ||
		    session->session_id) {
			ret = -EINVAL;
			break;
		}
		session->session_id = atomic64_inc_return(&agi_lc_next_session);
		session->owner_pid = task_pid_nr(current);
		session->owner_tgid = task_tgid_nr(current);
		ret = agi_lc_register_agent(session, session->session_id, 0,
					    task_tgid_nr(current));
		if (ret) {
			session->session_id = 0;
			break;
		}
		create.session_id = session->session_id;
		if (copy_to_user((void __user *)arg, &create, sizeof(create)))
			ret = -EFAULT;
		break;
	}
	case AGI_LC_BEGIN:
	case AGI_LC_END:
		ret = agi_lc_copy_event(session, command, arg);
		break;
	case AGI_LC_CANCEL:
		ret = agi_lc_cancel(session, arg);
		break;
	case AGI_LC_GET_STATS:
		ret = agi_lc_get_stats(session, arg);
		break;
	case AGI_LC_GET_SELF_STATE:
		ret = agi_lc_get_self_state(session, arg);
		break;
	case AGI_LC_SET_PHASE:
		ret = agi_lc_set_phase(session, arg);
		break;
	case AGI_LC_MEMORY_HINT:
		ret = agi_lc_memory_hint(session, arg);
		break;
	case AGI_LC_SET_PERF:
		ret = agi_lc_set_perf(session, arg);
		break;
	case AGI_LC_SET_GATE:
		ret = agi_lc_set_gate(session, arg);
		break;
	case AGI_LC_WAIT_GATE:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_wait_gate(session, arg);
	case AGI_LC_SEND:
		ret = agi_lc_send(session, arg);
		break;
	case AGI_LC_SET_AGENT:
		ret = agi_lc_set_agent(session, arg);
		break;
	case AGI_LC_LEASE_ACQUIRE:
		ret = agi_lc_lease_acquire(session, arg);
		break;
	case AGI_LC_LEASE_CHECK:
		ret = agi_lc_lease_check(session, arg);
		break;
	case AGI_LC_LEASE_REVOKE:
		ret = agi_lc_lease_revoke(session, arg);
		break;
	case AGI_LC_INTENT_LEASE:
		ret = agi_lc_intent_lease_control(session, arg);
		break;
	case AGI_LC_RECV:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_recv(session, arg);
	case AGI_LC_EXPERIENCE:
		ret = agi_lc_experience(session, arg);
		break;
	case AGI_LC_RECORD_EXPERIENCE:
		ret = agi_lc_record_experience(session, arg);
		break;
	case AGI_LC_GET_EXPERIENCE:
		ret = agi_lc_get_experience(session, arg);
		break;
	case AGI_LC_PUBLISH_ARTIFACT:
		ret = agi_lc_publish_artifact(session, arg);
		break;
	case AGI_LC_GET_ARTIFACT:
		ret = agi_lc_get_artifact(session, arg);
		break;
	case AGI_LC_ACCEL_ACCOUNT:
		ret = agi_lc_accel_account(session, arg);
		break;
	case AGI_LC_ACCEL_GET:
		ret = agi_lc_accel_get(session, arg);
		break;
	case AGI_LC_SUBSCRIBE:
		ret = agi_lc_subscribe(session, arg);
		break;
	case AGI_LC_EVENT_BACKPRESSURE:
		ret = agi_lc_event_backpressure(session, arg);
		break;
	case AGI_LC_SET_WORLD_SUBSCRIPTION:
		ret = agi_lc_set_world_subscription(session, arg);
		break;
	case AGI_LC_GET_WORLD_SUBSCRIPTION:
		ret = agi_lc_get_world_subscription(session, arg);
		break;
	case AGI_LC_CHECKPOINT:
		ret = agi_lc_checkpoint(session, arg);
		break;
	case AGI_LC_SET_BUDGET:
		ret = agi_lc_set_budget(session, arg);
		break;
	case AGI_LC_GET_BUDGET:
		ret = agi_lc_get_budget(session, arg);
		break;
	case AGI_LC_SET_MEMORY_BUDGET:
		ret = agi_lc_set_memory_budget(session, arg);
		break;
	case AGI_LC_GET_MEMORY_BUDGET:
		ret = agi_lc_get_memory_budget(session, arg);
		break;
	case AGI_LC_EXPORT_CHECKPOINT:
		ret = agi_lc_export_checkpoint(session, arg);
		break;
	case AGI_LC_IMPORT_CHECKPOINT:
		ret = agi_lc_import_checkpoint(session, arg);
		break;
	case AGI_LC_ATTACH_TASK:
		if (!session->session_id)
			ret = -EINVAL;
		else if (READ_ONCE(session->revoked))
			ret = -ESHUTDOWN;
		else
			ret = faisal_task_attach_lineage(current,
							session->session_id);
		break;
	case AGI_LC_DETACH_TASK:
		if (arg)
			ret = -EINVAL;
		else
			ret = faisal_prctl_clear_lineage();
		break;
	case AGI_LC_REVOKE: {
		struct agi_lc_revoke revoke;
		u32 i;

		if (copy_from_user(&revoke, (void __user *)arg, sizeof(revoke))) {
			ret = -EFAULT;
			break;
		}
		if (revoke.size != sizeof(revoke) || revoke.reserved[0] ||
		    revoke.reserved[1] || !session->session_id) {
			ret = -EINVAL;
			break;
		}
		spin_lock_irqsave(&session->queue_lock, flags);
		session->revoked = true;
		spin_unlock_irqrestore(&session->queue_lock, flags);
		for (i = 0; i < AGI_LC_LEASE_MAX; i++)
			session->leases[i].active = false;
		for (i = 0; i < AGI_LC_INTENT_LEASE_RECORDS; i++) {
			session->intent_leases[i].revoked = true;
			session->intent_leases[i].lease.status =
				AGI_LC_INTENT_STATUS_REVOKED;
		}
		session->recovery_invalidated = true;
		agi_lc_memory_release_session(session, false);

		agi_lc_artifact_release_session(session, false);
		memset(session->persistent_memory_records, 0, sizeof(session->persistent_memory_records));
		wake_up_interruptible(&session->read_wait);
		break;
	}
	case AGI_LC_GET_DOMAIN:
		ret = agi_lc_get_domain(session, arg);
		break;
	case AGI_LC_VERIFY_CHECKPOINT:
		ret = agi_lc_verify_checkpoint(session, arg);
		break;
	case AGI_LC_GET_AGENT:
		ret = agi_lc_get_agent(session, arg);
		break;
	case AGI_LC_SET_SCHED_HINT:
		ret = agi_lc_set_sched_hint(session, arg);
		break;
	case AGI_LC_GET_SCHED_HINT:
		ret = agi_lc_get_sched_hint(session, arg);
		break;
	case AGI_LC_SET_RESOURCE_DEMAND:
		ret = agi_lc_set_resource_demand(session, arg);
		break;
	case AGI_LC_GET_RESOURCE_DEMAND:
		ret = agi_lc_get_resource_demand(session, arg);
		break;
	case AGI_LC_GET_RESOURCE_SNAPSHOT:
		ret = agi_lc_get_resource_snapshot(session, arg);
		break;
	case AGI_LC_GET_TENANT_SNAPSHOT:
		ret = agi_lc_get_tenant_snapshot(session, arg);
		break;
	case AGI_LC_TENANT_BUDGET:
		ret = agi_lc_tenant_budget_control(session, arg);
		break;
	case AGI_LC_TENANT_CGROUP:
		ret = agi_lc_tenant_cgroup_control(session, arg);
		break;
	case AGI_LC_TENANT_CPU_POLICY:
		ret = agi_lc_tenant_cpu_policy_control(session, arg);
		break;
	case AGI_LC_ACCEL_REGISTER:
		ret = agi_lc_accel_register(session, arg);
		break;
	case AGI_LC_ACCEL_UNREGISTER:
		ret = agi_lc_accel_unregister(session, arg);
		break;
	case AGI_LC_ACCEL_GET_DEVICE:
		ret = agi_lc_accel_get_device(session, arg);
		break;
	case AGI_LC_ACCEL_SET_WORKLOAD:
		ret = agi_lc_accel_set_workload(session, arg);
		break;
	case AGI_LC_ACCEL_GET_WORKLOAD:
		ret = agi_lc_accel_get_workload(session, arg);
		break;
	case AGI_LC_ACCEL_DEVICE_ACCOUNT:
		ret = agi_lc_accel_device_account(session, arg);
		break;
	case AGI_LC_ACCEL_DEVICE_ACCOUNT_BATCH:
		ret = agi_lc_accel_device_account_batch(session, arg);
		break;
	case AGI_LC_CHECKPOINT_MANIFEST:
		ret = agi_lc_checkpoint_manifest(session, arg);
		break;
	case AGI_LC_RECOVERY:
		ret = agi_lc_recovery(session, arg);
		break;
	case AGI_LC_AUTONOMY_CONTROL:
		ret = agi_lc_autonomy_control(session, arg);
		break;

	case AGI_LC_LIGHT_AGENT_REGISTER:
		ret = agi_lc_light_register(session, arg);
		break;
	case AGI_LC_LIGHT_AGENT_UNREGISTER:
		ret = agi_lc_light_unregister(session, arg);
		break;
	case AGI_LC_LIGHT_AGENT_GET:
		ret = agi_lc_light_get(session, arg);
		break;
	case AGI_LC_LIGHT_AGENT_UPDATE:
		ret = agi_lc_light_update(session, arg);
		break;
	case AGI_LC_LIGHT_AGENT_SEND:
		ret = agi_lc_light_send(session, arg);
		break;
	case AGI_LC_LIGHT_AGENT_RECV:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_light_recv(session, arg);
	case AGI_LC_LIGHT_AGENT_WAIT:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_light_wait(session, arg);
	case AGI_LC_LIGHT_AGENT_LIST:
		ret = agi_lc_light_list(session, arg);
		break;
	case AGI_LC_CAPABILITY_GRANT:
		ret = agi_lc_capability_grant(session, arg);
		break;
	case AGI_LC_CAPABILITY_REVOKE:
		ret = agi_lc_capability_revoke(session, arg);
		break;
	case AGI_LC_CAPABILITY_GET:
		ret = agi_lc_capability_get(session, arg);
		break;
	case AGI_LC_CAPABILITY_CHECK:
		ret = agi_lc_capability_check(session, arg);
		break;
	case AGI_LC_GET_IDENTITY:
		ret = agi_lc_get_identity(session, arg);
		break;
	case AGI_LC_GET_ATTRIBUTION:
		ret = agi_lc_get_attribution(session, arg);
		break;
	case AGI_LC_PROVENANCE_PUBLISH:
		ret = agi_lc_provenance_publish(session, arg);
		break;
	case AGI_LC_PROVENANCE_QUERY:
		ret = agi_lc_provenance_query(session, arg);
		break;
	case AGI_LC_IPC_CHANNEL_CREATE:
		ret = agi_lc_ipc_channel_create(session, arg);
		break;
	case AGI_LC_IPC_CHANNEL_CLOSE:
		ret = agi_lc_ipc_channel_close(session, arg);
		break;
	case AGI_LC_IPC_SEND:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_ipc_send(session, arg);
	case AGI_LC_IPC_RECV:
		mutex_unlock(&session->ioctl_lock);
		return agi_lc_ipc_recv(session, arg);
	case AGI_LC_IPC_CANCEL:
		ret = agi_lc_ipc_cancel(session, arg);
		break;
	case AGI_LC_CANCEL_CONTROL:
		ret = agi_lc_cancel_control(session, arg);
		break;
	case AGI_LC_NETWORK_POLICY:
		ret = agi_lc_network_policy_control(session, arg);
		break;
	case AGI_LC_KNOWLEDGE:
		ret = agi_lc_knowledge_control(session, arg);
		break;
	case AGI_LC_BROWSER:
		ret = agi_lc_browser_control(session, arg);
		break;
	case AGI_LC_MEMORY_RECORD:
		ret = agi_lc_persistent_memory_control(session, arg);
		break;
	case AGI_LC_WORLD_SYNC:
		ret = agi_lc_world_sync(session, arg);
		break;
	case AGI_LC_TEMPORAL:
		ret = agi_lc_temporal_control(session, arg);
		break;
	case AGI_LC_REFLECTION:
		ret = agi_lc_reflection_control(session, arg);
		break;
	case AGI_LC_OBSERVABILITY:
		ret = agi_lc_observability_control(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_CREATE:
		ret = agi_lc_memory_region_create(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_SHARE:
		ret = agi_lc_memory_region_share(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_ATTACH:
		ret = agi_lc_memory_region_attach(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_GET:
		ret = agi_lc_memory_region_get(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_SNAPSHOT:
		ret = agi_lc_memory_region_snapshot(session, arg);
		break;
	case AGI_LC_MEMORY_REGION_REVOKE:
		ret = agi_lc_memory_region_revoke(session, arg);
		break;
	case AGI_LC_TENSOR_POLICY:
		ret = agi_lc_tensor_policy_control(session, arg);
		break;
	case AGI_LC_ADAPTIVE_MEMORY_POLICY:
		ret = agi_lc_adaptive_memory_policy_control(session, arg);
		break;
	case AGI_LC_GRAPH_NODE:
		ret = agi_lc_graph_node_control(session, arg);
		break;
	case AGI_LC_COMPUTE_CONTEXT:
		ret = agi_lc_compute_context_control(session, arg);
		break;
	case AGI_LC_PROVENANCE_BINDING:
		ret = agi_lc_provenance_binding_control(session, arg);
		break;
	case AGI_LC_TENSOR_TRANSPORT:
		ret = agi_lc_tensor_transport_control(session, arg);
		break;
	case AGI_LC_EXECUTION_DOMAIN:
		ret = agi_lc_execution_domain_control(session, arg);
		break;
	case AGI_LC_GRAPH_TELEMETRY:
		ret = agi_lc_graph_telemetry_control(session, arg);
		break;
	case AGI_LC_POWER_POLICY:
		ret = agi_lc_power_policy_control(session, arg);
		break;

	case AGI_LC_GET_INFO: {
		struct agi_lc_info info;

		if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
			ret = -EFAULT;
			break;
		}
		if (info.size != sizeof(info) || info.reserved[0] ||
		    info.reserved[1]) {
			ret = -EINVAL;
			break;
		}
		info.abi_version = AGI_LC_ABI_VERSION;
		info.session_id = session->session_id;
		info.owner_pid = session->owner_pid;
		info.owner_tgid = session->owner_tgid;
		info.dropped_records = session->dropped_records;
		if (copy_to_user((void __user *)arg, &info, sizeof(info)))
			ret = -EFAULT;
		break;
	}
	default:
		ret = -ENOTTY;
		break;
	}
	mutex_unlock(&session->ioctl_lock);
	return ret;
}

static const struct file_operations agi_lc_fops = {
	.owner = THIS_MODULE,
	.open = agi_lc_open,
	.release = agi_lc_release,
	.read = agi_lc_read,
	.poll = agi_lc_poll,
	.unlocked_ioctl = agi_lc_ioctl,
	.compat_ioctl = agi_lc_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice agi_lc_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = AGI_LC_DEVICE_NAME,
	.fops = &agi_lc_fops,
	.mode = 0600,
};

module_misc_device(agi_lc_miscdev);

MODULE_DESCRIPTION("FAISAL AGI lifecycle session device");
MODULE_AUTHOR("FAISAL Project");
MODULE_LICENSE("GPL");
