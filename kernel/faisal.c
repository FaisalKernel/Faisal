// SPDX-License-Identifier: GPL-2.0
/*
 * FAISAL task-state substrate reconstructed on the verified Linux base.
 * Semantic reasoning, model output, and policy decisions remain in userspace.
 */
#include <linux/faisal.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>

#define FAISAL_TASK_STATE_MAX 1024

struct faisal_task_state {
	struct task_struct *task;
	u64 lineage_id;
	u64 agent_id;
	u32 phase;
	u64 budget_ns;
	u64 started_ns;
	u64 memory_limit_pages;
	bool cancelled;
	bool resources_revoked;
	u64 net_policy_id;
	u64 net_family_mask;
	u64 net_type_mask;
	u64 net_operation_mask;
	u64 net_policy_flags;
	u64 net_max_sockets;
	u64 net_max_tx_bytes;
	u64 net_max_rx_bytes;
	u64 net_socket_count;
	u64 net_tx_bytes;
	u64 net_rx_bytes;
	u64 net_socket_creates;
	u64 net_denied;
	u64 net_generation;
	u64 accel_compute_ns;
	u64 accel_memory_bytes;
	u64 accel_submissions;
};

static DEFINE_SPINLOCK(faisal_state_lock);
static struct faisal_task_state faisal_states[FAISAL_TASK_STATE_MAX];

static struct faisal_task_state *faisal_find_locked(struct task_struct *task,
						 bool create)
{
	unsigned int i;
	struct faisal_task_state *free_state = NULL;

	for (i = 0; i < FAISAL_TASK_STATE_MAX; i++) {
		if (faisal_states[i].task == task)
			return &faisal_states[i];
		if (!faisal_states[i].task && !free_state)
			free_state = &faisal_states[i];
	}
	if (!create || !free_state)
		return NULL;
	memset(free_state, 0, sizeof(*free_state));
	free_state->task = task;
	free_state->started_ns = ktime_get_ns();
	return free_state;
}

int faisal_task_attach_lineage(struct task_struct *task, u64 lineage_id)
{
	unsigned long flags;
	struct faisal_task_state *state;
	if (!task || !lineage_id)
		return -EINVAL;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->lineage_id = lineage_id;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_attach_lineage);

int faisal_prctl_clear_lineage(void)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(current, false);
	if (state)
		state->lineage_id = 0;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(faisal_prctl_clear_lineage);

u64 faisal_task_get_lineage(struct task_struct *task)
{
	unsigned long flags;
	u64 value = 0;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state)
		value = state->lineage_id;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return value;
}
EXPORT_SYMBOL_GPL(faisal_task_get_lineage);

u32 faisal_task_get_phase(struct task_struct *task)
{
	unsigned long flags;
	u32 value = 0;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state)
		value = state->phase;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return value;
}
EXPORT_SYMBOL_GPL(faisal_task_get_phase);

int faisal_task_set_phase(struct task_struct *task, u32 phase)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->phase = phase;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_set_phase);

int faisal_task_set_agent(struct task_struct *task, u64 agent_id)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->agent_id = agent_id;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_set_agent);

u64 faisal_task_get_agent(struct task_struct *task)
{
	unsigned long flags;
	u64 value = 0;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state)
		value = state->agent_id;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return value;
}
EXPORT_SYMBOL_GPL(faisal_task_get_agent);

int faisal_task_set_budget(struct task_struct *task, u64 budget_ns)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state) {
		state->budget_ns = budget_ns;
		state->started_ns = ktime_get_ns();
	}
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_set_budget);

void faisal_task_get_budget(struct task_struct *task, u64 *budget_ns,
			    u64 *elapsed_ns, bool *exhausted)
{
	unsigned long flags;
	struct faisal_task_state *state;
	u64 now = ktime_get_ns(), start = 0, budget = 0;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state) {
		budget = state->budget_ns;
		start = state->started_ns;
	}
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	if (budget_ns) *budget_ns = budget;
	if (elapsed_ns) *elapsed_ns = start && now >= start ? now - start : 0;
	if (exhausted) *exhausted = budget && start && now >= start && now - start >= budget;
}
EXPORT_SYMBOL_GPL(faisal_task_get_budget);

int faisal_task_set_memory_limit(struct task_struct *task, u64 limit_pages)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->memory_limit_pages = limit_pages;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_set_memory_limit);

void faisal_task_get_memory_limit(struct task_struct *task, u64 *limit_pages,
				  u64 *current_pages, bool *exceeded)
{
	unsigned long flags;
	struct faisal_task_state *state;
	u64 limit = 0, current_pages_value = 0;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state)
		limit = state->memory_limit_pages;
	if (task->mm)
		current_pages_value = get_mm_rss(task->mm);
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	if (limit_pages) *limit_pages = limit;
	if (current_pages) *current_pages = current_pages_value;
	if (exceeded) *exceeded = limit && current_pages_value > limit;
}
EXPORT_SYMBOL_GPL(faisal_task_get_memory_limit);

bool faisal_task_cancelled(struct task_struct *task)
{
	unsigned long flags;
	bool value = false;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state)
		value = state->cancelled;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return value;
}
EXPORT_SYMBOL_GPL(faisal_task_cancelled);

void faisal_task_request_cancel(struct task_struct *task)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->cancelled = true;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_request_cancel);

void faisal_task_request_cancel_ex(struct task_struct *task, u32 mode,
					 u64 deadline_ns, u32 priority,
					 bool revoke_resources)
{
	faisal_task_request_cancel(task);
	if (revoke_resources)
		faisal_task_revoke_resources(task);
}
EXPORT_SYMBOL_GPL(faisal_task_request_cancel_ex);

void faisal_task_revoke_resources(struct task_struct *task)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state)
		state->resources_revoked = true;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_revoke_resources);

int faisal_task_net_policy_apply(struct task_struct *task, u64 policy_id,
						 u64 family_mask, u64 type_mask,
						 u64 operation_mask, u64 policy_flags,
						 u64 max_sockets, u64 max_tx_bytes,
						 u64 max_rx_bytes)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state) {
		state->net_policy_id = policy_id;
		state->net_family_mask = family_mask;
		state->net_type_mask = type_mask;
		state->net_operation_mask = operation_mask;
		state->net_policy_flags = policy_flags;
		state->net_max_sockets = max_sockets;
		state->net_max_tx_bytes = max_tx_bytes;
		state->net_max_rx_bytes = max_rx_bytes;
		state->net_generation++;
	}
	spin_unlock_irqrestore(&faisal_state_lock, flags);
	return state ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(faisal_task_net_policy_apply);

void faisal_task_net_policy_get(struct task_struct *task, u64 *policy_id,
						 u64 *family_mask, u64 *type_mask,
						 u64 *operation_mask, u32 *policy_flags,
						 u32 *max_sockets, u64 *max_tx_bytes,
						 u64 *max_rx_bytes, u64 *socket_count,
						 u64 *tx_bytes, u64 *rx_bytes,
						 u64 *socket_creates, u64 *denied,
						 u64 *generation)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (policy_id) *policy_id = state ? state->net_policy_id : 0;
	if (family_mask) *family_mask = state ? state->net_family_mask : 0;
	if (type_mask) *type_mask = state ? state->net_type_mask : 0;
	if (operation_mask) *operation_mask = state ? state->net_operation_mask : 0;
	if (policy_flags) *policy_flags = state ? state->net_policy_flags : 0;
	if (max_sockets) *max_sockets = state ? state->net_max_sockets : 0;
	if (max_tx_bytes) *max_tx_bytes = state ? state->net_max_tx_bytes : 0;
	if (max_rx_bytes) *max_rx_bytes = state ? state->net_max_rx_bytes : 0;
	if (socket_count) *socket_count = state ? state->net_socket_count : 0;
	if (tx_bytes) *tx_bytes = state ? state->net_tx_bytes : 0;
	if (rx_bytes) *rx_bytes = state ? state->net_rx_bytes : 0;
	if (socket_creates) *socket_creates = state ? state->net_socket_creates : 0;
	if (denied) *denied = state ? state->net_denied : 0;
	if (generation) *generation = state ? state->net_generation : 0;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_net_policy_get);

void faisal_task_net_policy_revoke(struct task_struct *task)
{
	faisal_task_net_policy_apply(task, 0, 0, 0, 0, 0, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(faisal_task_net_policy_revoke);

void faisal_task_net_usage_get(struct task_struct *task, u64 *tx_bytes,
						       u64 *rx_bytes, u64 *socket_creates,
						       u64 *denied, bool *available)
{
	if (tx_bytes) *tx_bytes = 0;
	if (rx_bytes) *rx_bytes = 0;
	if (socket_creates) *socket_creates = 0;
	if (denied) *denied = 0;
	if (available) *available = false;
}
EXPORT_SYMBOL_GPL(faisal_task_net_usage_get);

void faisal_task_accel_account(struct task_struct *task, u64 compute_ns,
				       u64 memory_bytes, u64 submissions)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, true);
	if (state) {
		state->accel_compute_ns += compute_ns;
		state->accel_memory_bytes += memory_bytes;
		state->accel_submissions += submissions;
	}
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_accel_account);

void faisal_task_accel_release(struct task_struct *task, u64 compute_ns,
				       u64 memory_bytes, u64 submissions)
{
	unsigned long flags;
	struct faisal_task_state *state;

	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (state) {
		state->accel_compute_ns = compute_ns > state->accel_compute_ns ?
			0 : state->accel_compute_ns - compute_ns;
		state->accel_memory_bytes = memory_bytes > state->accel_memory_bytes ?
			0 : state->accel_memory_bytes - memory_bytes;
		state->accel_submissions = submissions > state->accel_submissions ?
			0 : state->accel_submissions - submissions;
	}
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_accel_release);

void faisal_task_accel_get(struct task_struct *task, u64 *compute_ns,
				   u64 *memory_bytes, u64 *submissions)
{
	unsigned long flags;
	struct faisal_task_state *state;
	spin_lock_irqsave(&faisal_state_lock, flags);
	state = faisal_find_locked(task, false);
	if (compute_ns) *compute_ns = state ? state->accel_compute_ns : 0;
	if (memory_bytes) *memory_bytes = state ? state->accel_memory_bytes : 0;
	if (submissions) *submissions = state ? state->accel_submissions : 0;
	spin_unlock_irqrestore(&faisal_state_lock, flags);
}
EXPORT_SYMBOL_GPL(faisal_task_accel_get);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FAISAL task-state substrate");
