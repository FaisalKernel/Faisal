/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FAISAL_H
#define _LINUX_FAISAL_H

#include <linux/types.h>

struct task_struct;

int faisal_task_attach_lineage(struct task_struct *task, u64 lineage_id);
int faisal_prctl_clear_lineage(void);
u64 faisal_task_get_lineage(struct task_struct *task);

u32 faisal_task_get_phase(struct task_struct *task);
int faisal_task_set_phase(struct task_struct *task, u32 phase);

int faisal_task_set_agent(struct task_struct *task, u64 agent_id);
u64 faisal_task_get_agent(struct task_struct *task);

int faisal_task_set_budget(struct task_struct *task, u64 budget_ns);
void faisal_task_get_budget(struct task_struct *task, u64 *budget_ns,
			    u64 *elapsed_ns, bool *exhausted);
int faisal_task_set_memory_limit(struct task_struct *task, u64 limit_pages);
void faisal_task_get_memory_limit(struct task_struct *task, u64 *limit_pages,
				  u64 *current_pages, bool *exceeded);

bool faisal_task_cancelled(struct task_struct *task);
void faisal_task_request_cancel(struct task_struct *task);
void faisal_task_request_cancel_ex(struct task_struct *task, u32 mode,
					 u64 deadline_ns, u32 priority,
					 bool revoke_resources);
void faisal_task_revoke_resources(struct task_struct *task);

int faisal_task_net_policy_apply(struct task_struct *task, u64 policy_id,
					 u64 family_mask, u64 type_mask,
					 u64 operation_mask, u64 policy_flags,
					 u64 max_sockets, u64 max_tx_bytes,
					 u64 max_rx_bytes);
void faisal_task_net_policy_get(struct task_struct *task, u64 *policy_id,
					 u64 *family_mask, u64 *type_mask,
					 u64 *operation_mask, u32 *policy_flags,
					 u32 *max_sockets, u64 *max_tx_bytes,
					 u64 *max_rx_bytes, u64 *socket_count,
					 u64 *tx_bytes, u64 *rx_bytes,
					 u64 *socket_creates, u64 *denied,
					 u64 *generation);
void faisal_task_net_policy_revoke(struct task_struct *task);
void faisal_task_net_usage_get(struct task_struct *task, u64 *tx_bytes,
					       u64 *rx_bytes, u64 *socket_creates,
					       u64 *denied, bool *available);

void faisal_task_accel_account(struct task_struct *task, u64 compute_ns,
				       u64 memory_bytes, u64 submissions);
void faisal_task_accel_get(struct task_struct *task, u64 *compute_ns,
				   u64 *memory_bytes, u64 *submissions);

#endif
