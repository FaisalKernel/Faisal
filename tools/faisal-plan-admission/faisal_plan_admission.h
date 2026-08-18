#ifndef FAISAL_PLAN_ADMISSION_H
#define FAISAL_PLAN_ADMISSION_H

#include <stddef.h>
#include <stdint.h>

#define FPA_ABI_VERSION 1U
#define FPA_DIGEST_SIZE 32U
#define FPA_MAX_NODES 64U
#define FPA_MAX_DEPENDENCIES 8U
#define FPA_MAX_REASON 192U
#define FPA_RISK_APPROVAL 700000U
#define FPA_RISK_IRREVERSIBLE 900000U
#define FPA_FLAG_MODEL_PROPOSAL (1U << 0)
#define FPA_FLAG_VERIFIED_INPUT (1U << 1)
#define FPA_FLAG_IRREVERSIBLE (1U << 2)
#define FPA_FLAGS_ALL (FPA_FLAG_MODEL_PROPOSAL | FPA_FLAG_VERIFIED_INPUT | FPA_FLAG_IRREVERSIBLE)

enum fpa_status {
	FPA_OK = 0,
	FPA_ERR_ARGUMENT = -1,
	FPA_ERR_LIMIT = -2,
	FPA_ERR_DEPENDENCY = -3,
	FPA_ERR_CYCLE = -4,
	FPA_ERR_CAPABILITY = -5,
	FPA_ERR_BUDGET = -6,
	FPA_ERR_APPROVAL = -7,
	FPA_ERR_TAMPER = -8,
	FPA_ERR_OVERFLOW = -9,
	FPA_ERR_CONFLICT = -10
};

struct fpa_node {
	uint32_t node_id;
	uint32_t dependency_count;
	uint32_t dependency_ids[FPA_MAX_DEPENDENCIES];
	uint32_t priority;
	uint32_t risk_ppm;
	uint64_t duration_ns;
	uint64_t cpu_budget_ns;
	uint64_t cost_budget_micro;
	uint64_t required_capability_mask;
	uint32_t flags;
	uint32_t reserved;
	uint8_t action_digest[FPA_DIGEST_SIZE];
};

struct fpa_plan {
	uint32_t abi_version;
	uint32_t reserved0;
	uint64_t objective_id;
	uint64_t plan_generation;
	uint64_t deadline_ns;
	uint64_t cpu_budget_ns;
	uint64_t cost_budget_micro;
	uint64_t available_capability_mask;
	uint32_t node_count;
	uint32_t flags;
	struct fpa_node nodes[FPA_MAX_NODES];
	uint8_t context_digest[FPA_DIGEST_SIZE];
};

struct fpa_admission {
	uint64_t objective_id;
	uint64_t plan_generation;
	uint64_t critical_path_ns;
	uint64_t total_duration_ns;
	uint64_t total_cpu_budget_ns;
	uint64_t total_cost_budget_micro;
	uint64_t approval_node_mask;
	uint64_t irreversible_node_mask;
	uint64_t required_capability_mask;
	uint64_t slack_min_ns;
	uint32_t topological_count;
	uint32_t highest_risk_ppm;
	uint32_t approval_required;
	uint32_t admission_state;
	uint32_t violation_mask;
	uint32_t reserved;
	uint32_t topological_order[FPA_MAX_NODES];
	uint64_t earliest_finish_ns[FPA_MAX_NODES];
	uint64_t slack_ns[FPA_MAX_NODES];
	uint8_t plan_digest[FPA_DIGEST_SIZE];
	char reason[FPA_MAX_REASON];
};

#define FPA_ADMISSION_REJECTED 1U
#define FPA_ADMISSION_ADMITTED 2U
#define FPA_VIOLATION_DEADLINE (1U << 0)
#define FPA_VIOLATION_CPU_BUDGET (1U << 1)
#define FPA_VIOLATION_COST_BUDGET (1U << 2)
#define FPA_VIOLATION_CAPABILITY (1U << 3)
#define FPA_VIOLATION_APPROVAL (1U << 4)
#define FPA_VIOLATION_EMPTY (1U << 5)
#define FPA_VIOLATION_CYCLE (1U << 6)
#define FPA_VIOLATION_CONFLICT (1U << 7)

int fpa_validate_plan(const struct fpa_plan *plan, struct fpa_admission *out);
int fpa_verify_admission(const struct fpa_plan *plan,
			 const struct fpa_admission *admission);
int fpa_find_node(const struct fpa_plan *plan, uint32_t node_id,
		  uint32_t *index_out);
int fpa_plan_digest(const struct fpa_plan *plan,
		   uint8_t digest[FPA_DIGEST_SIZE]);

#endif
