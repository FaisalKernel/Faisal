#include "../../faisal-plan-admission/faisal_plan_admission.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void seed_plan(struct fpa_plan *plan)
{
	memset(plan, 0, sizeof(*plan));
	plan->abi_version = FPA_ABI_VERSION;
	plan->objective_id = 100U;
	plan->plan_generation = 1U;
	plan->deadline_ns = 1000U;
	plan->cpu_budget_ns = 500U;
	plan->cost_budget_micro = 100U;
	plan->available_capability_mask = 0x3U;
	plan->node_count = 3U;
	plan->flags = FPA_FLAG_VERIFIED_INPUT;
	plan->nodes[0].node_id = 1U;
	plan->nodes[0].priority = 5U;
	plan->nodes[0].risk_ppm = 100000U;
	plan->nodes[0].duration_ns = 100U;
	plan->nodes[0].cpu_budget_ns = 100U;
	plan->nodes[0].cost_budget_micro = 10U;
	plan->nodes[0].required_capability_mask = 0x1U;
	plan->nodes[1].node_id = 2U;
	plan->nodes[1].dependency_count = 1U;
	plan->nodes[1].dependency_ids[0] = 1U;
	plan->nodes[1].priority = 3U;
	plan->nodes[1].risk_ppm = 200000U;
	plan->nodes[1].duration_ns = 200U;
	plan->nodes[1].cpu_budget_ns = 100U;
	plan->nodes[1].cost_budget_micro = 20U;
	plan->nodes[1].required_capability_mask = 0x1U;
	plan->nodes[2].node_id = 3U;
	plan->nodes[2].dependency_count = 1U;
	plan->nodes[2].dependency_ids[0] = 1U;
	plan->nodes[2].priority = 4U;
	plan->nodes[2].risk_ppm = 300000U;
	plan->nodes[2].duration_ns = 50U;
	plan->nodes[2].cpu_budget_ns = 50U;
	plan->nodes[2].cost_budget_micro = 5U;
	plan->nodes[2].required_capability_mask = 0x2U;
}

int main(void)
{
	struct fpa_plan plan;
	struct fpa_admission admission;
	struct fpa_admission tampered;
	uint8_t digest[FPA_DIGEST_SIZE];

	seed_plan(&plan);
	assert(fpa_validate_plan(&plan, &admission) == FPA_OK);
	assert(admission.admission_state == FPA_ADMISSION_ADMITTED);
	assert(admission.topological_count == 3U);
	assert(admission.topological_order[0] == 1U);
	assert(admission.topological_order[1] == 3U);
	assert(admission.topological_order[2] == 2U);
	assert(admission.critical_path_ns == 300U);
	assert(admission.total_duration_ns == 350U);
	assert(admission.slack_min_ns == 700U);
	assert(admission.required_capability_mask == 0x3U);
	assert(admission.highest_risk_ppm == 300000U);
	assert(fpa_plan_digest(&plan, digest) == FPA_OK);
	assert(memcmp(digest, admission.plan_digest, FPA_DIGEST_SIZE) == 0);
	assert(fpa_verify_admission(&plan, &admission) == FPA_OK);
	tampered = admission;
	tampered.topological_order[0] = 3U;
	assert(fpa_verify_admission(&plan, &tampered) == FPA_ERR_TAMPER);

	plan.nodes[2].dependency_ids[0] = 99U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_DEPENDENCY);
	seed_plan(&plan);
	plan.nodes[2].node_id = plan.nodes[1].node_id;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_CONFLICT);
	seed_plan(&plan);
	plan.nodes[0].dependency_count = 1U;
	plan.nodes[0].dependency_ids[0] = 2U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_CYCLE);
	seed_plan(&plan);
	plan.available_capability_mask = 0x1U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_CAPABILITY);
	seed_plan(&plan);
	plan.cpu_budget_ns = 200U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_BUDGET);
	seed_plan(&plan);
	plan.deadline_ns = 200U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_LIMIT);
	seed_plan(&plan);
	plan.flags = FPA_FLAG_MODEL_PROPOSAL | FPA_FLAG_VERIFIED_INPUT;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_APPROVAL);
	assert(admission.approval_required == 1U);
	seed_plan(&plan);
	plan.nodes[1].flags = FPA_FLAG_IRREVERSIBLE;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_APPROVAL);
	assert(admission.approval_node_mask & (1ULL << 1));
	seed_plan(&plan);
	plan.abi_version = 0U;
	assert(fpa_validate_plan(&plan, &admission) == FPA_ERR_ARGUMENT);
	printf("FPA_PLAN_ADMISSION_SELFTEST_OK cases=25 critical_path=300 slack_min=700 approval_barriers=2\n");
	return 0;
}
