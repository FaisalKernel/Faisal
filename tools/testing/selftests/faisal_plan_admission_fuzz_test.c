#include "../../faisal-plan-admission/faisal_plan_admission.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void seed_plan(struct fpa_plan *plan)
{
	memset(plan, 0, sizeof(*plan));
	plan->abi_version = FPA_ABI_VERSION;
	plan->objective_id = 1U;
	plan->plan_generation = 1U;
	plan->deadline_ns = 1000U;
	plan->cpu_budget_ns = 1000U;
	plan->cost_budget_micro = 1000U;
	plan->available_capability_mask = 0x3U;
	plan->node_count = 3U;
	plan->flags = FPA_FLAG_VERIFIED_INPUT;
	plan->nodes[0].node_id = 1U;
	plan->nodes[0].priority = 1U;
	plan->nodes[0].risk_ppm = 100000U;
	plan->nodes[0].duration_ns = 100U;
	plan->nodes[0].cpu_budget_ns = 100U;
	plan->nodes[0].cost_budget_micro = 10U;
	plan->nodes[0].required_capability_mask = 0x1U;
	plan->nodes[1] = plan->nodes[0];
	plan->nodes[1].node_id = 2U;
	plan->nodes[1].dependency_count = 1U;
	plan->nodes[1].dependency_ids[0] = 1U;
	plan->nodes[2] = plan->nodes[0];
	plan->nodes[2].node_id = 3U;
	plan->nodes[2].dependency_count = 1U;
	plan->nodes[2].dependency_ids[0] = 2U;
}

int main(void)
{
	struct fpa_plan plan;
	struct fpa_admission admission;
	uint32_t rejected = 0;
	uint32_t admitted = 0;
	uint32_t approval = 0;
	uint32_t i;

	for (i = 0; i < 10000U; i++) {
		int rc;
		seed_plan(&plan);
		switch (i % 8U) {
		case 0U:
			plan.abi_version = 0U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_ARGUMENT);
			rejected++;
			break;
		case 1U:
			plan.nodes[0].dependency_count = 1U;
			plan.nodes[0].dependency_ids[0] = 2U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_CYCLE);
			rejected++;
			break;
		case 2U:
			plan.nodes[2].dependency_ids[0] = 99U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_DEPENDENCY);
			rejected++;
			break;
		case 3U:
			plan.nodes[2].node_id = 2U;
			plan.nodes[2].dependency_count = 0U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_CONFLICT);
			rejected++;
			break;
		case 4U:
			plan.available_capability_mask = 0U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_CAPABILITY);
			rejected++;
			break;
		case 5U:
			plan.cpu_budget_ns = 50U;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_BUDGET);
			rejected++;
			break;
		case 6U:
			plan.flags = FPA_FLAG_MODEL_PROPOSAL;
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_ERR_APPROVAL);
			assert(admission.approval_required == 1U);
			approval++;
			break;
		default:
			rc = fpa_validate_plan(&plan, &admission);
			assert(rc == FPA_OK);
			admitted++;
			break;
		}
	}
	printf("FPA_PLAN_ADMISSION_FUZZ_OK iterations=10000 rejected=%u approval=%u admitted=%u\n",
	       rejected, approval, admitted);
	return 0;
}
