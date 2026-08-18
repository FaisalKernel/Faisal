#include "../../faisal-plan-admission/faisal_plan_admission.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void seed_plan(struct fpa_plan *plan)
{
	uint32_t i;

	memset(plan, 0, sizeof(*plan));
	plan->abi_version = FPA_ABI_VERSION;
	plan->objective_id = 77U;
	plan->plan_generation = 1U;
	plan->deadline_ns = 1000000U;
	plan->cpu_budget_ns = 10000000U;
	plan->cost_budget_micro = 1000000U;
	plan->available_capability_mask = 0x7U;
	plan->node_count = 32U;
	plan->flags = FPA_FLAG_VERIFIED_INPUT;
	for (i = 0; i < plan->node_count; i++) {
		struct fpa_node *node = &plan->nodes[i];
		node->node_id = i + 1U;
		node->priority = i % 8U;
		node->risk_ppm = 100000U + (i % 5U) * 50000U;
		node->duration_ns = 100U + i;
		node->cpu_budget_ns = 1000U;
		node->cost_budget_micro = 100U;
		node->required_capability_mask = 1ULL << (i % 3U);
		if (i >= 2U) {
			node->dependency_count = 2U;
			node->dependency_ids[0] = i;
			node->dependency_ids[1] = i - 1U;
		}
	}
}

int main(void)
{
	struct fpa_plan plan;
	struct fpa_admission admission;
	const uint64_t rounds = 10000U;
	uint64_t start;
	uint64_t validation_elapsed;
	uint64_t baseline_elapsed;
	uint64_t checksum = 0;
	uint64_t i;

	seed_plan(&plan);
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		plan.plan_generation = i + 1U;
		assert(fpa_validate_plan(&plan, &admission) == FPA_OK);
		checksum ^= admission.critical_path_ns ^ admission.plan_generation;
	}
	validation_elapsed = now_ns() - start;
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		uint32_t j;
		uint64_t duration = 0;
		uint32_t order_checksum = 0;
		for (j = 0; j < plan.node_count; j++) {
			duration += plan.nodes[j].duration_ns;
			order_checksum ^= plan.nodes[j].node_id;
		}
		checksum ^= duration ^ order_checksum;
	}
	baseline_elapsed = now_ns() - start;
	printf("FPA_PLAN_ADMISSION_BENCHMARK_OK rounds=%" PRIu64
	       " nodes=32 validation_ns=%" PRIu64
	       " baseline_raw_pass_ns=%" PRIu64
	       " validation_ns_per_node=%.2f baseline_ns_per_node=%.2f"
	       " admission_overhead_permille=%.2f checksum=%" PRIu64 "\n",
	       rounds, validation_elapsed, baseline_elapsed,
	       (double)validation_elapsed / (double)(rounds * 32U),
	       (double)baseline_elapsed / (double)(rounds * 32U),
	       baseline_elapsed ?
		((double)(validation_elapsed - baseline_elapsed) * 1000.0 /
		 (double)baseline_elapsed) : 0.0,
	       checksum);
	return 0;
}
