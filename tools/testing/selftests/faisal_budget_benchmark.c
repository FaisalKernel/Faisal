#define _POSIX_C_SOURCE 200809L

#include "faisal_budget.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define M240_BENCHMARK_ROUNDS 100000U

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void setup(struct m240_policy *policy, struct m240_request *request,
		  struct m240_budget *usage)
{
	memset(policy, 0, sizeof(*policy));
	policy->current_time_ns = 1000U;
	policy->max_deadline_horizon_ns = 5000U;
	policy->minimum_priority = 1U;
	policy->require_authority = 1U;
	policy->require_verified_input = 1U;
	policy->maximum.cpu_ns = 1000000U;
	policy->maximum.memory_bytes = 1000000U;
	policy->maximum.gpu_ns = 1000000U;
	policy->maximum.npu_ns = 1000000U;
	policy->maximum.network_bytes = 1000000U;
	policy->maximum.storage_bytes = 1000000U;
	policy->maximum.cost_micro = 1000000U;
	policy->maximum.energy_uj = 1000000U;
	memset(request, 0, sizeof(*request));
	request->objective_id = 1U;
	request->agent_id = 2U;
	request->tenant_id = 3U;
	request->trace_id = 4U;
	request->task_generation = 5U;
	request->session_generation = 6U;
	request->world_generation = 7U;
	request->model_generation = 8U;
	request->request_sequence = 9U;
	request->issued_at_ns = 900U;
	request->deadline_ns = 2000U;
	request->priority = 100U;
	request->flags = M240_FLAG_VERIFIED_INPUT | M240_FLAG_AUTHORITY_GRANTED;
	request->requested.cpu_ns = 1000U;
	request->requested.memory_bytes = 1000U;
	request->requested.gpu_ns = 100U;
	request->requested.npu_ns = 100U;
	request->requested.network_bytes = 1000U;
	request->requested.storage_bytes = 1000U;
	request->requested.cost_micro = 100U;
	request->requested.energy_uj = 100U;
	memset(request->objective_digest, 0x41, sizeof(request->objective_digest));
	memset(request->provenance_digest, 0x42, sizeof(request->provenance_digest));
	memset(usage, 0, sizeof(*usage));
	usage->cpu_ns = 10U;
	usage->memory_bytes = 10U;
	usage->gpu_ns = 1U;
	usage->npu_ns = 1U;
	usage->network_bytes = 10U;
	usage->storage_bytes = 10U;
	usage->cost_micro = 1U;
	usage->energy_uj = 1U;
}

int main(void)
{
	struct m240_policy policy;
	struct m240_request request;
	struct m240_budget usage;
	struct m240_service service;
	struct m240_receipt receipt;
	uint64_t start;
	uint64_t end;
	uint64_t operations = 0U;
	unsigned int round;

	setup(&policy, &request, &usage);
	start = now_ns();
	if (start == 0U)
		return 1;
	for (round = 0U; round < M240_BENCHMARK_ROUNDS; ++round) {
		if (m240_init(&service, &policy) != M240_OK ||
		    m240_admit(&service, &request, &receipt) != M240_OK ||
		    m240_consume(&service, request.objective_id,
				 request.task_generation, request.session_generation,
				 &usage, 1100U, &receipt) != M240_OK ||
		    m240_complete(&service, request.objective_id,
				  request.task_generation, request.session_generation,
				  1200U, &receipt) != M240_OK)
			return 1;
		++operations;
		++operations;
		++operations;
	}
	end = now_ns();
	if (end <= start)
		return 1;
	printf("M240_BUDGET_BENCHMARK_EXIT=0 rounds=%u operations=%" PRIu64
	       " elapsed_ns=%" PRIu64 " ns_per_operation=%.2f\n",
	       M240_BENCHMARK_ROUNDS, operations, end - start,
	       (double)(end - start) / (double)operations);
	return 0;
}
