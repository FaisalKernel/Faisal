#include "../../faisal-agent-runtime/faisal_agent_runtime.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void digest(uint8_t out[FAR_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FAR_DIGEST_SIZE);
}

static struct far_policy make_policy(void)
{
	struct far_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.budget_policy.current_time_ns = 1000U;
	policy.budget_policy.max_deadline_horizon_ns = 1000000000ULL;
	policy.budget_policy.minimum_priority = 1U;
	policy.budget_policy.require_authority = 1U;
	policy.budget_policy.require_verified_input = 1U;
	policy.budget_policy.maximum.cpu_ns = 1000000000ULL;
	policy.budget_policy.maximum.memory_bytes = 1000000000ULL;
	policy.budget_policy.maximum.gpu_ns = 1000000000ULL;
	policy.budget_policy.maximum.npu_ns = 1000000000ULL;
	policy.budget_policy.maximum.network_bytes = 1000000000ULL;
	policy.budget_policy.maximum.storage_bytes = 1000000000ULL;
	policy.budget_policy.maximum.cost_micro = 1000000000ULL;
	policy.budget_policy.maximum.energy_uj = 1000000000ULL;
	policy.require_tool_authority = 1U;
	policy.require_message_authority = 1U;
	policy.require_verified_input = 1U;
	return policy;
}

static int run_point(size_t count, double *ns_per_operation, uint64_t *elapsed)
{
	char path[128];
	struct far_policy policy = make_policy();
	struct far_service *service;
	struct far_agent agent;
	struct far_objective request;
	struct far_objective admitted;
	struct far_objective running;
	struct far_objective completed;
	uint8_t identity[FAR_DIGEST_SIZE];
	uint8_t result_digest[FAR_DIGEST_SIZE];
	uint64_t start;
	uint64_t finish;
	size_t i;
	int result;

	if (count == 0U || count > FAR_MAX_OBJECTIVES || ns_per_operation == NULL ||
	    elapsed == NULL)
		return 1;
	service = calloc(1U, sizeof(*service));
	if (service == NULL)
		return 1;
	snprintf(path, sizeof(path), "/tmp/faisal-agent-runtime-bench-%ld-%zu.journal",
		 (long)getpid(), count);
	unlink(path);
	digest(identity, 0x11U);
	result = far_open(service, path, &policy);
	if (result != FAR_OK)
		goto fail;
	result = far_register_agent(service, 1U, 0xffffU, 1000000U, identity,
					"benchmark-agent", &agent);
	if (result != FAR_OK)
		goto close_fail;
	start = now_ns();
	for (i = 0U; i < count; ++i) {
		memset(&request, 0, sizeof(request));
		request.agent_id = agent.agent_id;
		request.tenant_id = 1U;
		request.trace_id = 7000U + (uint64_t)i;
		request.task_generation = 1U;
		request.session_generation = 1U;
		request.world_generation = 1U;
		request.model_generation = 1U;
		request.request_sequence = (uint64_t)i + 1U;
		request.created_at_ns = 100U;
		request.deadline_ns = 100000000U;
		request.required_capability_mask = 0x1U;
		request.priority = (uint32_t)(i % 100U) + 1U;
		request.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
		request.budget.cpu_ns = 1000U;
		request.budget.memory_bytes = 1000U;
		request.budget.gpu_ns = 1000U;
		request.budget.npu_ns = 1000U;
		request.budget.network_bytes = 1000U;
		request.budget.storage_bytes = 1000U;
		request.budget.cost_micro = 1000U;
		request.budget.energy_uj = 1000U;
		digest(request.objective_digest, (uint8_t)(i + 1U));
		digest(request.provenance_digest, (uint8_t)(i + 33U));
		result = far_admit_objective(service, &request, &admitted);
		if (result != FAR_OK)
			goto close_fail;
		result = far_dispatch(service, admitted.objective_id, 110U + (uint64_t)i,
					      &running);
		if (result != FAR_OK)
			goto close_fail;
		digest(result_digest, (uint8_t)(i + 65U));
		result = far_complete(service, running.objective_id, 120U + (uint64_t)i,
					      result_digest, &completed);
		if (result != FAR_OK)
			goto close_fail;
	}
	finish = now_ns();
	*elapsed = finish - start;
	*ns_per_operation = (double)(*elapsed) / (double)(count * 3U);
	far_close(service);
	unlink(path);
	free(service);
	return 0;

close_fail:
	far_close(service);
fail:
	unlink(path);
	free(service);
	return 1;
}

int main(void)
{
	static const size_t points[] = {1U, 16U, 64U, 128U, 256U, 512U};
	size_t i;

	printf("M241_AGENT_RUNTIME_BENCHMARK_BEGIN\n");
	for (i = 0U; i < sizeof(points) / sizeof(points[0]); ++i) {
		double ns_per_operation;
		uint64_t elapsed;
		if (run_point(points[i], &ns_per_operation, &elapsed) != 0) {
			fprintf(stderr, "benchmark point failed count=%zu\n", points[i]);
			return 1;
		}
		printf("objectives=%zu operations=%zu elapsed_ns=%llu ns_per_operation=%.2f\n",
		       points[i], points[i] * 3U, (unsigned long long)elapsed,
		       ns_per_operation);
	}
	printf("M241_AGENT_RUNTIME_BENCHMARK_EXIT=0\n");
	return 0;
}
