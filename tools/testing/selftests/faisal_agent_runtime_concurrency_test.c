#include "../../faisal-agent-runtime/faisal_agent_runtime.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 8U
#define OBJECTIVES_PER_THREAD 32U

struct worker_args {
	struct far_service *service;
	unsigned int index;
	atomic_int *failures;
};

static void digest(uint8_t out[FAR_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FAR_DIGEST_SIZE);
}

static struct far_policy policy(void)
{
	struct far_policy result;

	memset(&result, 0, sizeof(result));
	result.budget_policy.current_time_ns = 1000U;
	result.budget_policy.max_deadline_horizon_ns = 1000000000ULL;
	result.budget_policy.minimum_priority = 1U;
	result.budget_policy.require_authority = 1U;
	result.budget_policy.require_verified_input = 1U;
	result.budget_policy.maximum.cpu_ns = 1000000000ULL;
	result.budget_policy.maximum.memory_bytes = 1000000000ULL;
	result.budget_policy.maximum.gpu_ns = 1000000000ULL;
	result.budget_policy.maximum.npu_ns = 1000000000ULL;
	result.budget_policy.maximum.network_bytes = 1000000000ULL;
	result.budget_policy.maximum.storage_bytes = 1000000000ULL;
	result.budget_policy.maximum.cost_micro = 1000000000ULL;
	result.budget_policy.maximum.energy_uj = 1000000000ULL;
	result.require_tool_authority = 1U;
	result.require_message_authority = 1U;
	result.require_verified_input = 1U;
	return result;
}

static void *worker(void *opaque)
{
	struct worker_args *args = opaque;
	struct far_agent agent;
	uint8_t identity[FAR_DIGEST_SIZE];
	unsigned int i;

	digest(identity, (uint8_t)(args->index + 1U));
	if (far_register_agent(args->service, 1U, 1U, 1000000U, identity,
				       "concurrent-agent", &agent) != FAR_OK) {
		atomic_fetch_add(args->failures, 1);
		return NULL;
	}
	for (i = 0U; i < OBJECTIVES_PER_THREAD; ++i) {
		struct far_objective request;
		struct far_objective admitted;
		struct far_objective running;
		struct far_objective completed;
		uint8_t result_digest[FAR_DIGEST_SIZE];
		int result;

		memset(&request, 0, sizeof(request));
		request.agent_id = agent.agent_id;
		request.tenant_id = 1U;
		request.trace_id = (((uint64_t)args->index << 32) | i) + 1U;
		request.task_generation = 1U;
		request.session_generation = 1U;
		request.world_generation = 1U;
		request.model_generation = 1U;
		request.request_sequence = (uint64_t)i + 1U;
		request.created_at_ns = 100U;
		request.deadline_ns = 100000000U;
		request.required_capability_mask = 1U;
		request.priority = (i % 100U) + 1U;
		request.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
		request.budget.cpu_ns = 1000U;
		request.budget.memory_bytes = 1000U;
		request.budget.gpu_ns = 1000U;
		request.budget.npu_ns = 1000U;
		request.budget.network_bytes = 1000U;
		request.budget.storage_bytes = 1000U;
		request.budget.cost_micro = 1000U;
		request.budget.energy_uj = 1000U;
		digest(request.objective_digest, (uint8_t)(i + args->index + 1U));
		digest(request.provenance_digest, (uint8_t)(i + args->index + 33U));
		result = far_admit_objective(args->service, &request, &admitted);
		if (result == FAR_OK)
			result = far_dispatch(args->service, admitted.objective_id, 110U, &running);
		if (result == FAR_OK) {
			digest(result_digest, (uint8_t)(i + args->index + 65U));
			result = far_complete(args->service, running.objective_id, 120U,
						      result_digest, &completed);
		}
		if (result != FAR_OK)
			atomic_fetch_add(args->failures, 1);
	}
	return NULL;
}

int main(void)
{
	char path[128];
	struct far_service *service;
	struct far_service *recovered;
	struct far_journal_attestation attestation;
	struct far_policy service_policy = policy();
	struct worker_args args[THREADS];
	pthread_t threads[THREADS];
	atomic_int failures = 0;
	unsigned int i;
	int result;

	service = calloc(1U, sizeof(*service));
	recovered = calloc(1U, sizeof(*recovered));
	if (service == NULL || recovered == NULL)
		return 1;
	snprintf(path, sizeof(path), "/tmp/faisal-agent-runtime-concurrency-%ld.journal",
		 (long)getpid());
	unlink(path);
	if (far_open(service, path, &service_policy) != FAR_OK)
		return 1;
	for (i = 0U; i < THREADS; ++i) {
		args[i].service = service;
		args[i].index = i;
		args[i].failures = &failures;
		if (pthread_create(&threads[i], NULL, worker, &args[i]) != 0)
			return 1;
	}
	for (i = 0U; i < THREADS; ++i)
		if (pthread_join(threads[i], NULL) != 0)
			return 1;
	if (atomic_load(&failures) != 0 || service->agent_count != THREADS ||
	    service->objective_count != THREADS * OBJECTIVES_PER_THREAD)
		return 1;
	result = far_query_journal(service, &attestation);
	if (result != FAR_OK || attestation.last_sequence !=
	    THREADS + THREADS * OBJECTIVES_PER_THREAD * 3U)
		return 1;
	far_close(service);
	if (far_open(recovered, path, &service_policy) != FAR_OK)
		return 1;
	if (far_query_journal(recovered, &attestation) != FAR_OK ||
	    attestation.last_sequence != THREADS + THREADS * OBJECTIVES_PER_THREAD * 3U)
		return 1;
	far_close(recovered);
	unlink(path);
	free(service);
	free(recovered);
	printf("M241_AGENT_RUNTIME_CONCURRENCY_EXIT=0 threads=%u objectives=%u failures=%d\n",
	       THREADS, THREADS * OBJECTIVES_PER_THREAD, atomic_load(&failures));
	return 0;
}
