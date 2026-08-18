#include "../../faisal-fabric/faisal_fabric.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define THREADS 8U
#define SHARDS_PER_THREAD 32U

struct worker_args {
	struct ff_service *service;
	unsigned int index;
	atomic_int *failures;
};

static void digest(uint8_t out[FF_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FF_DIGEST_SIZE);
}

static struct ff_policy policy(void)
{
	struct ff_policy p;

	memset(&p, 0, sizeof(p));
	p.current_time_ns = 100U;
	p.observation_max_age_ns = 1000000U;
	p.default_lease_ns = 100000U;
	p.max_lease_ns = 200000U;
	p.minimum_priority = 1U;
	p.max_queue_depth = FF_MAX_SHARDS;
	p.require_authority = 1U;
	p.require_verified_input = 1U;
	return p;
}

static struct ff_node make_node(uint64_t node_id)
{
	struct ff_node n;

	memset(&n, 0, sizeof(n));
	n.node_id = node_id;
	n.generation = 1U;
	n.observed_at_ns = 100U;
	n.state = FF_NODE_HEALTHY;
	n.health_permille = 900U;
	n.pressure_permille = 100U;
	n.thermal_permille = 100U;
	n.forecast_permille = 100U;
	n.capacity.cpu_ns = 1000000000ULL;
	n.capacity.memory_bytes = 1000000000ULL;
	n.capacity.gpu_ns = 1000000000ULL;
	n.capacity.npu_ns = 1000000000ULL;
	n.capacity.network_bytes = 1000000000ULL;
	n.capacity.storage_bytes = 1000000000ULL;
	n.capacity.cost_micro = 1000000000ULL;
	n.capacity.energy_uj = 1000000000ULL;
	n.available = n.capacity;
	digest(n.identity_digest, (uint8_t)(node_id + 1U));
	digest(n.topology_digest, (uint8_t)(node_id + 33U));
	return n;
}

static void *worker(void *opaque)
{
	struct worker_args *args = opaque;
	struct ff_node observation = make_node((uint64_t)args->index + 1U);
	struct ff_node registered;
	unsigned int i;

	if (ff_register_node(args->service, &observation, &registered) != FF_OK) {
		atomic_fetch_add(args->failures, 1);
		return NULL;
	}
	for (i = 0U; i < SHARDS_PER_THREAD; ++i) {
		struct ff_shard request;
		struct ff_shard submitted;
		struct ff_shard placed;
		struct ff_lease lease;
		struct ff_lease renewed;
		int result;

		memset(&request, 0, sizeof(request));
		request.objective_id = 100000U + ((uint64_t)args->index * SHARDS_PER_THREAD) + i + 1U;
		request.agent_id = 100U + args->index;
		request.tenant_id = 1U;
		request.trace_id = 200000U + ((uint64_t)args->index * SHARDS_PER_THREAD) + i + 1U;
		request.task_generation = 1U;
		request.session_generation = 1U;
		request.issued_at_ns = 100U;
		request.deadline_ns = 1000000000ULL;
		request.priority = (i % 100U) + 1U;
		request.flags = FF_FLAG_AUTHORITY_GRANTED | FF_FLAG_VERIFIED_INPUT |
				FF_FLAG_MIGRATION_ALLOWED;
		request.demand.cpu_ns = 1000U;
		request.demand.memory_bytes = 2000U;
		request.demand.gpu_ns = 3000U;
		request.demand.npu_ns = 4000U;
		request.demand.network_bytes = 5000U;
		request.demand.storage_bytes = 6000U;
		request.demand.cost_micro = 7000U;
		request.demand.energy_uj = 8000U;
		digest(request.budget_receipt_digest, (uint8_t)(i + args->index + 1U));
		digest(request.provenance_digest, (uint8_t)(i + args->index + 33U));
		result = ff_submit_shard(args->service, &request, &submitted);
		if (result == FF_OK)
			result = ff_place_shard(args->service, submitted.shard_id, 110U,
							&placed, &lease);
		if (result == FF_OK)
			result = ff_renew_lease(args->service, lease.lease_id, 120U, 200U,
							&renewed);
		if (result != FF_OK)
			atomic_fetch_add(args->failures, 1);
	}
	return NULL;
}

int main(void)
{
	char path[128];
	struct ff_service *service;
	struct ff_service *recovered;
	struct ff_policy p = policy();
	struct ff_journal_attestation attestation;
	struct worker_args args[THREADS];
	pthread_t threads[THREADS];
	atomic_int failures = 0;
	unsigned int i;

	service = calloc(1U, sizeof(*service));
	recovered = calloc(1U, sizeof(*recovered));
	if (service == NULL || recovered == NULL)
		return 1;
	snprintf(path, sizeof(path), "/tmp/faisal-fabric-concurrency-%ld.journal", (long)getpid());
	unlink(path);
	if (ff_open(service, path, &p) != FF_OK)
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
	if (atomic_load(&failures) != 0 || service->node_count != THREADS ||
	    service->shard_count != THREADS * SHARDS_PER_THREAD ||
	    service->lease_count != THREADS * SHARDS_PER_THREAD)
		return 1;
	if (ff_query_journal(service, &attestation) != FF_OK ||
	    attestation.last_sequence != THREADS + THREADS * SHARDS_PER_THREAD * 3U)
		return 1;
	ff_close(service);
	if (ff_open(recovered, path, &p) != FF_OK)
		return 1;
	if (ff_query_journal(recovered, &attestation) != FF_OK ||
	    attestation.last_sequence != THREADS + THREADS * SHARDS_PER_THREAD * 3U)
		return 1;
	ff_close(recovered);
	unlink(path);
	free(service);
	free(recovered);
	printf("M242_FABRIC_CONCURRENCY_EXIT=0 threads=%u shards=%u failures=%d\n",
	       THREADS, THREADS * SHARDS_PER_THREAD, atomic_load(&failures));
	return 0;
}
