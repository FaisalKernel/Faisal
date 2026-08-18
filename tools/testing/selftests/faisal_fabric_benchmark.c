#include "../../faisal-fabric/faisal_fabric.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t clock_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

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

static struct ff_node node(uint64_t id)
{
	struct ff_node n;

	memset(&n, 0, sizeof(n));
	n.node_id = id;
	n.generation = 1U;
	n.observed_at_ns = 100U;
	n.state = FF_NODE_HEALTHY;
	n.health_permille = 900U;
	n.pressure_permille = (uint32_t)(id % 100U);
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
	digest(n.identity_digest, (uint8_t)(id + 1U));
	digest(n.topology_digest, (uint8_t)(id + 65U));
	return n;
}

static int run_point(size_t nodes, size_t shards, uint64_t *elapsed,
			 double *ns_per_operation)
{
	char path[128];
	struct ff_service *service;
	struct ff_policy p = policy();
	struct ff_node observation;
	struct ff_node registered;
	struct ff_shard request;
	struct ff_shard submitted;
	struct ff_shard placed;
	struct ff_lease lease;
	struct ff_lease renewed;
	uint64_t start;
	uint64_t finish;
	int result;

	if (nodes == 0U || nodes > FF_MAX_NODES || shards == 0U || shards > FF_MAX_SHARDS)
		return 1;
	service = calloc(1U, sizeof(*service));
	if (service == NULL)
		return 1;
	snprintf(path, sizeof(path), "/tmp/faisal-fabric-bench-%ld-%zu-%zu.journal",
		 (long)getpid(), nodes, shards);
	unlink(path);
	result = ff_open(service, path, &p);
	if (result != FF_OK)
		goto fail;
	start = clock_ns();
	for (size_t i = 0U; i < nodes; ++i) {
		observation = node((uint64_t)i + 1U);
		if (ff_register_node(service, &observation, &registered) != FF_OK)
			goto close_fail;
	}
	for (size_t i = 0U; i < shards; ++i) {
		memset(&request, 0, sizeof(request));
		request.objective_id = 100000U + (uint64_t)i;
		request.agent_id = 100U + (uint64_t)(i % nodes);
		request.tenant_id = 1U;
		request.trace_id = 200000U + (uint64_t)i;
		request.task_generation = 1U;
		request.session_generation = 1U;
		request.issued_at_ns = 100U;
		request.deadline_ns = 1000000000ULL;
		request.priority = (uint32_t)(i % 100U) + 1U;
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
		digest(request.budget_receipt_digest, (uint8_t)(i + 1U));
		digest(request.provenance_digest, (uint8_t)(i + 33U));
		if (ff_submit_shard(service, &request, &submitted) != FF_OK ||
		    ff_place_shard(service, submitted.shard_id, 110U, &placed, &lease) != FF_OK ||
		    ff_renew_lease(service, lease.lease_id, 120U, 200U, &renewed) != FF_OK)
			goto close_fail;
	}
	finish = clock_ns();
	*elapsed = finish - start;
	*ns_per_operation = (double)(*elapsed) / (double)(nodes + shards * 3U);
	ff_close(service);
	unlink(path);
	free(service);
	return 0;

close_fail:
	ff_close(service);
fail:
	unlink(path);
	free(service);
	return 1;
}

int main(void)
{
	static const size_t node_points[] = {1U, 4U, 16U, 32U, 64U};
	static const size_t shard_points[] = {1U, 32U, 128U, 256U};

	printf("M242_FABRIC_BENCHMARK_BEGIN\n");
	for (size_t i = 0U; i < sizeof(node_points) / sizeof(node_points[0]); ++i) {
		for (size_t j = 0U; j < sizeof(shard_points) / sizeof(shard_points[0]); ++j) {
			uint64_t elapsed;
			double ns_per_operation;
			if (run_point(node_points[i], shard_points[j], &elapsed,
				      &ns_per_operation) != 0) {
				fprintf(stderr, "benchmark point failed nodes=%zu shards=%zu\n",
					node_points[i], shard_points[j]);
				return 1;
			}
			printf("nodes=%zu shards=%zu operations=%zu elapsed_ns=%llu ns_per_operation=%.2f\n",
			       node_points[i], shard_points[j],
			       node_points[i] + shard_points[j] * 3U,
			       (unsigned long long)elapsed, ns_per_operation);
		}
	}
	printf("M242_FABRIC_BENCHMARK_EXIT=0\n");
	return 0;
}
