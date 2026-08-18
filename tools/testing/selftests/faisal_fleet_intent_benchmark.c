#define _GNU_SOURCE
#include "../../faisal-fleet/faisal_fleet_intent.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FLE_BENCH_ROUNDS 5000U
#define FLE_BENCH_NODES 16U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct fle_node make_node(uint64_t id)
{
	struct fle_node node;
	memset(&node, 0, sizeof(node));
	node.node_id = id;
	node.generation = 1;
	node.total_cpu_millis = 64000;
	node.free_cpu_millis = 32000 + id * 100;
	node.total_memory_bytes = 256ULL << 30;
	node.free_memory_bytes = (128ULL << 30) + id * (1ULL << 20);
	node.accelerator_mask = FLE_CAP_INFERENCE | FLE_CAP_NETWORK_FABRIC;
	node.accelerator_count = 4;
	node.capability_mask = FLE_CAP_INFERENCE | FLE_CAP_NETWORK_FABRIC | FLE_CAP_MEMORY_TIER;
	node.health_ppm = 950000 + (uint32_t)(id * 1000);
	node.state = FLE_STATE_READY;
	snprintf(node.zone, sizeof(node.zone), "zone-%llu", (unsigned long long)((id - 1) % 2 + 1));
	snprintf(node.rack, sizeof(node.rack), "rack-%llu", (unsigned long long)((id - 1) % 4 + 1));
	snprintf(node.fabric, sizeof(node.fabric), "fabric-%llu", (unsigned long long)((id - 1) % 2 + 1));
	return node;
}

int main(void)
{
	struct fle_service service;
	struct fle_intent intent;
	struct fle_assignment assignment;
	uint64_t start, elapsed;
	unsigned int round, i, placed = 0;

	start = now_ns();
	for (round = 0; round < FLE_BENCH_ROUNDS; round++) {
		if (fle_init(&service, FLE_POLICY_FAIL_CLOSED | FLE_POLICY_REQUIRE_LINEAGE |
			FLE_POLICY_REQUIRE_AUTHORITY | FLE_POLICY_REQUIRE_TOPOLOGY, 1000 + round) != FLE_OK)
			return 1;
		for (i = 0; i < FLE_BENCH_NODES; i++)
			if (fle_add_node(&service, &(struct fle_node){0}) != FLE_ERR_ARGUMENT)
				return 2;
		for (i = 0; i < FLE_BENCH_NODES; i++) {
			struct fle_node node = make_node(i + 1);
			if (fle_add_node(&service, &node) != FLE_OK)
				return 3;
		}
		memset(&intent, 0, sizeof(intent));
		intent.abi_version = FLE_ABI_VERSION;
		intent.policy_flags = FLE_POLICY_FAIL_CLOSED | FLE_POLICY_REQUIRE_LINEAGE |
			FLE_POLICY_REQUIRE_AUTHORITY | FLE_POLICY_REQUIRE_TOPOLOGY;
		intent.objective_id = round + 1;
		intent.tenant_id = 77;
		intent.agent_id = 1000 + round;
		intent.expected_node_generation = 1;
		intent.deadline_ns = 1000000000ULL + round;
		intent.required_cpu_millis = 1000;
		intent.required_memory_bytes = 1ULL << 30;
		intent.required_accelerator_mask = FLE_CAP_INFERENCE;
		intent.required_accelerator_count = 1;
		intent.required_capability_mask = FLE_CAP_INFERENCE;
		intent.gang_size = 4;
		intent.authorized = 1;
		strcpy(intent.tenant, "benchmark-tenant");
		strcpy(intent.objective, "fleet-placement");
		strcpy(intent.zone, "zone-1");
		intent.lineage_digest[0] = 0x55;
		intent.policy_digest[0] = 0x66;
		if (fle_place(&service, &intent, &assignment) != FLE_OK)
			return 4;
		placed++;
	}
	elapsed = now_ns() - start;
	printf("FLE_BENCH rounds=%u nodes_per_round=%u gang_size=4 placements=%u total_ns=%llu ns_per_round=%llu\n",
		FLE_BENCH_ROUNDS, FLE_BENCH_NODES, placed,
		(unsigned long long)elapsed,
		(unsigned long long)(elapsed / FLE_BENCH_ROUNDS));
	printf("FLE_BENCH_SCOPE=local_userspace_policy_fixture_not_kubernetes_or_physical_gpu_qualification\n");
	return 0;
}
