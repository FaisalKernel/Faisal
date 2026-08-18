#include "../../faisal-platform/faisal_platform.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 64U

static uint64_t now_ns(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
		return 0U;
	return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void digest(uint8_t out[FPL_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FPL_DIGEST_SIZE);
}

static struct fpl_policy make_policy(void)
{
	struct fpl_policy value;

	memset(&value, 0, sizeof(value));
	value.current_time_ns = 1000U;
	value.max_intent_age_ns = 10000U;
	value.flags = FPL_REQUIRE_AUTHORITY | FPL_REQUIRE_LINEAGE |
		FPL_REQUIRE_TOPOLOGY | FPL_FAIL_CLOSED;
	value.max_workloads = FPL_MAX_WORKLOADS;
	value.max_recovery_attempts = 3U;
	digest(value.authority_digest, 0xA1U);
	return value;
}

static struct fpl_node make_node(uint64_t id)
{
	struct fpl_node value;

	memset(&value, 0, sizeof(value));
	value.node_id = id;
	value.generation = 1U;
	value.total_cpu_millis = 1000000U;
	value.free_cpu_millis = value.total_cpu_millis;
	value.total_memory_bytes = 1ULL << 40;
	value.free_memory_bytes = value.total_memory_bytes;
	value.total_network_mbps = 1000000U;
	value.free_network_mbps = value.total_network_mbps;
	value.total_storage_bytes = 1ULL << 50;
	value.free_storage_bytes = value.total_storage_bytes;
	value.accelerator_mask = 1U;
	value.accelerator_count = 8U;
	value.capability_mask = FLE_CAP_INFERENCE | FLE_CAP_MEMORY_TIER |
		FLE_CAP_NETWORK_FABRIC;
	value.provider_mask = 1U;
	value.health_ppm = 1000000U;
	value.state = FPL_NODE_READY;
	snprintf(value.provider, sizeof(value.provider), "bench-provider");
	snprintf(value.zone, sizeof(value.zone), "zone-a");
	snprintf(value.rack, sizeof(value.rack), "rack-a");
	snprintf(value.fabric, sizeof(value.fabric), "fabric-a");
	digest(value.attestation_digest, (uint8_t)id);
	return value;
}

static struct fpl_intent make_intent(uint64_t id)
{
	struct fpl_intent value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FPL_ABI_VERSION;
	value.provider_kind = FPL_PROVIDER_KUBERNETES_DRA;
	value.workload_id = id;
	value.tenant_id = 1U;
	value.agent_id = 2U;
	value.objective_id = id;
	value.created_at_ns = 900U;
	value.deadline_ns = 9000U;
	value.required_cpu_millis = 100U;
	value.required_memory_bytes = 1ULL << 20;
	value.required_network_mbps = 10U;
	value.required_storage_bytes = 1ULL << 20;
	value.required_accelerator_mask = 1U;
	value.required_accelerator_count = 1U;
	value.required_capability_mask = FLE_CAP_INFERENCE;
	value.replicas = 1U;
	value.gang_size = 1U;
	value.authorized = 1U;
	value.allow_recovery = 1U;
	snprintf(value.tenant, sizeof(value.tenant), "bench-tenant");
	snprintf(value.model_id, sizeof(value.model_id), "bench-model");
	snprintf(value.objective, sizeof(value.objective), "bench-objective");
	snprintf(value.zone, sizeof(value.zone), "zone-a");
	snprintf(value.rack, sizeof(value.rack), "rack-a");
	snprintf(value.fabric, sizeof(value.fabric), "fabric-a");
	digest(value.lineage_digest, 0xB1U);
	digest(value.policy_digest, 0xB2U);
	digest(value.provider_claim_digest, 0xB3U);
	return value;
}

int main(void)
{
	char path[128];
	struct fpl_service service;
	struct fpl_policy configured = make_policy();
	struct fpl_workload workload;
	uint64_t durable_start;
	uint64_t durable_end;
	uint64_t static_start;
	uint64_t static_end;
	uint64_t static_state = 0U;
	unsigned int i;

	snprintf(path, sizeof(path), "/tmp/faisal-platform-benchmark-%ld.journal", (long)getpid());
	unlink(path);
	if (fpl_open(&service, path, &configured) != FPL_OK ||
	    fpl_add_node(&service, &(struct fpl_node){
		.node_id = 1U, .generation = 1U, .total_cpu_millis = 1000000U,
		.free_cpu_millis = 1000000U, .total_memory_bytes = 1ULL << 40,
		.free_memory_bytes = 1ULL << 40, .total_network_mbps = 1000000U,
		.free_network_mbps = 1000000U, .total_storage_bytes = 1ULL << 50,
		.free_storage_bytes = 1ULL << 50, .accelerator_mask = 1U,
		.accelerator_count = 8U, .capability_mask = FLE_CAP_INFERENCE | FLE_CAP_MEMORY_TIER | FLE_CAP_NETWORK_FABRIC,
		.provider_mask = 1U, .health_ppm = 1000000U, .state = FPL_NODE_READY,
		.provider = "bench-provider", .zone = "zone-a", .rack = "rack-a", .fabric = "fabric-a"
	}) != FPL_OK)
		return 1;
	/* Keep the helper in the benchmark contract and ensure it remains warning-clean. */
	(void)make_node;
	durable_start = now_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		struct fpl_intent request = make_intent((uint64_t)i + 1U);
		uint8_t checkpoint[FPL_DIGEST_SIZE];
		if (fpl_submit(&service, &request, &workload) != FPL_OK ||
		    fpl_place(&service, request.workload_id, &workload) != FPL_OK) {
			fpl_close(&service);
			unlink(path);
			return 1;
		}
		digest(checkpoint, (uint8_t)i);
		if (fpl_checkpoint(&service, request.workload_id, 1100U, checkpoint) != FPL_OK ||
		    fpl_complete(&service, request.workload_id, checkpoint) != FPL_OK) {
			fpl_close(&service);
			unlink(path);
			return 1;
		}
	}
	durable_end = now_ns();
	static_start = now_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		static_state += 100U;
		static_state -= 100U;
		static_state ^= (uint64_t)i;
	}
	static_end = now_ns();
	fpl_close(&service);
	unlink(path);
	printf("M245_PLATFORM_BENCHMARK_EXIT=0 rounds=%u durable_lifecycle_ns=%llu durable_ns_per_round=%.2f static_elapsed_ns=%llu static_ns_per_round=%.2f checksum=%llu\n",
	       ROUNDS, (unsigned long long)(durable_end - durable_start),
	       (double)(durable_end - durable_start) / (double)ROUNDS,
	       (unsigned long long)(static_end - static_start),
	       (double)(static_end - static_start) / (double)ROUNDS,
	       (unsigned long long)static_state);
	return 0;
}
