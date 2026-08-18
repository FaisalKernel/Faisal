#define _POSIX_C_SOURCE 200809L

#include "faisal_kv_tier.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void fill(uint8_t digest[RKV_DIGEST_SIZE], uint8_t seed)
{
	size_t i;

	for (i = 0U; i < RKV_DIGEST_SIZE; ++i)
		digest[i] = (uint8_t)(seed + (uint8_t)i);
}

static struct rkv_request request(uint64_t id)
{
	struct rkv_request value;

	memset(&value, 0, sizeof(value));
	value.cache_id = id;
	value.model_id = 1U;
	value.objective_id = 2U;
	value.trace_id = 3U;
	value.agent_id = 4U;
	value.tenant_id = 5U;
	value.task_generation = 6U;
	value.session_generation = 7U;
	value.world_generation = 8U;
	value.model_generation = 9U;
	value.request_sequence = 1U;
	value.issued_at_ns = 100U;
	value.observed_at_ns = 200U;
	value.deadline_ns = 1000000U;
	value.bytes = 4096U;
	value.page_count = 4U;
	value.locality_domain = 10U;
	value.bandwidth_bytes_s = 1000000U;
	value.latency_ns = 20U;
	value.source_tier = RKV_TIER_HBM;
	value.target_tier = RKV_TIER_HBM;
	value.pressure_ppm = 100000U;
	value.flags = RKV_FLAG_VERIFIED;
	fill(value.content_digest, 1U);
	fill(value.metadata_digest, 2U);
	fill(value.provenance_digest, 3U);
	return value;
}

static struct rkv_policy policy(uint64_t now, uint64_t sequence)
{
	struct rkv_policy value;

	memset(&value, 0, sizeof(value));
	value.now_ns = now;
	value.expected_model_id = 1U;
	value.expected_objective_id = 2U;
	value.expected_trace_id = 3U;
	value.expected_agent_id = 4U;
	value.expected_tenant_id = 5U;
	value.expected_task_generation = 6U;
	value.expected_session_generation = 7U;
	value.expected_world_generation = 8U;
	value.expected_model_generation = 9U;
	value.expected_sequence = sequence;
	value.max_age_ns = 100000U;
	value.max_latency_ns = 100000U;
	value.allowed_tier_mask = RKV_TIER_MASK(RKV_TIER_HBM) |
		RKV_TIER_MASK(RKV_TIER_DDR);
	value.require_provenance = 1U;
	value.authority_granted = 1U;
	return value;
}

int main(void)
{
	static struct rkv_service service;
	struct rkv_request req;
	struct rkv_policy admit_policy;
	struct rkv_policy move_policy;
	struct rkv_receipt receipt;
	struct rkv_receipt moved;
	struct rkv_record record;
	uint8_t transfer[RKV_DIGEST_SIZE];
	struct timespec ts;
	uint64_t start;
	uint64_t elapsed;
	uint64_t rounds = 100000U;
	uint64_t operations = 0U;
	uint64_t i;

	fill(transfer, 9U);
	clock_gettime(CLOCK_MONOTONIC, &ts);
	start = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
	for (i = 0U; i < rounds; ++i) {
		if (rkv_init(&service) != RKV_OK)
			return 1;
		req = request(100U + i);
		admit_policy = policy(300U, 1U);
		if (rkv_admit(&service, &req, &admit_policy, &receipt) != RKV_OK)
			return 2;
		operations++;
		if (rkv_verify_receipt(&receipt) != RKV_OK)
			return 3;
		operations++;
		move_policy = policy(400U, 1U);
		if (rkv_transition(&service, receipt.cache_id, RKV_TIER_DDR, 9U,
			350U, 2048U, transfer, &move_policy, &moved) != RKV_OK)
			return 4;
		operations++;
		if (rkv_query(&service, receipt.cache_id, &record) != RKV_OK ||
		    record.request.target_tier != RKV_TIER_DDR)
			return 5;
		operations++;
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	elapsed = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec - start;
	printf("M239_KV_TIER_BENCHMARK_EXIT=0 rounds=%llu operations=%llu elapsed_ns=%llu ns_per_operation=%.2f\n",
	       (unsigned long long)rounds, (unsigned long long)operations,
	       (unsigned long long)elapsed,
	       operations == 0U ? 0.0 : (double)elapsed / (double)operations);
	return 0;
}
