#include "faisal_kv_tier.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_eq(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual,
			expected);
		failures++;
	}
}

static void fill(uint8_t digest[RKV_DIGEST_SIZE], uint8_t seed)
{
	size_t i;

	for (i = 0U; i < RKV_DIGEST_SIZE; ++i)
		digest[i] = (uint8_t)(seed + (uint8_t)i);
}

static struct rkv_request request(void)
{
	struct rkv_request value;

	memset(&value, 0, sizeof(value));
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
	value.deadline_ns = 10000U;
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
	value.max_age_ns = 1000U;
	value.max_latency_ns = 1000U;
	value.allowed_tier_mask = RKV_TIER_MASK(RKV_TIER_HBM) |
		RKV_TIER_MASK(RKV_TIER_DDR);
	value.require_provenance = 1U;
	return value;
}

int main(void)
{
	struct rkv_service service;
	struct rkv_request good = request();
	struct rkv_policy test_policy;
	struct rkv_policy limits = policy(300U, 1U);
	struct rkv_policy authorized = policy(400U, 1U);
	struct rkv_receipt receipt;
	struct rkv_receipt moved;
	struct rkv_record record;
	uint8_t transfer[RKV_DIGEST_SIZE];
	unsigned int i;
	unsigned int mutation_rejections = 0U;

	expect_eq("init", rkv_init(&service), RKV_OK);
	expect_eq("admit", rkv_admit(&service, &good, &limits, &receipt), RKV_OK);
	expect_eq("receipt", rkv_verify_receipt(&receipt), RKV_OK);
	expect_eq("query", rkv_query(&service, receipt.cache_id, &record), RKV_OK);
	expect_eq("resident", (int)record.state, RKV_STATE_RESIDENT);
	good.cache_id = receipt.cache_id;
	expect_eq("duplicate", rkv_admit(&service, &good, &limits, &moved),
		RKV_ERR_REPLAY);
	fill(transfer, 9U);
	expect_eq("migration-authority", rkv_transition(&service, receipt.cache_id,
		RKV_TIER_DDR, 9U, 350U, 2048U, transfer, &limits, &moved),
		RKV_ERR_AUTHORITY);
	authorized.authority_granted = 1U;
	expect_eq("migration-generation", rkv_transition(&service, receipt.cache_id,
		RKV_TIER_DDR, 99U, 350U, 2048U, transfer, &authorized, &moved),
		RKV_ERR_GENERATION);
	expect_eq("migration", rkv_transition(&service, receipt.cache_id,
		RKV_TIER_DDR, 9U, 350U, 2048U, transfer, &authorized, &moved), RKV_OK);
	expect_eq("moved-receipt", rkv_verify_receipt(&moved), RKV_OK);
	expect_eq("moved-query", rkv_query(&service, receipt.cache_id, &record), RKV_OK);
	expect_eq("moved-tier", (int)record.request.target_tier, RKV_TIER_DDR);
	expect_eq("moved-sequence", (int)record.request.request_sequence, 2);
	moved.receipt_digest[0] ^= 0xFFU;
	expect_eq("receipt-tamper", rkv_verify_receipt(&moved), RKV_ERR_TAMPER);
	good = request();
	good.target_tier = RKV_TIER_DDR;
	limits = policy(300U, 1U);
	limits.allowed_tier_mask = RKV_TIER_MASK(RKV_TIER_HBM);
	expect_eq("tier-policy", rkv_admit(&service, &good, &limits, &moved),
		RKV_ERR_POLICY);
	good = request();
	test_policy = policy(300U, 1U);
	good.provenance_digest[0] = 0U;
	memset(good.provenance_digest + 1U, 0, RKV_DIGEST_SIZE - 1U);
	expect_eq("provenance-policy", rkv_admit(&service, &good, &test_policy,
		&moved), RKV_ERR_ARGUMENT);
	good = request();
	good.flags = 0U;
	expect_eq("verified-policy", rkv_admit(&service, &good, &test_policy,
		&moved), RKV_ERR_POLICY);
	good = request();
	test_policy = policy(11000U, 1U);
	expect_eq("expired", rkv_admit(&service, &good, &test_policy,
		&moved), RKV_ERR_EXPIRED);
	for (i = 0U; i < 64U; ++i) {
		struct rkv_receipt altered = receipt;
		altered.receipt_digest[i % RKV_DIGEST_SIZE] ^= 0x80U;
		if (rkv_verify_receipt(&altered) != RKV_ERR_TAMPER)
			mutation_rejections++;
	}
	if (mutation_rejections != 0U)
		failures++;
	printf("M239_KV_TIER_SELFTEST_EXIT=%d cases=16 mutation_rejections=%u\n",
	       failures == 0 ? 0 : 1, 64U - mutation_rejections);
	return failures == 0 ? 0 : 1;
}
