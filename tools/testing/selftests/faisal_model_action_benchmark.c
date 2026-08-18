#define _GNU_SOURCE
#include "../../faisal-model-action/faisal_model_action.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FMA_BENCH_ROUNDS 100000U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct fma_policy policy(void)
{
	struct fma_policy p;
	memset(&p, 0, sizeof(p));
	p.now_ns = 1000;
	p.expected_agent_id = 7;
	p.expected_objective_id = 8;
	p.expected_tenant_id = 9;
	p.expected_tool_id = 10;
	p.expected_registry_generation = 11;
	p.expected_revocation_generation = 12;
	p.expected_authority_lease_id = 13;
	p.max_ttl_ns = 500;
	p.allowed_provider_mask = 0x1FU;
	p.allowed_action_mask = (1U << (FMA_ACTION_TOOL - 1U));
	p.authority_granted = 1;
	p.require_schema = 1;
	p.require_provenance = 1;
	return p;
}

static struct fma_action_envelope envelope(uint64_t sequence)
{
	struct fma_action_envelope e;
	uint32_t i;
	memset(&e, 0, sizeof(e));
	e.abi_version = FMA_ABI_VERSION;
	e.action_kind = FMA_ACTION_TOOL;
	e.provider_kind = FMA_PROVIDER_LOCAL;
	e.schema_valid = 1;
	e.authority_source = FMA_AUTH_POLICY;
	e.request_id = sequence + 100;
	e.agent_id = 7;
	e.objective_id = 8;
	e.tenant_id = 9;
	e.tool_id = 10;
	e.registry_generation = 11;
	e.revocation_generation = 12;
	e.authority_lease_id = 13;
	e.request_sequence = sequence;
	e.nonce = sequence + 1000;
	e.issued_at_ns = 1000;
	e.expires_at_ns = 1400;
	e.confidence_ppm = 900000;
	snprintf(e.provider, sizeof(e.provider), "local");
	snprintf(e.model, sizeof(e.model), "fixture-model");
	snprintf(e.tool, sizeof(e.tool), "authorized_tool");
	for (i = 0; i < FMA_DIGEST_SIZE; i++) {
		e.input_digest[i] = (uint8_t)(i + 1);
		e.schema_digest[i] = (uint8_t)(i + 2);
		e.arguments_digest[i] = (uint8_t)(i + 3);
		e.model_provenance_digest[i] = (uint8_t)(i + 4);
	}
	return e;
}

int main(void)
{
	struct fma_verifier verifier;
	struct fma_policy p = policy();
	struct fma_action_envelope e;
	struct fma_decision d;
	struct fma_completion c;
	uint8_t result_digest[FMA_DIGEST_SIZE] = {1};
	uint64_t start, elapsed;
	unsigned int i;

	if (fma_init(&verifier) != FMA_OK)
		return 1;
	start = now_ns();
	for (i = 0; i < FMA_BENCH_ROUNDS; i++) {
		e = envelope((uint64_t)i + 1);
		if (fma_admit(&verifier, &e, &p, &d) != FMA_OK)
			return 2;
		memset(&c, 0, sizeof(c));
		c.request_id = e.request_id;
		c.observed_at_ns = 1100;
		c.result_code = 0;
		c.verifier_authorized = 1;
		memcpy(c.result_digest, result_digest, sizeof(c.result_digest));
		if (fma_complete(&verifier, &e, &d, &c) != FMA_OK)
			return 3;
	}
	elapsed = now_ns() - start;
	printf("FMA_BENCH rounds=%u admitted=%u completed=%u total_ns=%llu ns_per_round=%llu\n",
		FMA_BENCH_ROUNDS, FMA_BENCH_ROUNDS, FMA_BENCH_ROUNDS,
		(unsigned long long)elapsed,
		(unsigned long long)(elapsed / FMA_BENCH_ROUNDS));
	printf("FMA_BENCH_SCOPE=local_userspace_policy_fixture_not_model_inference_or_paid_provider_latency\n");
	return 0;
}
