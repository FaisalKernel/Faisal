#define _GNU_SOURCE
#include "../../faisal-experience/faisal_experience_evidence.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void make_input(struct fee_input *input, uint64_t request_sequence)
{
	memset(input, 0, sizeof(*input));
	input->request_sequence = request_sequence;
	input->verification_status = FEE_VERIFICATION_VERIFIED;
	input->authority_grant = 1;
	input->confidence_ppm = 900000;
	input->impact_ppm = 800000;
	input->novelty_ppm = 700000;
	input->recurrence_ppm = 600000;
	input->now_ns = 1000 + request_sequence;
	input->provenance.present_mask = FEE_PROVENANCE_ALL;
	input->provenance.source_sequence = 1;
	input->provenance.provider_generation = 2;
	input->provenance.sandbox_generation = 3;
	input->provenance.verifier_sequence = 4;
	input->provenance.observed_at_ns = 900;
	input->provenance.expires_at_ns = UINT64_MAX;
	strcpy(input->provenance.source, "benchmark-source");
	strcpy(input->provenance.provider, "provider-neutral");
	strcpy(input->provenance.model, "benchmark-model");
	strcpy(input->provenance.tool, "benchmark-tool");
	strcpy(input->provenance.sandbox, "benchmark-sandbox");
	strcpy(input->provenance.verifier, "benchmark-verifier");
	strcpy(input->key, "benchmark-key");
	strcpy(input->action, "benchmark action");
	strcpy(input->observation, "bounded observation");
	strcpy(input->result, "verified result");
	strcpy(input->lesson, "replay-safe lesson");
	strcpy(input->skill, "bounded skill");
}

int main(void)
{
	const uint64_t rounds = FEE_MAX_REUSE;
	struct fee_policy policy = {
		.required_provenance_mask = FEE_PROVENANCE_ALL,
		.minimum_confidence_ppm = 700000,
		.minimum_importance_ppm = 700000,
	};
	struct fee_service service;
	struct fee_input input;
	struct fee_record record;
	uint64_t start, elapsed;
	uint64_t i;
	uint64_t operations = 0;

	fee_init(&service, &policy);
	make_input(&input, 1);
	if (fee_record(&service, &input, &record) != FEE_OK)
		return 1;
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		if (fee_retrieve(&service, "benchmark-key", 5000, &record) != FEE_OK)
			return 2;
		if (fee_verify(&service, &record) != FEE_OK)
			return 3;
		if (fee_reuse(&service, record.sequence, 5000, &record) != FEE_OK)
			return 4;
		operations += 3;
	}
	elapsed = now_ns() - start;
	printf("M229_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M229_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M229_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M229_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M229_BENCHMARK_REUSE_COUNT=%llu\n",
	       (unsigned long long)record.reuse_count);
	printf("M229_BENCHMARK_EXIT=0\n");
	return 0;
}
