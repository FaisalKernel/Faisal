#include "../../faisal-evolution/faisal_evolution.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_digest(uint8_t digest[FEV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FEV_DIGEST_SIZE);
}

int main(void)
{
	const char *journal = "/tmp/faisal-evolution-benchmark.journal";
	struct fev_service service;
	struct fev_policy policy;
	struct fev_candidate candidate;
	struct fev_candidate isolated;
	struct fev_candidate validated;
	struct fev_candidate promoted;
	struct fev_receipt receipt;
	uint8_t research[FEV_DIGEST_SIZE];
	uint8_t baseline[FEV_DIGEST_SIZE];
	uint8_t artifact[FEV_DIGEST_SIZE];
	uint8_t evidence[FEV_DIGEST_SIZE];
	uint8_t approval[FEV_DIGEST_SIZE];
	uint64_t start;
	uint64_t lifecycle_elapsed;
	uint64_t raw_elapsed;
	uint64_t checksum = 0;
	uint64_t i;
	const uint64_t rounds = 32U;

	fill_digest(research, 0x11U);
	fill_digest(baseline, 0x22U);
	fill_digest(artifact, 0x33U);
	fill_digest(evidence, 0x44U);
	fill_digest(approval, 0x55U);
	memset(&policy, 0, sizeof(policy));
	policy.min_improvement_ppm = 1000U;
	policy.require_reproducible = 1U;
	policy.require_rollback = 1U;
	policy.require_research = 1U;
	policy.require_external_approval = 1U;
	unlink(journal);
	assert(fev_open(&service, journal) == FEV_OK);
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		uint64_t id = 100U + i;
		assert(fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
				   FEV_METRIC_LOWER_BETTER, 100000U,
				   "source-head", "parent-head", "rollback-tag",
				   research, baseline, artifact, &policy, &candidate) == FEV_OK);
		assert(fev_isolate(&service, id, &isolated) == FEV_OK);
		assert(fev_record_validation(&service, id, 1U, 1U, 90000U,
					     evidence, approval, &validated) == FEV_OK);
		assert(fev_promote(&service, id, &promoted, &receipt) == FEV_OK);
		assert(fev_verify_receipt(&receipt) == FEV_OK);
		checksum ^= promoted.candidate_id ^ promoted.improvement_ppm;
	}
	lifecycle_elapsed = now_ns() - start;
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		uint64_t baseline_metric = 100000U;
		uint64_t candidate_metric = 90000U;
		checksum ^= baseline_metric > candidate_metric ?
			baseline_metric - candidate_metric : candidate_metric - baseline_metric;
	}
	raw_elapsed = now_ns() - start;
	printf("FEV_EVOLUTION_BENCHMARK_OK rounds=%" PRIu64
	       " lifecycle_transitions=%" PRIu64
	       " lifecycle_elapsed_ns=%" PRIu64
	       " raw_metric_compare_ns=%" PRIu64
	       " lifecycle_ns_per_transition=%.2f raw_ns_per_round=%.2f"
	       " durability=fsync_per_transition checksum=%" PRIu64 "\n",
	       rounds, rounds * 4U, lifecycle_elapsed, raw_elapsed,
	       (double)lifecycle_elapsed / (double)(rounds * 4U),
	       (double)raw_elapsed / (double)rounds, checksum);
	fev_close(&service);
	unlink(journal);
	return 0;
}
