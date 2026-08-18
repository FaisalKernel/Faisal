#include "../../faisal-adaptive/faisal_adaptive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 1024U

static uint64_t clock_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_digest(uint8_t digest[FAP_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value == 0U ? 1U : value, FAP_DIGEST_SIZE);
}

static struct fap_policy make_policy(void)
{
	struct fap_policy p;

	memset(&p, 0, sizeof(p));
	p.current_time_ns = 1000U;
	p.observation_max_age_ns = 10000U;
	p.minimum_admission_permille = 100U;
	p.maximum_admission_permille = 1000U;
	p.minimum_migration_permille = 0U;
	p.maximum_migration_permille = 1000U;
	p.minimum_lease_permille = 100U;
	p.maximum_lease_permille = 1000U;
	p.minimum_priority_delta = -100;
	p.maximum_priority_delta = 100;
	p.maximum_action_delta = 50U;
	p.maximum_queue_depth = 1000U;
	p.maximum_pressure_permille = 900U;
	p.maximum_thermal_permille = 900U;
	p.minimum_health_permille = 500U;
	p.baseline.admission_permille = 500U;
	p.baseline.migration_permille = 500U;
	p.baseline.lease_permille = 500U;
	p.fallback.admission_permille = 200U;
	p.fallback.migration_permille = 800U;
	p.fallback.lease_permille = 300U;
	p.fallback.priority_delta = -50;
	fill_digest(p.authority_digest, 0xA1U);
	return p;
}

int main(void)
{
	char path[128];
	struct fap_policy policy = make_policy();
	struct fap_service service;
	struct fap_observation observation;
	struct fap_recommendation recommendation;
	struct fap_action action;
	uint64_t start;
	uint64_t adaptive_elapsed;
	uint64_t fixed_elapsed;
	uint32_t fixed_admission = 500U;
	uint32_t fixed_migration = 500U;

	snprintf(path, sizeof(path), "/tmp/faisal-adaptive-bench-%ld.journal", (long)getpid());
	unlink(path);
	if (fap_open(&service, path, &policy) != FAP_OK)
		return 1;
	start = clock_ns();
	for (uint64_t i = 1U; i <= ROUNDS; ++i) {
		memset(&observation, 0, sizeof(observation));
		observation.observation_seq = i;
		observation.policy_generation = 1U;
		observation.observed_at_ns = 1000U;
		observation.source_generation = 1U;
		observation.queue_depth = (uint32_t)(100U + (i % 20U));
		observation.pressure_permille = (uint32_t)(200U + (i % 100U));
		observation.thermal_permille = 200U;
		observation.health_permille = 900U;
		observation.cache_hit_permille = (uint32_t)(700U + (i % 100U));
		observation.latency_ns = 100U;
		observation.throughput_units = i;
		fill_digest(observation.source_digest, 0xB1U);
		fill_digest(observation.provenance_digest, (uint8_t)(i + 1U));
		if (fap_observe(&service, &observation, &recommendation) != FAP_OK ||
		    fap_commit(&service, recommendation.recommendation_id, 1000U,
			       FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
			       FAP_FLAG_EXPERIMENTAL, &action) != FAP_OK)
			return 1;
	}
	adaptive_elapsed = clock_ns() - start;
	fap_close(&service);
	unlink(path);

	start = clock_ns();
	for (uint64_t i = 1U; i <= ROUNDS; ++i) {
		uint32_t pressure = (uint32_t)(200U + (i % 100U));
		if (pressure < 700U) {
			fixed_admission = fixed_admission < 950U ? fixed_admission + 50U : 1000U;
			fixed_migration = fixed_migration > 50U ? fixed_migration - 50U : 0U;
		} else {
			fixed_admission = fixed_admission > 150U ? fixed_admission - 50U : 100U;
			fixed_migration = fixed_migration < 950U ? fixed_migration + 50U : 1000U;
		}
		fixed_admission ^= (uint32_t)(i & 1U);
	}
	fixed_elapsed = clock_ns() - start;
	printf("M243_ADAPTIVE_BENCHMARK_EXIT=0 rounds=%u adaptive_elapsed_ns=%llu adaptive_ns_per_decision=%.2f fixed_elapsed_ns=%llu fixed_ns_per_decision=%.2f final_admission=%u final_migration=%u\n",
	       ROUNDS, (unsigned long long)adaptive_elapsed,
	       (double)adaptive_elapsed / ROUNDS,
	       (unsigned long long)fixed_elapsed,
	       (double)fixed_elapsed / ROUNDS,
	       fixed_admission, fixed_migration);
	return 0;
}
