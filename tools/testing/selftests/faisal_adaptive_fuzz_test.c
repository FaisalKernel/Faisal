#include "../../faisal-adaptive/faisal_adaptive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t next_rand(uint32_t *state)
{
	*state = *state * 1664525U + 1013904223U;
	return *state;
}

int main(void)
{
	char path[128];
	struct fap_policy policy;
	struct fap_service service;
	struct fap_event event;
	struct fap_observation observation;
	struct fap_recommendation recommendation;
	uint8_t payload[FAP_MAX_PAYLOAD];
	uint8_t previous[FAP_DIGEST_SIZE];
	uint32_t state = 0x243f00U;
	unsigned int rejected = 0U;
	unsigned int accepted = 0U;

	memset(&policy, 0, sizeof(policy));
	policy.current_time_ns = 1000U;
	policy.observation_max_age_ns = 10000U;
	policy.minimum_admission_permille = 100U;
	policy.maximum_admission_permille = 1000U;
	policy.minimum_migration_permille = 0U;
	policy.maximum_migration_permille = 1000U;
	policy.minimum_lease_permille = 100U;
	policy.maximum_lease_permille = 1000U;
	policy.minimum_priority_delta = -100;
	policy.maximum_priority_delta = 100;
	policy.maximum_action_delta = 50U;
	policy.maximum_queue_depth = 1000U;
	policy.maximum_pressure_permille = 900U;
	policy.maximum_thermal_permille = 900U;
	policy.minimum_health_permille = 500U;
	policy.baseline.admission_permille = 500U;
	policy.baseline.migration_permille = 500U;
	policy.baseline.lease_permille = 500U;
	policy.fallback.admission_permille = 200U;
	policy.fallback.migration_permille = 800U;
	policy.fallback.lease_permille = 300U;
	policy.fallback.priority_delta = -50;
	memset(policy.authority_digest, 0xA1, FAP_DIGEST_SIZE);
	snprintf(path, sizeof(path), "/tmp/faisal-adaptive-fuzz-%ld.journal", (long)getpid());
	unlink(path);
	if (fap_open(&service, path, &policy) != FAP_OK)
		return 1;
	for (unsigned int i = 0U; i < 10000U; ++i) {
		memset(&event, 0, sizeof(event));
		memset(&observation, 0, sizeof(observation));
		memset(&recommendation, 0, sizeof(recommendation));
		memset(payload, 0, sizeof(payload));
		memset(previous, 0, sizeof(previous));
		for (size_t j = 0U; j < sizeof(event); ++j)
			((uint8_t *)&event)[j] = (uint8_t)next_rand(&state);
		for (size_t j = 0U; j < sizeof(payload); ++j)
			payload[j] = (uint8_t)next_rand(&state);
		if (fap_verify_event(&event, payload, previous) == FAP_OK)
			accepted++;
		else
			rejected++;
		observation.observation_seq = next_rand(&state);
		observation.policy_generation = next_rand(&state);
		observation.observed_at_ns = next_rand(&state);
		observation.source_generation = next_rand(&state);
		observation.queue_depth = next_rand(&state);
		observation.pressure_permille = next_rand(&state);
		observation.thermal_permille = next_rand(&state);
		observation.health_permille = next_rand(&state);
		observation.cache_hit_permille = next_rand(&state);
		observation.deadline_misses = next_rand(&state);
		observation.latency_ns = next_rand(&state);
		observation.throughput_units = next_rand(&state);
		memset(observation.source_digest, (int)next_rand(&state), FAP_DIGEST_SIZE);
		memset(observation.provenance_digest, (int)next_rand(&state), FAP_DIGEST_SIZE);
		(void)fap_observe(&service, &observation, &recommendation);
		recommendation.recommendation_id = next_rand(&state);
		recommendation.observation_seq = next_rand(&state);
		recommendation.policy_generation = next_rand(&state);
		recommendation.flags = next_rand(&state);
		recommendation.action.admission_permille = next_rand(&state);
		recommendation.action.migration_permille = next_rand(&state);
		recommendation.action.lease_permille = next_rand(&state);
		recommendation.action.priority_delta = (int32_t)next_rand(&state);
		(void)fap_propose(&service, &recommendation, &recommendation);
	}
	fap_close(&service);
	unlink(path);
	if (accepted != 0U || rejected != 10000U)
		return 1;
	printf("M243_ADAPTIVE_FUZZ_EXIT=0 iterations=10000 rejected=%u accepted=%u\n",
	       rejected, accepted);
	return 0;
}
