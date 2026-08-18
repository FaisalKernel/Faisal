#include "../../faisal-adaptive/faisal_adaptive.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define READERS 4U
#define OBSERVATIONS 512U

struct shared {
	struct fap_service *service;
	atomic_int failures;
	atomic_int stop;
};

static void digest(uint8_t out[FAP_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FAP_DIGEST_SIZE);
}

static struct fap_policy policy(void)
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
	digest(p.authority_digest, 0xA1U);
	return p;
}

static void *reader(void *opaque)
{
	struct shared *shared = opaque;

	while (!atomic_load(&shared->stop)) {
		struct fap_attestation attestation;
		if (fap_query(shared->service, &attestation) != FAP_OK)
			atomic_fetch_add(&shared->failures, 1);
	}
	return NULL;
}

int main(void)
{
	char path[128];
	struct fap_policy p = policy();
	struct fap_service service;
	struct shared shared;
	pthread_t readers[READERS];
	struct fap_observation observation;
	struct fap_recommendation recommendation;
	struct fap_action action;
	struct fap_attestation attestation;
	unsigned int i;

	snprintf(path, sizeof(path), "/tmp/faisal-adaptive-concurrency-%ld.journal", (long)getpid());
	unlink(path);
	if (fap_open(&service, path, &p) != FAP_OK)
		return 1;
	shared.service = &service;
	atomic_init(&shared.failures, 0);
	atomic_init(&shared.stop, 0);
	for (i = 0U; i < READERS; ++i)
		if (pthread_create(&readers[i], NULL, reader, &shared) != 0)
			return 1;
	for (uint64_t seq = 1U; seq <= OBSERVATIONS; ++seq) {
		memset(&observation, 0, sizeof(observation));
		observation.observation_seq = seq;
		observation.policy_generation = 1U;
		observation.observed_at_ns = 1000U;
		observation.source_generation = 1U;
		observation.queue_depth = (uint32_t)(100U + (seq % 50U));
		observation.pressure_permille = (uint32_t)(200U + (seq % 100U));
		observation.thermal_permille = 200U;
		observation.health_permille = 900U;
		observation.cache_hit_permille = 700U;
		observation.latency_ns = 100U;
		observation.throughput_units = seq;
		digest(observation.source_digest, 0xB1U);
		digest(observation.provenance_digest, (uint8_t)(seq + 1U));
		if (fap_observe(&service, &observation, &recommendation) != FAP_OK ||
		    fap_commit(&service, recommendation.recommendation_id, 1000U,
			       FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
			       FAP_FLAG_EXPERIMENTAL, &action) != FAP_OK)
			atomic_fetch_add(&shared.failures, 1);
	}
	atomic_store(&shared.stop, 1);
	for (i = 0U; i < READERS; ++i)
		if (pthread_join(readers[i], NULL) != 0)
			return 1;
	if (atomic_load(&shared.failures) != 0 || fap_query(&service, &attestation) != FAP_OK ||
	    attestation.last_observation_seq != OBSERVATIONS ||
	    attestation.policy_generation != 1U)
		return 1;
	fap_close(&service);
	if (fap_open(&service, path, &p) != FAP_OK ||
	    fap_query(&service, &attestation) != FAP_OK ||
	    attestation.last_observation_seq != OBSERVATIONS)
		return 1;
	fap_close(&service);
	unlink(path);
	printf("M243_ADAPTIVE_CONCURRENCY_EXIT=0 readers=%u observations=%u failures=%d\n",
	       READERS, OBSERVATIONS, atomic_load(&shared.failures));
	return 0;
}
