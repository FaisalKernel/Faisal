#include "../../faisal-adaptive/faisal_adaptive.h"
#include "../../faisal-optimizer/faisal_optimizer.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define READERS 4U
#define ROUNDS 256U

struct shared {
	struct fao_service *optimizer;
	atomic_int stop;
	atomic_int failures;
};

static void digest(uint8_t value, uint8_t out[FAO_DIGEST_SIZE])
{
	memset(out, value == 0U ? 1U : value, FAO_DIGEST_SIZE);
}

static struct fap_policy apolicy(void)
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
	digest(0xA1U, p.authority_digest);
	return p;
}

static struct fao_policy opolicy(void)
{
	struct fao_policy p;

	memset(&p, 0, sizeof(p));
	p.now_ns = 1000U;
	p.max_age_ns = 10000U;
	p.minimum_canary_samples = 4U;
	p.maximum_latency_increase_permille = 100U;
	p.maximum_throughput_decrease_permille = 100U;
	p.maximum_pressure_permille = 900U;
	p.maximum_thermal_permille = 900U;
	p.minimum_health_permille = 500U;
	p.maximum_queue_depth = 1000U;
	p.maximum_forecast_risk_permille = 700U;
	p.minimum_confidence_permille = 100U;
	digest(0xA2U, p.authority_digest);
	return p;
}

static void *reader(void *opaque)
{
	struct shared *shared = opaque;

	while (!atomic_load(&shared->stop)) {
		struct fao_attestation attestation;
		if (fao_query(shared->optimizer, &attestation) != FAO_OK)
			atomic_fetch_add(&shared->failures, 1);
	}
	return NULL;
}

int main(void)
{
	char fap_path[128];
	char fao_path[128];
	struct fap_service adaptive;
	struct fao_service optimizer;
	struct fao_service recovered;
	struct shared shared;
	struct fap_policy ap = apolicy();
	struct fao_policy op = opolicy();
	pthread_t readers[READERS];
	struct fap_observation ao;
	struct fap_recommendation recommendation;
	struct fao_sample sample;
	struct fao_forecast forecast;
	struct fao_attestation attestation;
	unsigned int i;

	snprintf(fap_path, sizeof(fap_path), "/tmp/faisal-optimizer-concurrency-fap-%ld.journal", (long)getpid());
	snprintf(fao_path, sizeof(fao_path), "/tmp/faisal-optimizer-concurrency-fao-%ld.journal", (long)getpid());
	unlink(fap_path);
	unlink(fao_path);
	if (fap_open(&adaptive, fap_path, &ap) != FAP_OK ||
	    fao_open(&optimizer, fao_path, &op, &adaptive) != FAO_OK)
		return 1;
	shared.optimizer = &optimizer;
	atomic_init(&shared.stop, 0);
	atomic_init(&shared.failures, 0);
	for (i = 0U; i < READERS; ++i)
		if (pthread_create(&readers[i], NULL, reader, &shared) != 0)
			return 1;
	for (uint64_t sequence = 1U; sequence <= ROUNDS; ++sequence) {
		memset(&ao, 0, sizeof(ao));
		ao.observation_seq = sequence;
		ao.policy_generation = 1U;
		ao.observed_at_ns = 1000U;
		ao.source_generation = 1U;
		ao.queue_depth = 100U + (uint32_t)(sequence % 20U);
		ao.pressure_permille = 200U;
		ao.thermal_permille = 200U;
		ao.health_permille = 900U;
		ao.cache_hit_permille = 800U;
		ao.latency_ns = 100U;
		ao.throughput_units = 1000U + sequence;
		digest(0xB1U, ao.source_digest);
		digest((uint8_t)(0xB2U + sequence), ao.provenance_digest);
		memset(&sample, 0, sizeof(sample));
		sample.sequence = sequence;
		sample.policy_generation = 1U;
		sample.observed_at_ns = 1000U;
		sample.source_generation = 1U;
		sample.lane = FAO_LANE_CONTROL;
		sample.queue_depth = ao.queue_depth;
		sample.pressure_permille = ao.pressure_permille;
		sample.thermal_permille = ao.thermal_permille;
		sample.health_permille = ao.health_permille;
		sample.cache_hit_permille = ao.cache_hit_permille;
		sample.latency_ns = 100U;
		sample.throughput_units = 1000U + sequence;
		digest(0xC1U, sample.source_digest);
		digest((uint8_t)(0xC2U + sequence), sample.provenance_digest);
		if (fap_observe(&adaptive, &ao, &recommendation) != FAP_OK ||
		    fao_ingest(&optimizer, &sample, &forecast) != FAO_OK)
			atomic_fetch_add(&shared.failures, 1);
	}
	atomic_store(&shared.stop, 1);
	for (i = 0U; i < READERS; ++i)
		if (pthread_join(readers[i], NULL) != 0)
			return 1;
	if (atomic_load(&shared.failures) != 0 || fao_query(&optimizer, &attestation) != FAO_OK ||
	    attestation.sample_sequence != ROUNDS)
		return 1;
	fao_close(&optimizer);
	fap_close(&adaptive);
	if (fap_open(&adaptive, fap_path, &ap) != FAP_OK ||
	    fao_open(&recovered, fao_path, &op, &adaptive) != FAO_OK ||
	    fao_query(&recovered, &attestation) != FAO_OK ||
	    attestation.sample_sequence != ROUNDS)
		return 1;
	fao_close(&recovered);
	fap_close(&adaptive);
	unlink(fap_path);
	unlink(fao_path);
	printf("M244_OPTIMIZER_CONCURRENCY_EXIT=0 readers=%u samples=%u failures=%d\n",
	       READERS, ROUNDS, atomic_load(&shared.failures));
	return 0;
}
