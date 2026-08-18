#include "../../faisal-adaptive/faisal_adaptive.h"
#include "../../faisal-optimizer/faisal_optimizer.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 512U

static uint64_t clock_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0U;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void digest(uint8_t value, uint8_t out[FAO_DIGEST_SIZE])
{
	memset(out, value == 0U ? 1U : value, FAO_DIGEST_SIZE);
}

static struct fap_policy adaptive_policy(void)
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
	digest(0xA1U, p.authority_digest);
	return p;
}

static struct fao_policy optimizer_policy(void)
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

int main(void)
{
	char fap_path[128];
	char fao_path[128];
	struct fap_service adaptive;
	struct fao_service optimizer;
	struct fap_policy ap = adaptive_policy();
	struct fao_policy op = optimizer_policy();
	struct fap_observation ao;
	struct fap_recommendation recommendation;
	struct fao_sample sample;
	struct fao_forecast forecast;
	uint64_t start;
	uint64_t adaptive_elapsed;
	uint64_t static_elapsed;
	uint32_t admission = 500U;
	uint32_t migration = 500U;
	uint64_t latency_sum = 0U;

	snprintf(fap_path, sizeof(fap_path), "/tmp/faisal-optimizer-bench-fap-%ld.journal", (long)getpid());
	snprintf(fao_path, sizeof(fao_path), "/tmp/faisal-optimizer-bench-fao-%ld.journal", (long)getpid());
	unlink(fap_path);
	unlink(fao_path);
	if (fap_open(&adaptive, fap_path, &ap) != FAP_OK ||
	    fao_open(&optimizer, fao_path, &op, &adaptive) != FAO_OK)
		return 1;
	start = clock_ns();
	for (uint64_t sequence = 1U; sequence <= ROUNDS; ++sequence) {
		memset(&ao, 0, sizeof(ao));
		ao.observation_seq = sequence;
		ao.policy_generation = 1U;
		ao.observed_at_ns = 1000U;
		ao.source_generation = 1U;
		ao.queue_depth = 100U + (uint32_t)(sequence % 50U);
		ao.pressure_permille = 200U + (uint32_t)(sequence % 100U);
		ao.thermal_permille = 200U;
		ao.health_permille = 900U;
		ao.cache_hit_permille = 800U;
		ao.latency_ns = 100U + sequence % 10U;
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
		sample.latency_ns = ao.latency_ns;
		sample.throughput_units = ao.throughput_units;
		digest(0xC1U, sample.source_digest);
		digest((uint8_t)(0xC2U + sequence), sample.provenance_digest);
		if (fap_observe(&adaptive, &ao, &recommendation) != FAP_OK ||
		    fao_ingest(&optimizer, &sample, &forecast) != FAO_OK)
			return 1;
	}
	adaptive_elapsed = clock_ns() - start;
	fao_close(&optimizer);
	fap_close(&adaptive);
	unlink(fap_path);
	unlink(fao_path);

	start = clock_ns();
	for (uint64_t sequence = 1U; sequence <= ROUNDS; ++sequence) {
		uint32_t pressure = 200U + (uint32_t)(sequence % 100U);
		uint64_t latency = 100U + sequence % 10U;
		latency_sum += latency;
		if (pressure > 700U || latency > 150U) {
			admission = admission > 150U ? admission - 50U : 100U;
			migration = migration < 950U ? migration + 50U : 1000U;
		} else {
			admission = admission < 950U ? admission + 50U : 1000U;
			migration = migration > 50U ? migration - 50U : 0U;
		}
	}
	static_elapsed = clock_ns() - start;
	printf("M244_OPTIMIZER_BENCHMARK_EXIT=0 rounds=%u durable_observe_forecast_ns=%llu durable_ns_per_sample=%.2f static_elapsed_ns=%llu static_ns_per_sample=%.2f final_admission=%u final_migration=%u latency_sum=%llu\n",
	       ROUNDS, (unsigned long long)adaptive_elapsed,
	       (double)adaptive_elapsed / ROUNDS,
	       (unsigned long long)static_elapsed,
	       (double)static_elapsed / ROUNDS,
	       admission, migration, (unsigned long long)latency_sum);
	return 0;
}
