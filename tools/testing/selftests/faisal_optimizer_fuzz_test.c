#include "../../faisal-adaptive/faisal_adaptive.h"
#include "../../faisal-optimizer/faisal_optimizer.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ITERATIONS 10000U

static uint32_t next_value(uint32_t *state)
{
	*state = *state * 1664525U + 1013904223U;
	return *state;
}

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
	p.fallback.admission_permille = 500U;
	p.fallback.migration_permille = 500U;
	p.fallback.lease_permille = 500U;
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

int main(void)
{
	char fap_path[128];
	char fao_path[128];
	struct fap_service adaptive;
	struct fao_service optimizer;
	struct fao_event event;
	struct fao_sample sample;
	uint8_t payload[FAO_MAX_PAYLOAD];
	uint8_t previous[FAO_DIGEST_SIZE] = {0};
	uint32_t state = 0x243244U;
	unsigned int rejected = 0U;
	unsigned int accepted = 0U;

	snprintf(fap_path, sizeof(fap_path), "/tmp/faisal-optimizer-fuzz-fap-%ld.journal", (long)getpid());
	snprintf(fao_path, sizeof(fao_path), "/tmp/faisal-optimizer-fuzz-fao-%ld.journal", (long)getpid());
	unlink(fap_path);
	unlink(fao_path);
	{
		struct fap_policy ap = apolicy();
		struct fao_policy op = opolicy();
		int adaptive_result = fap_open(&adaptive, fap_path, &ap);
		int optimizer_result = adaptive_result == FAP_OK ? fao_open(&optimizer, fao_path, &op, &adaptive) : FAO_ERR_IO;
		if (adaptive_result != FAP_OK || optimizer_result != FAO_OK)
			return 1;
	}
	for (unsigned int i = 0U; i < ITERATIONS; ++i) {
		memset(&event, 0, sizeof(event));
		memset(payload, 0, sizeof(payload));
		event.magic = FAO_EVENT_MAGIC;
		event.version = FAO_EVENT_VERSION;
		event.kind = (uint16_t)(next_value(&state) % 8U);
		event.sequence = next_value(&state);
		event.policy_generation = next_value(&state);
		event.payload_len = next_value(&state) % (FAO_MAX_PAYLOAD + 1U);
		for (size_t j = 0U; j < FAO_DIGEST_SIZE; ++j) {
			event.previous_digest[j] = (uint8_t)next_value(&state);
			event.payload_digest[j] = (uint8_t)next_value(&state);
			event.event_digest[j] = (uint8_t)next_value(&state);
			previous[j] = (uint8_t)next_value(&state);
		}
		for (size_t j = 0U; j < event.payload_len; ++j)
			payload[j] = (uint8_t)next_value(&state);
		if (fao_verify_event(&event, payload, previous) == FAO_OK)
			++accepted;
		else
			++rejected;

		memset(&sample, 0, sizeof(sample));
		sample.sequence = next_value(&state);
		sample.policy_generation = next_value(&state);
		sample.observed_at_ns = next_value(&state);
		sample.source_generation = next_value(&state);
		sample.lane = next_value(&state);
		sample.queue_depth = next_value(&state);
		sample.pressure_permille = next_value(&state);
		sample.thermal_permille = next_value(&state);
		sample.health_permille = next_value(&state);
		sample.cache_hit_permille = next_value(&state);
		sample.latency_ns = next_value(&state);
		sample.throughput_units = next_value(&state);
		digest((uint8_t)next_value(&state), sample.source_digest);
		digest((uint8_t)next_value(&state), sample.provenance_digest);
		{
			struct fao_forecast forecast;
			int result = fao_ingest(&optimizer, &sample, &forecast);
			if (result != FAO_OK)
				++rejected;
			else {
				++accepted;
				fprintf(stderr, "UNEXPECTED_SAMPLE_ACCEPT iteration=%u result=%d sequence=%llu generation=%llu observed=%llu source_generation=%llu lane=%u queue=%u pressure=%u thermal=%u health=%u\n", i, result, (unsigned long long)sample.sequence, (unsigned long long)sample.policy_generation, (unsigned long long)sample.observed_at_ns, (unsigned long long)sample.source_generation, sample.lane, sample.queue_depth, sample.pressure_permille, sample.thermal_permille, sample.health_permille);
			}
		}
	}
	fao_close(&optimizer);
	fap_close(&adaptive);
	unlink(fap_path);
	unlink(fao_path);
	if (accepted != 0U || rejected < ITERATIONS)
		return 1;
	printf("M244_OPTIMIZER_FUZZ_EXIT=0 iterations=%u rejected=%u accepted=%u\n",
	       ITERATIONS, rejected, accepted);
	return 0;
}
