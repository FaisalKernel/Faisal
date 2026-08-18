#include "../../faisal-adaptive/faisal_adaptive.h"
#include "../../faisal-optimizer/faisal_optimizer.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int cases_run;
static unsigned int rejected;

static void expect_code(const char *name, int actual, int expected)
{
	++cases_run;
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual, expected);
		exit(1);
	}
}

static void expect_true(const char *name, int condition)
{
	++cases_run;
	if (!condition) {
		fprintf(stderr, "FAIL %s\n", name);
		exit(1);
	}
}

static void digest(uint8_t value, uint8_t out[FAO_DIGEST_SIZE])
{
	memset(out, value == 0U ? 1U : value, FAO_DIGEST_SIZE);
}

static struct fap_policy make_adaptive_policy(void)
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

static struct fao_policy make_optimizer_policy(void)
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

static struct fap_observation make_fap_observation(uint64_t sequence)
{
	struct fap_observation o;

	memset(&o, 0, sizeof(o));
	o.observation_seq = sequence;
	o.policy_generation = 1U;
	o.observed_at_ns = 1000U;
	o.source_generation = 1U;
	o.queue_depth = 100U;
	o.pressure_permille = 200U;
	o.thermal_permille = 200U;
	o.health_permille = 900U;
	o.cache_hit_permille = 800U;
	o.latency_ns = 100U;
	o.throughput_units = 1000U;
	digest(0xB1U, o.source_digest);
	digest((uint8_t)(0xB2U + sequence), o.provenance_digest);
	return o;
}

static struct fao_sample make_sample(uint64_t sequence, uint32_t lane,
				     uint64_t latency, uint64_t throughput)
{
	struct fao_sample s;

	memset(&s, 0, sizeof(s));
	s.sequence = sequence;
	s.policy_generation = 1U;
	s.observed_at_ns = 1000U;
	s.source_generation = 1U;
	s.lane = lane;
	s.queue_depth = 100U;
	s.pressure_permille = 200U;
	s.thermal_permille = 200U;
	s.health_permille = 900U;
	s.cache_hit_permille = 800U;
	s.latency_ns = latency;
	s.throughput_units = throughput;
	digest(0xC1U, s.source_digest);
	digest((uint8_t)(0xC2U + sequence), s.provenance_digest);
	return s;
}

static void remove_pair(const char *fap_path, const char *fao_path)
{
	unlink(fap_path);
	unlink(fao_path);
}

int main(void)
{
	char fap_path[128];
	char fao_path[128];
	char fail_fap_path[128];
	char fail_fao_path[128];
	struct fap_service adaptive;
	struct fap_service fail_adaptive;
	struct fao_service optimizer;
	struct fao_service fail_optimizer;
	struct fao_service recovered;
	struct fao_service tampered;
	struct fap_policy adaptive_policy = make_adaptive_policy();
	struct fao_policy optimizer_policy = make_optimizer_policy();
	struct fap_recommendation recommendation;
	struct fap_recommendation model_recommendation;
	struct fao_forecast forecast;
	struct fao_candidate candidate;
	struct fao_compare compare;
	struct fao_attestation attestation;
	int fd;
	uint8_t byte;

	snprintf(fap_path, sizeof(fap_path), "/tmp/faisal-optimizer-fap-%ld.journal", (long)getpid());
	snprintf(fao_path, sizeof(fao_path), "/tmp/faisal-optimizer-fao-%ld.journal", (long)getpid());
	snprintf(fail_fap_path, sizeof(fail_fap_path), "/tmp/faisal-optimizer-fail-fap-%ld.journal", (long)getpid());
	snprintf(fail_fao_path, sizeof(fail_fao_path), "/tmp/faisal-optimizer-fail-fao-%ld.journal", (long)getpid());
	remove_pair(fap_path, fao_path);
	remove_pair(fail_fap_path, fail_fao_path);

	expect_code("adaptive-open", fap_open(&adaptive, fap_path, &adaptive_policy), FAP_OK);
	expect_code("optimizer-open", fao_open(&optimizer, fao_path, &optimizer_policy, &adaptive), FAO_OK);
	for (uint64_t sequence = 1U; sequence <= 4U; ++sequence) {
		struct fap_observation fap_observation = make_fap_observation(sequence);
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CONTROL, 100U, 1000U);
		expect_code("adaptive-observe", fap_observe(&adaptive, &fap_observation, &recommendation), FAP_OK);
		expect_code("optimizer-ingest", fao_ingest(&optimizer, &sample, &forecast), FAO_OK);
	}
	expect_true("forecast-confidence", forecast.confidence_permille >= 100U && forecast.risk_permille <= 700U);
	expect_code("attach-candidate", fao_attach_recommendation(&optimizer, &recommendation, &candidate), FAO_OK);
	expect_code("approve-missing-authority", fao_approve(&optimizer, candidate.candidate_id, 1000U,
								 FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL), FAO_ERR_AUTHORITY);
	++rejected;
	expect_code("approve-candidate", fao_approve(&optimizer, candidate.candidate_id, 1000U,
								 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
								 FAO_FLAG_EXPERIMENTAL), FAO_OK);
	expect_code("begin-canary", fao_begin_canary(&optimizer, candidate.candidate_id, 1000U,
								 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
								 FAO_FLAG_EXPERIMENTAL), FAO_OK);
	for (uint64_t sequence = 5U; sequence <= 8U; ++sequence) {
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CONTROL, 100U, 1000U);
		expect_code("control-ingest", fao_ingest(&optimizer, &sample, &forecast), FAO_OK);
	}
	for (uint64_t sequence = 9U; sequence <= 12U; ++sequence) {
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CANARY, 100U, 1000U);
		expect_code("canary-ingest", fao_ingest(&optimizer, &sample, &forecast), FAO_OK);
	}
	expect_code("monitor-good-canary", fao_monitor(&optimizer, 1000U,
						 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
						 FAO_FLAG_EXPERIMENTAL, &compare), FAO_OK);
	expect_true("canary-active", compare.regression_flags == 0U);
	expect_code("optimizer-query-active", fao_query(&optimizer, &attestation), FAO_OK);
	expect_true("active-stage", attestation.stage == FAO_STAGE_ACTIVE && attestation.rollback_count == 0U);
	fao_close(&optimizer);
	fap_close(&adaptive);

	expect_code("adaptive-replay-open", fap_open(&adaptive, fap_path, &adaptive_policy), FAP_OK);
	expect_code("optimizer-replay-open", fao_open(&recovered, fao_path, &optimizer_policy, &adaptive), FAO_OK);
	expect_code("optimizer-replay-query", fao_query(&recovered, &attestation), FAO_OK);
	expect_true("replay-active", attestation.stage == FAO_STAGE_ACTIVE && attestation.sample_sequence == 12U);
	fao_close(&recovered);
	fap_close(&adaptive);

	expect_code("fail-adaptive-open", fap_open(&fail_adaptive, fail_fap_path, &adaptive_policy), FAP_OK);
	expect_code("fail-optimizer-open", fao_open(&fail_optimizer, fail_fao_path, &optimizer_policy, &fail_adaptive), FAO_OK);
	for (uint64_t sequence = 1U; sequence <= 4U; ++sequence) {
		struct fap_observation fap_observation = make_fap_observation(sequence);
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CONTROL, 100U, 1000U);
		expect_code("fail-adaptive-observe", fap_observe(&fail_adaptive, &fap_observation, &model_recommendation), FAP_OK);
		expect_code("fail-ingest", fao_ingest(&fail_optimizer, &sample, &forecast), FAO_OK);
	}
	expect_code("fail-attach", fao_attach_recommendation(&fail_optimizer, &model_recommendation, &candidate), FAO_OK);
	expect_code("fail-approve", fao_approve(&fail_optimizer, candidate.candidate_id, 1000U,
							 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
							 FAO_FLAG_EXPERIMENTAL), FAO_OK);
	expect_code("fail-canary", fao_begin_canary(&fail_optimizer, candidate.candidate_id, 1000U,
							 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
							 FAO_FLAG_EXPERIMENTAL), FAO_OK);
	for (uint64_t sequence = 5U; sequence <= 8U; ++sequence) {
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CONTROL, 100U, 1000U);
		expect_code("fail-control-ingest", fao_ingest(&fail_optimizer, &sample, &forecast), FAO_OK);
	}
	for (uint64_t sequence = 9U; sequence <= 12U; ++sequence) {
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CANARY, 300U, 1000U);
		expect_code("bad-canary-ingest", fao_ingest(&fail_optimizer, &sample, &forecast), FAO_OK);
	}
	expect_code("automatic-rollback", fao_monitor(&fail_optimizer, 1000U,
						 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
						 FAO_FLAG_EXPERIMENTAL, &compare), FAO_OK);
	expect_true("rollback-regression-flag", (compare.regression_flags & FAO_REGRESSION_LATENCY) != 0U);
	expect_code("rollback-query", fao_query(&fail_optimizer, &attestation), FAO_OK);
	expect_true("rolled-back-stage", attestation.stage == FAO_STAGE_ROLLED_BACK &&
			 attestation.rollback_count == 1U && attestation.policy_generation == 2U);
	fao_close(&fail_optimizer);
	fap_close(&fail_adaptive);

	/* Model advisory candidates cannot be approved. */
	remove_pair(fail_fap_path, fail_fao_path);
	expect_code("model-adaptive-open", fap_open(&fail_adaptive, fail_fap_path, &adaptive_policy), FAP_OK);
	expect_code("model-optimizer-open", fao_open(&fail_optimizer, fail_fao_path, &optimizer_policy, &fail_adaptive), FAO_OK);
	for (uint64_t sequence = 1U; sequence <= 4U; ++sequence) {
		struct fap_observation fap_observation = make_fap_observation(sequence);
		struct fao_sample sample = make_sample(sequence, FAO_LANE_CONTROL, 100U, 1000U);
		expect_code("model-adaptive-observe", fap_observe(&fail_adaptive, &fap_observation, &model_recommendation), FAP_OK);
		expect_code("model-ingest", fao_ingest(&fail_optimizer, &sample, &forecast), FAO_OK);
	}
	model_recommendation.flags |= FAP_FLAG_MODEL_PROPOSAL;
	expect_code("model-attach", fao_attach_recommendation(&fail_optimizer, &model_recommendation, &candidate), FAO_OK);
	expect_code("model-approval-rejected", fao_approve(&fail_optimizer, candidate.candidate_id, 1000U,
							 FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT |
							 FAO_FLAG_EXPERIMENTAL), FAO_ERR_AUTHORITY);
	++rejected;
	fao_close(&fail_optimizer);
	fap_close(&fail_adaptive);

	fd = open(fao_path, O_RDWR);
	expect_true("tamper-open", fd >= 0);
	expect_true("tamper-read", lseek(fd, (off_t)(sizeof(struct fao_event) - FAO_DIGEST_SIZE), SEEK_SET) >= 0 &&
			 read(fd, &byte, 1) == 1);
	byte ^= 0xffU;
	expect_true("tamper-write", lseek(fd, (off_t)(sizeof(struct fao_event) - FAO_DIGEST_SIZE), SEEK_SET) >= 0 &&
			 write(fd, &byte, 1) == 1);
	close(fd);
	expect_code("tampered-replay", fap_open(&adaptive, fap_path, &adaptive_policy), FAP_OK);
	expect_code("optimizer-tamper-reject", fao_open(&tampered, fao_path, &optimizer_policy, &adaptive), FAO_ERR_REPLAY);
	++rejected;
	fap_close(&adaptive);

	remove_pair(fap_path, fao_path);
	remove_pair(fail_fap_path, fail_fao_path);
	printf("M244_OPTIMIZER_SELFTEST_EXIT=0 cases=%u mutation_rejections=%u\n", cases_run, rejected);
	return 0;
}
