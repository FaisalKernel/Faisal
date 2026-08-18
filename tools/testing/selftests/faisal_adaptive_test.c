#include "../../faisal-adaptive/faisal_adaptive.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int cases_run;
static unsigned int mutation_rejections;

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

static void fill_digest(uint8_t digest[FAP_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value == 0U ? 1U : value, FAP_DIGEST_SIZE);
}

static struct fap_policy make_policy(void)
{
	struct fap_policy policy;

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
	policy.baseline.priority_delta = 0;
	policy.fallback.admission_permille = 200U;
	policy.fallback.migration_permille = 800U;
	policy.fallback.lease_permille = 300U;
	policy.fallback.priority_delta = -50;
	fill_digest(policy.authority_digest, 0xA1U);
	return policy;
}

static struct fap_observation make_observation(uint64_t seq, uint32_t queue,
					       uint32_t pressure, uint32_t thermal,
					       uint32_t health, uint32_t cache,
					       uint32_t misses, uint64_t latency,
					       uint64_t throughput)
{
	struct fap_observation observation;

	memset(&observation, 0, sizeof(observation));
	observation.observation_seq = seq;
	observation.policy_generation = 1U;
	observation.observed_at_ns = 1000U;
	observation.source_generation = 1U;
	observation.queue_depth = queue;
	observation.pressure_permille = pressure;
	observation.thermal_permille = thermal;
	observation.health_permille = health;
	observation.cache_hit_permille = cache;
	observation.deadline_misses = misses;
	observation.latency_ns = latency;
	observation.throughput_units = throughput;
	fill_digest(observation.source_digest, 0xB1U);
	fill_digest(observation.provenance_digest, (uint8_t)(0xB2U + seq));
	return observation;
}

int main(void)
{
	char path[128];
	struct fap_service service;
	struct fap_service recovered;
	struct fap_service bad;
	struct fap_policy policy = make_policy();
	struct fap_observation observation;
	struct fap_recommendation recommendation;
	struct fap_recommendation recommendation2;
	struct fap_recommendation model_proposal;
	struct fap_action action;
	struct fap_action rollback_action;
	struct fap_attestation attestation;
	int fd;
	unsigned char byte;

	snprintf(path, sizeof(path), "/tmp/faisal-adaptive-%ld.journal", (long)getpid());
	unlink(path);
	expect_code("open", fap_open(&service, path, &policy), FAP_OK);

	observation = make_observation(1U, 100U, 200U, 200U, 900U, 700U, 0U, 100U, 1000U);
	expect_code("observe-baseline", fap_observe(&service, &observation, &recommendation), FAP_OK);
	expect_true("adaptive-recommendation", recommendation.action.mode == FAP_MODE_ADAPTIVE &&
			 recommendation.recommendation_id == 1U);
	expect_code("commit-without-authority", fap_commit(&service, recommendation.recommendation_id,
							  1010U, FAP_FLAG_VERIFIED_INPUT | FAP_FLAG_EXPERIMENTAL,
							  &action), FAP_ERR_AUTHORITY);
	++mutation_rejections;
	expect_code("commit-adaptive", fap_commit(&service, recommendation.recommendation_id, 1010U,
							 FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
							 FAP_FLAG_EXPERIMENTAL, &action), FAP_OK);
	expect_true("adaptive-action-bounded", action.admission_permille >= 100U &&
			 action.admission_permille <= 1000U);

	observation = make_observation(2U, 90U, 300U, 300U, 900U, 800U, 0U, 90U, 1100U);
	expect_code("observe-improving", fap_observe(&service, &observation, &recommendation2), FAP_OK);
	expect_true("improvement-action", recommendation2.action.admission_permille >= action.admission_permille);
	expect_code("commit-improving", fap_commit(&service, recommendation2.recommendation_id, 1020U,
							 FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
							 FAP_FLAG_EXPERIMENTAL, &action), FAP_OK);

	observation = make_observation(3U, 200U, 700U, 700U, 900U, 750U, 1U, 500U, 900U);
	expect_code("observe-unsafe", fap_observe(&service, &observation, &recommendation), FAP_OK);
	expect_true("fallback-mode", recommendation.action.mode == FAP_MODE_FALLBACK &&
			 (recommendation.flags & FAP_FLAG_FALLBACK) != 0U);
	expect_code("commit-fallback", fap_commit(&service, recommendation.recommendation_id, 1030U,
							 FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
							 FAP_FLAG_EXPERIMENTAL, &action), FAP_OK);

	model_proposal = recommendation;
	model_proposal.recommendation_id = 0U;
	model_proposal.flags = FAP_FLAG_VERIFIED_INPUT | FAP_FLAG_MODEL_PROPOSAL;
	model_proposal.source_kind = 99U;
	fill_digest(model_proposal.source_digest, 0xC1U);
	expect_code("model-proposal", fap_propose(&service, &model_proposal, &model_proposal), FAP_OK);
	expect_code("model-proposal-not-authority", fap_commit(&service, model_proposal.recommendation_id,
								1040U, FAP_FLAG_AUTHORITY_GRANTED |
								FAP_FLAG_VERIFIED_INPUT | FAP_FLAG_EXPERIMENTAL,
								&action), FAP_ERR_AUTHORITY);
	++mutation_rejections;

	observation = make_observation(1U, 10U, 100U, 100U, 900U, 900U, 0U, 50U, 1200U);
	expect_code("replay-observation-rejected", fap_observe(&service, &observation, &recommendation), FAP_ERR_REPLAY);
	++mutation_rejections;

	model_proposal = recommendation2;
	model_proposal.observation_seq = 3U;
	model_proposal.policy_generation = 1U;
	model_proposal.flags = FAP_FLAG_VERIFIED_INPUT;
	model_proposal.action.admission_permille = 1000U;
	model_proposal.action.mode = FAP_MODE_ADAPTIVE;
	fill_digest(model_proposal.source_digest, 0xC2U);
	expect_code("unsafe-delta-proposal", fap_propose(&service, &model_proposal, &recommendation), FAP_ERR_BOUNDS);
	++mutation_rejections;

	expect_code("rollback", fap_rollback(&service, 1050U,
						 FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT,
						 "unsafe adaptive proposal", &rollback_action), FAP_OK);
	expect_true("rollback-generation", rollback_action.policy_generation == 2U &&
			 rollback_action.mode == FAP_MODE_FALLBACK);
	expect_code("stale-commit-fenced", fap_commit(&service, recommendation2.recommendation_id, 1060U,
							 FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
							 FAP_FLAG_EXPERIMENTAL, &action), FAP_ERR_NOT_FOUND);
	++mutation_rejections;
	expect_code("query", fap_query(&service, &attestation), FAP_OK);
	expect_true("fallback-and-rollback-counts", attestation.fallback_count >= 2U &&
			 attestation.rollback_count == 1U && attestation.policy_generation == 2U);
	fap_close(&service);

	expect_code("replay-open", fap_open(&recovered, path, &policy), FAP_OK);
	expect_code("replay-query", fap_query(&recovered, &attestation), FAP_OK);
	expect_true("replay-generation", attestation.policy_generation == 2U &&
			 attestation.rollback_count == 1U);
	fap_close(&recovered);

	fd = open(path, O_RDWR);
	expect_true("tamper-open", fd >= 0);
	expect_true("tamper-seek", lseek(fd, (off_t)(sizeof(struct fap_event) - FAP_DIGEST_SIZE), SEEK_SET) >= 0);
	expect_true("tamper-read", read(fd, &byte, 1) == 1);
	byte ^= 0xffU;
	expect_true("tamper-write", lseek(fd, (off_t)(sizeof(struct fap_event) - FAP_DIGEST_SIZE), SEEK_SET) >= 0 &&
			 write(fd, &byte, 1) == 1);
	close(fd);
	expect_code("tampered-replay", fap_open(&bad, path, &policy), FAP_ERR_REPLAY);
	++mutation_rejections;
	unlink(path);
	printf("M243_ADAPTIVE_SELFTEST_EXIT=0 cases=%u mutation_rejections=%u\n",
	       cases_run, mutation_rejections);
	return 0;
}
