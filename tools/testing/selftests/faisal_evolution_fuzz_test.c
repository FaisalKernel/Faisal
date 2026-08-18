#include "../../faisal-evolution/faisal_evolution.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_digest(uint8_t digest[FEV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FEV_DIGEST_SIZE);
}

static void seed_policy(struct fev_policy *policy)
{
	memset(policy, 0, sizeof(*policy));
	policy->min_improvement_ppm = 10000U;
	policy->max_regression_ppm = 0U;
	policy->require_reproducible = 1U;
	policy->require_rollback = 1U;
	policy->require_research = 1U;
	policy->require_external_approval = 1U;
}

int main(void)
{
	const char *journal = "/tmp/faisal-evolution-fuzz.journal";
	struct fev_service service;
	struct fev_policy policy;
	struct fev_candidate candidate;
	struct fev_candidate isolated;
	struct fev_candidate result;
	uint8_t research[FEV_DIGEST_SIZE];
	uint8_t baseline[FEV_DIGEST_SIZE];
	uint8_t artifact[FEV_DIGEST_SIZE];
	uint8_t evidence[FEV_DIGEST_SIZE];
	uint8_t approval[FEV_DIGEST_SIZE];
	uint32_t rejected = 0;
	uint32_t promoted = 0;
	uint32_t i;

	fill_digest(research, 0x11U);
	fill_digest(baseline, 0x22U);
	fill_digest(artifact, 0x33U);
	fill_digest(evidence, 0x44U);
	fill_digest(approval, 0x55U);
	seed_policy(&policy);
	unlink(journal);
	assert(fev_open(&service, journal) == FEV_OK);
	for (i = 0; i < 10000U; i++) {
		uint64_t id = 1000U + i;
		if (i != 0U && (i % (FEV_MAX_CANDIDATES / 2U)) == 0U) {
			fev_close(&service);
			unlink(journal);
			assert(fev_open(&service, journal) == FEV_OK);
		}
		int rc;
		uint8_t zero[FEV_DIGEST_SIZE] = { 0 };

		switch (i % 8U) {
		case 0U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", zero,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_ERR_ARGUMENT);
			rejected++;
			break;
		case 1U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 zero, artifact, &policy, &candidate);
			assert(rc == FEV_ERR_ARGUMENT);
			rejected++;
			break;
		case 2U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, zero, &policy, &candidate);
			assert(rc == FEV_ERR_ARGUMENT);
			rejected++;
			break;
		case 3U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_OK);
			assert(fev_isolate(&service, id, &isolated) == FEV_OK);
			rc = fev_record_validation(&service, id, 1U, 0U, 800U,
						     evidence, approval, &result);
			assert(rc == FEV_ERR_POLICY && result.state == FEV_STATE_REJECTED);
			rejected++;
			break;
		case 4U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_OK);
			assert(fev_isolate(&service, id, &isolated) == FEV_OK);
			rc = fev_record_validation(&service, id, 1U, 1U, 1200U,
						     evidence, approval, &result);
			assert(rc == FEV_ERR_POLICY && result.state == FEV_STATE_REJECTED);
			rejected++;
			break;
		case 5U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_OK);
			assert(fev_isolate(&service, id, &isolated) == FEV_OK);
			rc = fev_record_validation(&service, id, 1U, 1U, 800U,
						     evidence, NULL, &result);
			assert(rc == FEV_ERR_POLICY && result.state == FEV_STATE_REJECTED);
			rejected++;
			break;
		case 6U:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_OK);
			assert(fev_isolate(&service, id, &isolated) == FEV_OK);
			assert(fev_record_validation(&service, id, 1U, 1U, 800U,
						     evidence, approval, &result) == FEV_OK);
			assert(fev_promote(&service, id, &result, NULL) == FEV_OK);
			promoted++;
			break;
		default:
			rc = fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					 FEV_METRIC_LOWER_BETTER, 1000U,
					 "head", "parent", "rollback", research,
					 baseline, artifact, &policy, &candidate);
			assert(rc == FEV_OK);
			assert(fev_propose(&service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
					   FEV_METRIC_LOWER_BETTER, 1000U,
					   "head", "parent", "rollback", research,
					   baseline, artifact, &policy, &result) == FEV_ERR_CONFLICT);
			rejected++;
			break;
		}
	}
	fev_close(&service);
	unlink(journal);
	printf("FEV_EVOLUTION_FUZZ_OK iterations=10000 rejected=%u promoted=%u\n",
	       rejected, promoted);
	return 0;
}
