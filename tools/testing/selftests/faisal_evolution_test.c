#include "../../faisal-evolution/faisal_evolution.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_digest(uint8_t digest[FEV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FEV_DIGEST_SIZE);
}

static void policy(struct fev_policy *value)
{
	memset(value, 0, sizeof(*value));
	value->min_improvement_ppm = 100000U;
	value->max_regression_ppm = 0U;
	value->require_reproducible = 1U;
	value->require_rollback = 1U;
	value->require_research = 1U;
	value->require_external_approval = 1U;
}

static int propose(struct fev_service *service, uint64_t id,
		   const struct fev_policy *value, struct fev_candidate *out,
		   const uint8_t research[FEV_DIGEST_SIZE],
		   const uint8_t baseline[FEV_DIGEST_SIZE],
		   const uint8_t candidate_digest[FEV_DIGEST_SIZE])
{
	return fev_propose(service, id, 1U, FEV_FLAG_MODEL_PROPOSAL,
			   FEV_METRIC_LOWER_BETTER, 1000U,
			   "88ae2b0ea075d63052abc85b4fda485b17f365dc",
			   "c89634200999209680dcab4b69b040ba00917db9",
			   "FAISAL-FRONTIER-BASE-EVOLUTION", research, baseline,
			   candidate_digest, value, out);
}

int main(void)
{
	const char *journal = "/tmp/faisal-evolution-selftest.journal";
	const char *corrupt_journal = "/tmp/faisal-evolution-corrupt.journal";
	struct fev_service service;
	struct fev_policy value;
	struct fev_candidate candidate;
	struct fev_candidate isolated;
	struct fev_candidate validated;
	struct fev_candidate promoted;
	struct fev_candidate rolled_back;
	struct fev_candidate rejected;
	struct fev_candidate queried;
	struct fev_receipt receipt;
	uint8_t research[FEV_DIGEST_SIZE];
	uint8_t baseline[FEV_DIGEST_SIZE];
	uint8_t artifact[FEV_DIGEST_SIZE];
	uint8_t evidence[FEV_DIGEST_SIZE];
	uint8_t approval[FEV_DIGEST_SIZE];
	uint8_t rollback_reason[FEV_DIGEST_SIZE];
	int fd;

	fill_digest(research, 0x11U);
	fill_digest(baseline, 0x22U);
	fill_digest(artifact, 0x33U);
	fill_digest(evidence, 0x44U);
	fill_digest(approval, 0x55U);
	fill_digest(rollback_reason, 0x66U);
	unlink(journal);
	unlink(corrupt_journal);
	policy(&value);
	assert(fev_open(&service, journal) == FEV_OK);
	assert(propose(&service, 1U, &value, &candidate, research, baseline,
		       artifact) == FEV_OK);
	assert(candidate.state == FEV_STATE_DRAFT);
	assert(fev_verify_candidate(&candidate) == FEV_OK);
	assert(fev_isolate(&service, 1U, &isolated) == FEV_OK);
	assert(isolated.state == FEV_STATE_ISOLATED);
	assert(fev_record_validation(&service, 1U, 1U, 1U, 800U, evidence,
				     approval, &validated) == FEV_OK);
	assert(validated.state == FEV_STATE_VALIDATED);
	assert(validated.improvement_ppm == 200000U);
	assert(validated.regression_ppm == 0U);
	assert(fev_promote(&service, 1U, &promoted, &receipt) == FEV_OK);
	assert(promoted.state == FEV_STATE_PROMOTED);
	assert(fev_verify_receipt(&receipt) == FEV_OK);
	assert(fev_rollback(&service, 1U, rollback_reason, &rolled_back,
			   &receipt) == FEV_OK);
	assert(rolled_back.state == FEV_STATE_ROLLED_BACK);
	assert(fev_verify_receipt(&receipt) == FEV_OK);
	assert(fev_query(&service, 1U, &queried) == FEV_OK);
	assert(queried.state == FEV_STATE_ROLLED_BACK);
	assert(fev_promote(&service, 1U, &promoted, &receipt) == FEV_ERR_STATE);
	assert(propose(&service, 2U, &value, &candidate, research, baseline,
		       artifact) == FEV_OK);
	assert(fev_isolate(&service, 2U, &isolated) == FEV_OK);
	assert(fev_record_validation(&service, 2U, 1U, 1U, 800U, evidence,
				     NULL, &rejected) == FEV_ERR_POLICY);
	assert(rejected.state == FEV_STATE_REJECTED);
	assert(fev_promote(&service, 2U, &promoted, &receipt) == FEV_ERR_STATE);
	assert(propose(&service, 3U, &value, &candidate, research, baseline,
		       artifact) == FEV_OK);
	assert(fev_isolate(&service, 3U, &isolated) == FEV_OK);
	assert(fev_record_validation(&service, 3U, 1U, 1U, 1200U, evidence,
				     approval, &rejected) == FEV_ERR_POLICY);
	assert(rejected.state == FEV_STATE_REJECTED);
	assert(fev_query(&service, 99U, &queried) == FEV_ERR_NOT_FOUND);
	fev_close(&service);
	assert(fev_open(&service, journal) == FEV_OK);
	assert(fev_query(&service, 1U, &queried) == FEV_OK);
	assert(queried.state == FEV_STATE_ROLLED_BACK);
	assert(fev_query(&service, 2U, &queried) == FEV_OK);
	assert(queried.state == FEV_STATE_REJECTED);
	fev_close(&service);
	assert(fev_open(&service, corrupt_journal) == FEV_OK);
	assert(propose(&service, 10U, &value, &candidate, research, baseline,
		       artifact) == FEV_OK);
	fev_close(&service);
	fd = open(corrupt_journal, O_RDWR);
	assert(fd >= 0);
	assert(lseek(fd, -1, SEEK_END) >= 0);
	assert(write(fd, "X", 1U) == 1);
	close(fd);
	assert(fev_open(&service, corrupt_journal) == FEV_ERR_TAMPER);
	unlink(journal);
	unlink(corrupt_journal);
	printf("FEV_EVOLUTION_SELFTEST_OK cases=29 promoted=1 rolled_back=1 rejected=2 replay=verified model_authority=denied\n");
	return 0;
}
