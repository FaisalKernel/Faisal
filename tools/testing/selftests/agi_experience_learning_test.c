#define _GNU_SOURCE
#include "../../faisal-experience/faisal_experience_service.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M72_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m72-memory.journal";
	struct fes_service service;
	struct fes_item rejected, reusable, corrected;
	int rc;

	unlink(journal);
	unlink("/tmp/faisal-m72-memory.journal.ckpt");
	memset(&service, 0, sizeof(service));
	rc = fes_open(&service, journal);
	if (rc != FMS_OK)
		return fail("open", rc);
	rc = fes_record_and_evaluate(&service, "unverified-query", "observation lacks verification", "do-not-reuse", 0, &rejected);
	if (rc != 0 || rejected.state != FES_REJECTED)
		return fail("unverified rejection", rc);
	printf("M72_UNVERIFIED_REJECT_OK\n");
	if (fes_record_and_evaluate(&service, "weather-query", "verified source observation", "prefer-primary-source", 1, &reusable) != 0 ||
	    reusable.state != FES_REUSABLE || !reusable.artifact_id)
		return fail("verified reusable experience", rc);
	printf("M72_QUERY1_RETAINED_OK sequence=%llu\n",
	       (unsigned long long)reusable.experience_sequence);
	if (fes_retrieve_reusable(&service, "weather-query", &corrected) != 0 ||
	    corrected.artifact_id != reusable.artifact_id ||
	    strcmp(corrected.skill, "prefer-primary-source"))
		return fail("query2 retrieval", rc);
	printf("M72_QUERY2_RETRIEVAL_OK artifact=%llu\n",
	       (unsigned long long)corrected.artifact_id);
	if (fes_record_reuse(&service, &corrected) != 0)
		return fail("skill reuse record", rc);
	printf("M72_SKILL_REUSE_RECORDED_OK\n");
	if (fes_test_stale_artifact(&service, &corrected) != 0)
		return fail("stale artifact capability", rc);
	printf("M72_STALE_ARTIFACT_REJECT_OK\n");
	if (fes_correct(&service, &corrected, "corrected verified source observation", "require-two-primary-sources") != 0)
		return fail("correction", rc);
	if (fes_retrieve_reusable(&service, "weather-query", &reusable) != 0 ||
	    strcmp(reusable.skill, "require-two-primary-sources") ||
	    reusable.state != FES_REUSABLE)
		return fail("corrected retrieval", rc);
	printf("M72_CORRECTION_REEVALUATION_OK\n");
	fes_close(&service);
	unlink(journal);
	unlink("/tmp/faisal-m72-memory.journal.ckpt");
	printf("M72_SELFTEST_EXIT=0\n");
	return 0;
}
