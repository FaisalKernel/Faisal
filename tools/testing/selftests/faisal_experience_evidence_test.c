#include "../../faisal-experience/faisal_experience_evidence.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M229_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void make_input(struct fee_input *input, uint64_t sequence,
			       const char *key, const char *result)
{
	memset(input, 0, sizeof(*input));
	input->request_sequence = sequence;
	input->verification_status = FEE_VERIFICATION_VERIFIED;
	input->authority_grant = 1;
	input->confidence_ppm = 900000;
	input->impact_ppm = 800000;
	input->novelty_ppm = 700000;
	input->recurrence_ppm = 600000;
	input->now_ns = 1000 + sequence;
	input->provenance.present_mask = FEE_PROVENANCE_ALL;
	input->provenance.source_sequence = 11;
	input->provenance.provider_generation = 22;
	input->provenance.sandbox_generation = 33;
	input->provenance.verifier_sequence = 44;
	input->provenance.observed_at_ns = 900;
	input->provenance.expires_at_ns = 100000;
	strcpy(input->provenance.source, "verified-research-source");
	strcpy(input->provenance.provider, "provider-neutral-adapter");
	strcpy(input->provenance.model, "model-under-test");
	strcpy(input->provenance.tool, "authorized-tool");
	strcpy(input->provenance.sandbox, "m228-sandbox");
	strcpy(input->provenance.verifier, "independent-verifier");
	strcpy(input->key, key);
	strcpy(input->action, "observe authorized result");
	strcpy(input->observation, "tool returned bounded observation");
	strcpy(input->result, result);
	strcpy(input->lesson, "retain only verified operational lesson");
	strcpy(input->skill, "replay-safe verified procedure");
}

int main(void)
{
	struct fee_service service;
	struct fee_policy policy = {
		.required_provenance_mask = FEE_PROVENANCE_ALL,
		.minimum_confidence_ppm = 700000,
		.minimum_importance_ppm = 700000,
	};
	struct fee_input input;
	struct fee_record first, retrieved, conflict, corrected, expiring;
	struct fee_stats stats;
	uint32_t expired = 0;
	int rc;

	fee_init(&service, &policy);
	make_input(&input, 1, "compile-failure", "use bounded rebuild and retest");
	rc = fee_record(&service, &input, &first);
	if (rc != FEE_OK || first.state != FEE_STATE_REUSABLE)
		return fail("verified promotion", rc);
	printf("M229_VERIFIED_PROMOTION_OK sequence=%llu importance=%u\n",
	       (unsigned long long)first.sequence, first.importance_ppm);
	if (fee_verify(&service, &first) != FEE_OK)
		return fail("binding verification", rc);
	printf("M229_BINDING_VERIFY_OK\n");
	if (fee_retrieve(&service, "compile-failure", 2000, &retrieved) != FEE_OK ||
	    retrieved.sequence != first.sequence)
		return fail("provenance retrieval", rc);
	printf("M229_PROVENANCE_RETRIEVAL_OK\n");
	if (fee_reuse(&service, first.sequence, 3000, &retrieved) != FEE_OK ||
	    retrieved.reuse_count != 1)
		return fail("reuse evidence", rc);
	printf("M229_REUSE_EVIDENCE_OK count=%llu\n",
	       (unsigned long long)retrieved.reuse_count);

	retrieved.result[0] ^= 1;
	if (fee_verify(&service, &retrieved) != FEE_ERR_CORRUPT)
		return fail("tamper rejection", rc);
	printf("M229_TAMPER_REJECT_OK\n");
	if (fee_record(&service, &input, &conflict) != FEE_ERR_REPLAY)
		return fail("request replay rejection", rc);
	printf("M229_REQUEST_REPLAY_REJECT_OK\n");

	make_input(&input, 2, "compile-failure", "silently skip the required retest");
	rc = fee_record(&service, &input, &conflict);
	if (rc != FEE_ERR_CONFLICT || conflict.state != FEE_STATE_CONFLICT)
		return fail("conflict detection", rc);
	printf("M229_CONFLICT_DETECTION_OK sequence=%llu\n",
	       (unsigned long long)conflict.sequence);
	if (fee_retrieve(&service, "compile-failure", 4000, &retrieved) != FEE_ERR_NOT_FOUND)
		return fail("conflict retrieval block", rc);
	printf("M229_CONFLICT_RETRIEVAL_BLOCK_OK\n");

	make_input(&input, 3, "compile-failure", "rebuild, fuzz, benchmark, and retest");
	rc = fee_correct(&service, first.sequence, &input, &corrected);
	if (rc != FEE_OK || corrected.state != FEE_STATE_REUSABLE ||
	    corrected.supersedes_sequence != first.sequence)
		return fail("correction supersession", rc);
	printf("M229_CORRECTION_SUPERSESSION_OK sequence=%llu\n",
	       (unsigned long long)corrected.sequence);

	make_input(&input, 4, "expiring-lesson", "expire after bounded validation window");
	input.provenance.expires_at_ns = 5000;
	input.now_ns = 1500;
	if (fee_record(&service, &input, &expiring) != FEE_OK)
		return fail("expiring record", rc);
	if (fee_reuse(&service, expiring.sequence, 5000, &retrieved) != FEE_ERR_EXPIRED)
		return fail("expiry enforcement", rc);
	printf("M229_EXPIRY_ENFORCEMENT_OK\n");
	if (fee_expire(&service, 5000, &expired) != FEE_OK)
		return fail("expiry sweep", rc);
	printf("M229_EXPIRY_SWEEP_OK count=%u\n", expired);

	make_input(&input, 5, "unverified-lesson", "do not promote model output");
	input.verification_status = FEE_VERIFICATION_UNVERIFIED;
	input.authority_grant = 0;
	if (fee_record(&service, &input, &retrieved) != FEE_OK ||
	    retrieved.state != FEE_STATE_RECORDED)
		return fail("unverified nonpromotion", rc);
	printf("M229_MODEL_OUTPUT_NONAUTHORITY_OK\n");

	make_input(&input, 6, "missing-provenance", "reject incomplete evidence");
	input.provenance.present_mask = FEE_PROVENANCE_SOURCE;
	input.provenance.provider[0] = '\0';
	if (fee_record(&service, &input, &retrieved) != FEE_ERR_POLICY)
		return fail("provenance policy", rc);
	printf("M229_PROVENANCE_POLICY_REJECT_OK\n");

	if (fee_stats_get(&service, 6000, &stats) != FEE_OK ||
	    stats.conflicts != 1 || stats.superseded != 1 || stats.verified < 3 ||
	    stats.provenance_complete < 3)
		return fail("statistics", rc);
	printf("M229_STATS_OK records=%u reusable=%u conflicts=%u superseded=%u expired=%u\n",
	       stats.recorded + stats.reusable + stats.superseded + stats.conflicts +
	       stats.expired + stats.rejected, stats.reusable, stats.conflicts,
	       stats.superseded, stats.expired);
	printf("M229_SELFTEST_EXIT=0\n");
	return 0;
}
