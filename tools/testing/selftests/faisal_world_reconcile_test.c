#include "../../faisal-world-reconcile/faisal_world_reconcile.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M233_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void digest_fill(uint8_t digest[MWR_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < MWR_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void item_fill(struct mwr_item *item, uint64_t entity,
		      uint64_t property, uint64_t value, uint64_t observed_at,
		      uint32_t severity, uint8_t digest_value)
{
	memset(item, 0, sizeof(*item));
	item->item_id = entity ^ property ^ value;
	item->entity_hash = entity;
	item->property_hash = property;
	item->value_hash = value;
	item->observed_at_ns = observed_at;
	item->freshness_ttl_ns = 5000;
	item->kind = MWR_KIND_SERVICE;
	item->flags = MWR_FLAG_MEASURED | MWR_FLAG_FRESH;
	item->confidence_ppm = 900000;
	item->severity_hint = severity;
	digest_fill(item->value_digest, digest_value);
}

static void snapshot_base(struct mwr_snapshot *snapshot, uint64_t sequence,
			  uint64_t generation)
{
	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->snapshot_sequence = sequence;
	snapshot->world_generation = generation;
	snapshot->captured_at_ns = 1000;
	snapshot->provider_kind = 1;
	snapshot->flags = MWR_FLAG_MEASURED;
}

static void request_for(struct mwr_request *request, uint64_t sequence,
			uint64_t previous, uint64_t now,
			const struct mwr_snapshot *expected,
			const struct mwr_snapshot *observed)
{
	memset(request, 0, sizeof(*request));
	request->request_sequence = sequence;
	request->expected_generation = expected->world_generation;
	request->observed_generation = observed->world_generation;
	request->previous_observed_sequence = previous;
	request->now_ns = now;
	(void)mwr_digest_snapshot(expected, request->expected_digest);
	(void)mwr_digest_snapshot(observed, request->observed_digest);
}

int main(void)
{
	const struct mwr_policy policy = {
		.minimum_observation_confidence_ppm = 700000,
		.stale_after_ns = 2000,
		.require_measured_observation = 1,
		.reject_model_only_observation = 1,
		.sequence_gap_is_critical = 1,
		.allow_empty_expected = 1,
	};
	struct mwr_service service;
	struct mwr_snapshot expected;
	struct mwr_snapshot observed;
	struct mwr_request request;
	struct mwr_receipt receipt;
	struct mwr_receipt verified;

	if (mwr_init(&service, &policy) != MWR_OK)
		return fail("init", MWR_ERR_ARGUMENT);
	snapshot_base(&expected, 10, 7);
	expected.item_count = 2;
	item_fill(&expected.items[0], 1, 11, 100, 1000, MWR_SEVERITY_LOW, 1);
	item_fill(&expected.items[1], 2, 22, 200, 1000, MWR_SEVERITY_MEDIUM, 2);
	snapshot_base(&observed, 11, 7);
	observed.item_count = 2;
	item_fill(&observed.items[0], 1, 11, 100, 1000, MWR_SEVERITY_LOW, 1);
	item_fill(&observed.items[1], 2, 22, 201, 1000, MWR_SEVERITY_MEDIUM, 3);
	request_for(&request, 1, 10, 1500, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_OK ||
	    receipt.state != MWR_STATE_DRIFT || receipt.drift_count != 1 ||
	    receipt.drifts[0].type != MWR_DRIFT_CHANGED)
		return fail("changed drift", MWR_ERR_NO_DRIFT);
	printf("M233_CHANGED_DRIFT_OK count=%u severity=%u\n",
	       receipt.drift_count, receipt.max_severity);
	verified = receipt;
	if (mwr_verify(&service, &request, &verified) != MWR_OK)
		return fail("receipt verify", MWR_ERR_CORRUPT);
	printf("M233_RECEIPT_VERIFY_OK\n");
	verified.digest[0] ^= 1;
	if (mwr_verify(&service, &request, &verified) != MWR_ERR_CORRUPT)
		return fail("receipt tamper", MWR_ERR_CORRUPT);
	printf("M233_RECEIPT_TAMPER_REJECT_OK\n");
	if (mwr_propose_only(&receipt, 1, MWR_FLAG_MODEL_PROPOSED) != MWR_OK)
		return fail("proposal only", MWR_ERR_POLICY);
	printf("M233_PROPOSAL_NONAUTHORITY_OK\n");

	snapshot_base(&observed, 12, 7);
	observed.item_count = 2;
	item_fill(&observed.items[0], 1, 11, 100, 1000, MWR_SEVERITY_LOW, 1);
	item_fill(&observed.items[1], 3, 33, 300, 1000, MWR_SEVERITY_LOW, 4);
	request_for(&request, 2, 11, 1500, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_OK ||
	    receipt.state != MWR_STATE_DRIFT || receipt.drift_count != 2)
		return fail("missing unexpected drift", MWR_ERR_NO_DRIFT);
	printf("M233_MISSING_UNEXPECTED_DRIFT_OK count=%u\n", receipt.drift_count);

	snapshot_base(&expected, 20, 7);
	expected.item_count = 1;
	item_fill(&expected.items[0], 9, 99, 900, 1000, MWR_SEVERITY_LOW, 9);
	snapshot_base(&observed, 13, 7);
	observed.item_count = 1;
	item_fill(&observed.items[0], 9, 99, 900, 1, MWR_SEVERITY_LOW, 9);
	request_for(&request, 3, 12, 4000, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_OK ||
	    receipt.state != MWR_STATE_DRIFT || receipt.drifts[0].type != MWR_DRIFT_STALE)
		return fail("stale drift", MWR_ERR_STALE);
	printf("M233_STALE_DRIFT_OK\n");

	snapshot_base(&observed, 14, 7);
	observed.item_count = 1;
	item_fill(&observed.items[0], 9, 99, 900, 1000, MWR_SEVERITY_LOW, 9);
	observed.items[0].flags = MWR_FLAG_MODEL_PROPOSED;
	request_for(&request, 4, 13, 1500, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_ERR_POLICY ||
	    receipt.state != MWR_STATE_REJECTED)
		return fail("model-only rejection", MWR_ERR_POLICY);
	printf("M233_MODEL_ONLY_REJECT_OK\n");

	snapshot_base(&observed, 16, 7);
	observed.item_count = 1;
	item_fill(&observed.items[0], 9, 99, 900, 1000, MWR_SEVERITY_LOW, 9);
	request_for(&request, 5, 14, 1500, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_ERR_SEQUENCE_GAP)
		return fail("sequence gap", MWR_ERR_SEQUENCE_GAP);
	printf("M233_SEQUENCE_GAP_REJECT_OK\n");

	request_for(&request, 6, 15, 1500, &expected, &observed);
	if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_OK)
		return fail("in sync", MWR_ERR_NO_DRIFT);
	if (receipt.state != MWR_STATE_IN_SYNC || receipt.drift_count != 0)
		return fail("in sync state", MWR_ERR_NO_DRIFT);
	printf("M233_IN_SYNC_OK\n");
	request.observed_generation = 8;
	if (mwr_verify(&service, &request, &receipt) != MWR_ERR_GENERATION)
		return fail("generation fence", MWR_ERR_GENERATION);
	printf("M233_GENERATION_FENCE_OK\n");
	if (mwr_propose_only(&receipt, 1, MWR_FLAG_MODEL_PROPOSED) != MWR_ERR_POLICY)
		return fail("in-sync proposal", MWR_ERR_POLICY);
	printf("M233_NO_ACTION_FOR_IN_SYNC_OK\n");

	printf("M233_SELFTEST_EXIT=0\n");
	return 0;
}
