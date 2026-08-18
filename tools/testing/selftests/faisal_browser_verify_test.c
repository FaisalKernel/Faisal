#include "../../faisal-browser-verify/faisal_browser_verify.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M235_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void fill_digest(uint8_t digest[BIV_DIGEST_SIZE], uint8_t value)
{
	size_t i;

	for (i = 0; i < BIV_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void make_observation(struct biv_observation *observation,
			     uint64_t page_id, uint64_t observed_at,
			     uint8_t dom_value)
{
	memset(observation, 0, sizeof(*observation));
	observation->page_id = page_id;
	observation->frame_id = 1;
	observation->observed_at_ns = observed_at;
	fill_digest(observation->origin_digest, 0x11);
	fill_digest(observation->url_digest, 0x22);
	fill_digest(observation->dom_digest, dom_value);
	fill_digest(observation->a11y_digest, 0x33);
	fill_digest(observation->screenshot_digest, 0x44);
}

static void make_request(struct biv_action_request *request, uint64_t sequence,
			 uint64_t page_generation, uint32_t action_kind)
{
	memset(request, 0, sizeof(*request));
	request->action_sequence = sequence;
	request->session_generation = 7;
	request->page_generation = page_generation;
	request->provider_sequence = 100 + sequence;
	request->page_id = 42;
	request->action_kind = action_kind;
	request->flags = BIV_FLAG_SEMANTIC | BIV_FLAG_DOM_OBSERVED |
		BIV_FLAG_A11Y_OBSERVED;
	request->locator.locator_kind = BIV_LOCATOR_ROLE;
	request->locator.match_count = 1;
	request->locator.confidence_ppm = 950000;
	request->locator.semantic_score_ppm = 960000;
	fill_digest(request->locator.locator_digest, 0x51);
	fill_digest(request->locator.accessible_name_digest, 0x52);
	make_observation(&request->pre_observation, 42, 9700, 0x60);
	fill_digest(request->input_digest, 0x61);
	request->attribute[0] = 's';
	request->attribute[1] = 'e';
	request->attribute[2] = 'm';
}

int main(void)
{
	const struct biv_policy policy = {
		.session_generation = 7,
		.page_generation = 3,
		.current_time_ns = 10000,
		.max_observation_age_ns = 500,
		.minimum_semantic_confidence_ppm = 900000,
		.require_unique_locator = 1,
		.allow_coordinate_fallback = 0,
		.require_artifact_digest = 1,
		.max_actions = 16,
	};
	struct biv_service service;
	struct biv_action_request request;
	struct biv_observation post;
	struct biv_receipt receipt;
	struct biv_receipt queried;
	uint8_t artifact[BIV_DIGEST_SIZE];

	if (biv_init(&service, &policy) != BIV_OK)
		return fail("init", BIV_ERR_ARGUMENT);
	make_request(&request, 1, 3, BIV_ACTION_CLICK);
	if (biv_admit(&service, &request, &receipt) != BIV_OK)
		return fail("semantic admission", BIV_ERR_POLICY);
	if (biv_verify_receipt(&service, &receipt) != BIV_OK)
		return fail("admission receipt", BIV_ERR_TAMPER);
	printf("M235_SEMANTIC_ADMISSION_OK\n");

	make_observation(&post, 42, 9800, 0x71);
	memcpy(request.expected_post_digest, post.dom_digest,
	       BIV_DIGEST_SIZE);
	if (biv_commit(&service, &request, &post, NULL, &receipt) != BIV_OK)
		return fail("postcondition commit", BIV_ERR_CONFLICT);
	if (receipt.decision != BIV_DECISION_COMMITTED ||
	    biv_verify_receipt(&service, &receipt) != BIV_OK)
		return fail("commit receipt", BIV_ERR_TAMPER);
	printf("M235_POSTCONDITION_COMMIT_OK\n");

	make_request(&request, 2, 3, BIV_ACTION_CLICK);
	request.locator.match_count = 2;
	if (biv_admit(&service, &request, &queried) != BIV_ERR_AMBIGUOUS)
		return fail("ambiguous locator", BIV_ERR_AMBIGUOUS);
	printf("M235_AMBIGUOUS_LOCATOR_REJECT_OK\n");

	make_request(&request, 2, 4, BIV_ACTION_CLICK);
	if (biv_admit(&service, &request, &queried) != BIV_ERR_STALE)
		return fail("page generation", BIV_ERR_STALE);
	printf("M235_PAGE_GENERATION_REJECT_OK\n");

	make_request(&request, 1, 3, BIV_ACTION_CLICK);
	if (biv_admit(&service, &request, &queried) != BIV_ERR_REPLAY)
		return fail("replay", BIV_ERR_REPLAY);
	printf("M235_REPLAY_REJECT_OK\n");

	make_request(&request, 2, 3, BIV_ACTION_CLICK);
	request.pre_observation.observed_at_ns = 9000;
	if (biv_admit(&service, &request, &queried) != BIV_ERR_STALE)
		return fail("stale observation", BIV_ERR_STALE);
	printf("M235_STALE_OBSERVATION_REJECT_OK\n");

	make_request(&request, 2, 3, BIV_ACTION_CLICK);
	request.flags = BIV_FLAG_COORDINATE_FALLBACK;
	request.locator.locator_kind = BIV_LOCATOR_COORDINATE;
	if (biv_admit(&service, &request, &queried) != BIV_ERR_POLICY)
		return fail("coordinate fallback", BIV_ERR_POLICY);
	printf("M235_COORDINATE_POLICY_REJECT_OK\n");

	make_request(&request, 2, 3, BIV_ACTION_DOWNLOAD);
	request.flags |= BIV_FLAG_ARTIFACT_EXPECTED;
	fill_digest(request.expected_artifact_digest, 0x81);
	if (biv_admit(&service, &request, &receipt) != BIV_OK)
		return fail("artifact admission", BIV_ERR_ARTIFACT);
	make_observation(&post, 42, 9850, 0x72);
	if (biv_commit(&service, &request, &post, NULL, &queried) != BIV_ERR_ARTIFACT)
		return fail("missing artifact", BIV_ERR_ARTIFACT);
	fill_digest(artifact, 0x82);
	if (biv_commit(&service, &request, &post, artifact, &receipt) != BIV_ERR_ARTIFACT)
		return fail("wrong artifact", BIV_ERR_ARTIFACT);
	fill_digest(artifact, 0x81);
	if (biv_commit(&service, &request, &post, artifact, &receipt) != BIV_OK)
		return fail("artifact commit", BIV_ERR_ARTIFACT);
	printf("M235_ARTIFACT_BINDING_OK\n");

	queried = receipt;
	queried.receipt_digest[0] ^= 1;
	if (biv_verify_receipt(&service, &queried) != BIV_ERR_TAMPER)
		return fail("receipt tamper", BIV_ERR_TAMPER);
	printf("M235_RECEIPT_TAMPER_REJECT_OK\n");
	if (biv_query_receipt(&service, 2, &queried) != BIV_OK ||
	    queried.decision != BIV_DECISION_COMMITTED)
		return fail("query", BIV_ERR_NOT_FOUND);
	printf("M235_QUERY_OK\n");
	if (biv_authority_check(&request) != BIV_ERR_AUTHORITY)
		return fail("authority", BIV_ERR_AUTHORITY);
	printf("M235_MODEL_NONAUTHORITY_OK\n");
	printf("M235_SELFTEST_EXIT=0\n");
	return 0;
}
