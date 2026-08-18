#include "faisal_browser_verify.h"

#include <openssl/evp.h>
#include <string.h>

static int nonzero_bytes(const uint8_t *bytes, size_t length)
{
	size_t i;

	if (!bytes)
		return 0;
	for (i = 0; i < length; i++)
		if (bytes[i] != 0)
			return 1;
	return 0;
}

static int digest_data(const void *data, size_t length,
		       uint8_t digest[BIV_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int out_length = 0;
	int result = BIV_ERR_TAMPER;

	if (!data || !digest)
		return BIV_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return BIV_ERR_TAMPER;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, length) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &out_length) == 1 &&
	    out_length == BIV_DIGEST_SIZE)
		result = BIV_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int digest_request(const struct biv_action_request *request,
			  uint8_t digest[BIV_DIGEST_SIZE])
{
	struct biv_action_request canonical;

	if (!request || !digest)
		return BIV_ERR_ARGUMENT;
	canonical = *request;
	memset(canonical.expected_post_digest, 0,
	       sizeof(canonical.expected_post_digest));
	memset(canonical.expected_artifact_digest, 0,
	       sizeof(canonical.expected_artifact_digest));
	return digest_data(&canonical, sizeof(canonical), digest);
}

static int digest_receipt(const struct biv_receipt *receipt,
			  uint8_t digest[BIV_DIGEST_SIZE])
{
	struct biv_receipt canonical;

	if (!receipt || !digest)
		return BIV_ERR_ARGUMENT;
	canonical = *receipt;
	memset(canonical.receipt_digest, 0, sizeof(canonical.receipt_digest));
	return digest_data(&canonical, sizeof(canonical), digest);
}

static int observation_valid(const struct biv_observation *observation)
{
	if (!observation || !observation->page_id || !observation->observed_at_ns ||
	    !nonzero_bytes(observation->origin_digest, BIV_DIGEST_SIZE) ||
	    !nonzero_bytes(observation->url_digest, BIV_DIGEST_SIZE))
		return 0;
	return 1;
}

static int observation_fresh(const struct biv_service *service,
			     const struct biv_observation *observation)
{
	uint64_t age;

	if (!observation_valid(observation))
		return 0;
	if (observation->observed_at_ns > service->policy.current_time_ns)
		return 0;
	if (!service->policy.max_observation_age_ns)
		return 1;
	age = service->policy.current_time_ns - observation->observed_at_ns;
	return age <= service->policy.max_observation_age_ns;
}

static int policy_accepts(const struct biv_service *service,
			  const struct biv_action_request *request)
{
	const struct biv_locator_evidence *locator;
	const struct biv_observation *observation;

	if (!service || !request || request->reserved || !request->action_sequence ||
	    !request->page_id || request->action_kind == 0 ||
	    request->action_kind > BIV_ACTION_VERIFY ||
	    request->flags & ~(BIV_FLAG_SEMANTIC | BIV_FLAG_COORDINATE_FALLBACK |
				    BIV_FLAG_MODEL_PROPOSAL | BIV_FLAG_OPERATOR_CONFIRMED |
				    BIV_FLAG_DOM_OBSERVED | BIV_FLAG_A11Y_OBSERVED |
				    BIV_FLAG_SCREENSHOT_OBSERVED | BIV_FLAG_ARTIFACT_EXPECTED))
		return BIV_ERR_ARGUMENT;
	if (request->session_generation != service->policy.session_generation ||
	    request->page_generation != service->policy.page_generation)
		return BIV_ERR_STALE;
	locator = &request->locator;
	if (request->flags & BIV_FLAG_COORDINATE_FALLBACK) {
		if (!(service->policy.allow_coordinate_fallback) ||
		    locator->locator_kind != BIV_LOCATOR_COORDINATE)
			return BIV_ERR_POLICY;
	} else {
		if (!(request->flags & BIV_FLAG_SEMANTIC) ||
		    locator->locator_kind == BIV_LOCATOR_COORDINATE)
			return BIV_ERR_POLICY;
		if (service->policy.require_unique_locator && locator->match_count != 1)
			return BIV_ERR_AMBIGUOUS;
		if (locator->confidence_ppm < service->policy.minimum_semantic_confidence_ppm ||
		    locator->semantic_score_ppm < service->policy.minimum_semantic_confidence_ppm)
			return BIV_ERR_POLICY;
		if (!nonzero_bytes(locator->locator_digest, BIV_DIGEST_SIZE))
			return BIV_ERR_POLICY;
	}
	observation = &request->pre_observation;
	if (!observation_fresh(service, observation) ||
	    observation->page_id != request->page_id)
		return BIV_ERR_STALE;
	if ((request->flags & BIV_FLAG_ARTIFACT_EXPECTED) &&
	    !nonzero_bytes(request->expected_artifact_digest, BIV_DIGEST_SIZE))
		return BIV_ERR_ARTIFACT;
	return BIV_OK;
}

int biv_init(struct biv_service *service, const struct biv_policy *policy)
{
	if (!service || !policy || !policy->session_generation ||
	    !policy->page_generation || policy->max_actions == 0 ||
	    policy->max_actions > BIV_MAX_ACTIONS ||
	    policy->minimum_semantic_confidence_ppm > BIV_PPM_SCALE)
		return BIV_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->next_action_id = 1;
	return BIV_OK;
}

int biv_admit(struct biv_service *service,
	      const struct biv_action_request *request,
	      struct biv_receipt *out)
{
	struct biv_receipt receipt;
	int rc;

	if (!service || !request || !out || service->receipt_count >= service->policy.max_actions)
		return BIV_ERR_ARGUMENT;
	if (request->action_sequence <= service->last_action_sequence)
		return BIV_ERR_REPLAY;
	rc = policy_accepts(service, request);
	if (rc != BIV_OK)
		return rc;
	memset(&receipt, 0, sizeof(receipt));
	receipt.decision = BIV_DECISION_ADMITTED;
	receipt.status = BIV_OK;
	receipt.action_sequence = request->action_sequence;
	receipt.session_generation = request->session_generation;
	receipt.page_generation = request->page_generation;
	receipt.action_id = service->next_action_id++;
	if (digest_request(request, receipt.request_digest) != BIV_OK)
		return BIV_ERR_TAMPER;
	if (digest_receipt(&receipt, receipt.receipt_digest) != BIV_OK)
		return BIV_ERR_TAMPER;
	service->receipts[service->receipt_count++] = receipt;
	service->last_action_sequence = request->action_sequence;
	*out = receipt;
	return BIV_OK;
}

int biv_commit(struct biv_service *service,
	       const struct biv_action_request *request,
	       const struct biv_observation *post_observation,
	       const uint8_t artifact_digest[BIV_DIGEST_SIZE],
	       struct biv_receipt *out)
{
	struct biv_receipt *admitted;
	struct biv_receipt receipt;
	uint8_t request_digest[BIV_DIGEST_SIZE];
	int rc;

	if (!service || !request || !post_observation || !out)
		return BIV_ERR_ARGUMENT;
	if (biv_query_receipt(service, request->action_sequence, &receipt) != BIV_OK)
		return BIV_ERR_NOT_FOUND;
	admitted = NULL;
	if (service->receipt_count)
		admitted = &service->receipts[service->receipt_count - 1];
	if (!admitted || admitted->action_sequence != request->action_sequence ||
	    admitted->decision != BIV_DECISION_ADMITTED)
		return BIV_ERR_REPLAY;
	rc = policy_accepts(service, request);
	if (rc != BIV_OK)
		return rc;
	if (!observation_fresh(service, post_observation) ||
	    post_observation->page_id != request->page_id)
		return BIV_ERR_STALE;
	if (digest_request(request, request_digest) != BIV_OK ||
	    memcmp(request_digest, admitted->request_digest, BIV_DIGEST_SIZE) != 0)
		return BIV_ERR_TAMPER;
	if (nonzero_bytes(request->expected_post_digest, BIV_DIGEST_SIZE) &&
	    memcmp(request->expected_post_digest, post_observation->dom_digest,
		   BIV_DIGEST_SIZE) != 0)
		return BIV_ERR_CONFLICT;
	if (request->flags & BIV_FLAG_ARTIFACT_EXPECTED) {
		if (!artifact_digest ||
		    memcmp(request->expected_artifact_digest, artifact_digest,
			   BIV_DIGEST_SIZE) != 0)
			return BIV_ERR_ARTIFACT;
	} else if (artifact_digest)
		return BIV_ERR_ARTIFACT;
	receipt.decision = BIV_DECISION_COMMITTED;
	receipt.status = BIV_OK;
	receipt.post_observation = *post_observation;
	if (artifact_digest)
		memcpy(receipt.artifact_digest, artifact_digest,
		       sizeof(receipt.artifact_digest));
	memcpy(receipt.request_digest, request_digest, sizeof(receipt.request_digest));
	if (digest_receipt(&receipt, receipt.receipt_digest) != BIV_OK)
		return BIV_ERR_TAMPER;
	*admitted = receipt;
	*out = receipt;
	return BIV_OK;
}

int biv_verify_receipt(const struct biv_service *service,
		       const struct biv_receipt *receipt)
{
	uint8_t digest[BIV_DIGEST_SIZE];

	if (!service || !receipt || !receipt->action_sequence ||
	    receipt->session_generation != service->policy.session_generation ||
	    receipt->page_generation != service->policy.page_generation)
		return BIV_ERR_STALE;
	if (digest_receipt(receipt, digest) != BIV_OK ||
	    memcmp(digest, receipt->receipt_digest, BIV_DIGEST_SIZE) != 0)
		return BIV_ERR_TAMPER;
	return BIV_OK;
}

int biv_query_receipt(const struct biv_service *service,
		      uint64_t action_sequence,
		      struct biv_receipt *out)
{
	size_t i;

	if (!service || !out || !action_sequence)
		return BIV_ERR_ARGUMENT;
	for (i = 0; i < service->receipt_count; i++)
		if (service->receipts[i].action_sequence == action_sequence) {
			*out = service->receipts[i];
			return BIV_OK;
		}
	return BIV_ERR_NOT_FOUND;
}

int biv_authority_check(const struct biv_action_request *request)
{
	if (!request)
		return BIV_ERR_ARGUMENT;
	return BIV_ERR_AUTHORITY;
}
