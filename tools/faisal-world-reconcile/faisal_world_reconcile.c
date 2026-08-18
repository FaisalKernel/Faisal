#include "faisal_world_reconcile.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

static int nonzero_digest(const uint8_t digest[MWR_DIGEST_SIZE])
{
	unsigned int i;

	if (!digest)
		return 0;
	for (i = 0; i < MWR_DIGEST_SIZE; i++)
		if (digest[i] != 0)
			return 1;
	return 0;
}

static void hash_u32(EVP_MD_CTX *ctx, uint32_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_u64(EVP_MD_CTX *ctx, uint64_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_digest(EVP_MD_CTX *ctx, const uint8_t digest[MWR_DIGEST_SIZE])
{
	(void)EVP_DigestUpdate(ctx, digest, MWR_DIGEST_SIZE);
}

static void hash_item(EVP_MD_CTX *ctx, const struct mwr_item *item)
{
	hash_u64(ctx, item->item_id);
	hash_u64(ctx, item->entity_hash);
	hash_u64(ctx, item->property_hash);
	hash_u64(ctx, item->value_hash);
	hash_u64(ctx, item->observed_at_ns);
	hash_u64(ctx, item->freshness_ttl_ns);
	hash_u32(ctx, item->kind);
	hash_u32(ctx, item->flags);
	hash_u32(ctx, item->confidence_ppm);
	hash_u32(ctx, item->severity_hint);
	hash_digest(ctx, item->value_digest);
}

static int item_compare(const void *left, const void *right)
{
	const struct mwr_item *a = left;
	const struct mwr_item *b = right;

	if (a->entity_hash < b->entity_hash)
		return -1;
	if (a->entity_hash > b->entity_hash)
		return 1;
	if (a->property_hash < b->property_hash)
		return -1;
	if (a->property_hash > b->property_hash)
		return 1;
	if (a->item_id < b->item_id)
		return -1;
	if (a->item_id > b->item_id)
		return 1;
	return 0;
}

static int valid_item(const struct mwr_item *item)
{
	return item && item->item_id && item->entity_hash && item->property_hash &&
		item->observed_at_ns && item->confidence_ppm <= MWR_SCORE_MAX &&
		nonzero_digest(item->value_digest);
}

static int valid_snapshot(const struct mwr_snapshot *snapshot, int allow_empty)
{
	uint32_t i;

	if (!snapshot || !snapshot->snapshot_sequence || !snapshot->world_generation ||
	    !snapshot->captured_at_ns || snapshot->item_count > MWR_MAX_ITEMS ||
	    (!allow_empty && !snapshot->item_count))
		return 0;
	for (i = 0; i < snapshot->item_count; i++)
		if (!valid_item(&snapshot->items[i]))
			return 0;
	return 1;
}

int mwr_digest_snapshot(const struct mwr_snapshot *snapshot,
			uint8_t digest[MWR_DIGEST_SIZE])
{
	struct mwr_item sorted[MWR_MAX_ITEMS];
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	uint32_t i;

	if (!snapshot || !digest || snapshot->item_count > MWR_MAX_ITEMS ||
	    !valid_snapshot(snapshot, 1))
		return MWR_ERR_ARGUMENT;
	memcpy(sorted, snapshot->items, sizeof(sorted));
	qsort(sorted, snapshot->item_count, sizeof(sorted[0]), item_compare);
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return MWR_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return MWR_ERR_CORRUPT;
	}
	hash_u64(ctx, snapshot->snapshot_sequence);
	hash_u64(ctx, snapshot->world_generation);
	hash_u64(ctx, snapshot->captured_at_ns);
	hash_u32(ctx, snapshot->item_count);
	hash_u32(ctx, snapshot->provider_kind);
	hash_u32(ctx, snapshot->flags);
	for (i = 0; i < snapshot->item_count; i++)
		hash_item(ctx, &sorted[i]);
	if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 ||
	    length != MWR_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return MWR_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return MWR_OK;
}

static int same_identity(const struct mwr_item *left, const struct mwr_item *right)
{
	return left->entity_hash == right->entity_hash &&
		left->property_hash == right->property_hash;
}

static const struct mwr_item *find_item(const struct mwr_snapshot *snapshot,
					const struct mwr_item *needle)
{
	uint32_t i;

	for (i = 0; i < snapshot->item_count; i++)
		if (same_identity(&snapshot->items[i], needle))
			return &snapshot->items[i];
	return NULL;
}

static uint32_t severity_for(uint32_t type, uint32_t hint)
{
	uint32_t severity;

	switch (type) {
	case MWR_DRIFT_MISSING:
	case MWR_DRIFT_UNEXPECTED:
		severity = MWR_SEVERITY_HIGH;
		break;
	case MWR_DRIFT_CHANGED:
		severity = MWR_SEVERITY_MEDIUM;
		break;
	case MWR_DRIFT_STALE:
		severity = MWR_SEVERITY_HIGH;
		break;
	case MWR_DRIFT_UNCERTAIN:
		severity = MWR_SEVERITY_CRITICAL;
		break;
	default:
		severity = MWR_SEVERITY_INFO;
		break;
	}
	return hint > severity ? hint : severity;
}

static int stale_item(const struct mwr_service *service,
		      const struct mwr_item *item, uint64_t now_ns)
{
	uint64_t age;
	uint64_t ttl = item->freshness_ttl_ns;

	if (item->observed_at_ns > now_ns)
		return 1;
	age = now_ns - item->observed_at_ns;
	if (service->policy.stale_after_ns && age > service->policy.stale_after_ns)
		return 1;
	return ttl && age > ttl;
}

static int digest_receipt(const struct mwr_request *request,
			  const struct mwr_receipt *receipt,
			  uint8_t digest[MWR_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	uint32_t i;

	if (!request || !receipt || !digest)
		return MWR_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return MWR_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return MWR_ERR_CORRUPT;
	}
	hash_u64(ctx, request->request_sequence);
	hash_u64(ctx, request->expected_generation);
	hash_u64(ctx, request->observed_generation);
	hash_u64(ctx, request->previous_observed_sequence);
	hash_u64(ctx, request->now_ns);
	hash_digest(ctx, request->expected_digest);
	hash_digest(ctx, request->observed_digest);
	hash_u64(ctx, receipt->request_sequence);
	hash_u64(ctx, receipt->expected_generation);
	hash_u64(ctx, receipt->observed_generation);
	hash_u64(ctx, receipt->receipt_sequence);
	hash_u32(ctx, receipt->drift_count);
	hash_u32(ctx, receipt->max_severity);
	hash_u32(ctx, receipt->confidence_ppm);
	hash_u32(ctx, receipt->state);
	for (i = 0; i < receipt->drift_count && i < MWR_MAX_ITEMS; i++) {
		const struct mwr_drift *drift = &receipt->drifts[i];
		hash_u64(ctx, drift->entity_hash);
		hash_u64(ctx, drift->property_hash);
		hash_u64(ctx, drift->expected_value_hash);
		hash_u64(ctx, drift->observed_value_hash);
		hash_u32(ctx, drift->kind);
		hash_u32(ctx, drift->type);
		hash_u32(ctx, drift->severity);
		hash_u32(ctx, drift->confidence_ppm);
		hash_u32(ctx, drift->source_flags);
	}
	if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 ||
	    length != MWR_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return MWR_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return MWR_OK;
}

int mwr_init(struct mwr_service *service, const struct mwr_policy *policy)
{
	if (!service || !policy ||
	    policy->minimum_observation_confidence_ppm > MWR_SCORE_MAX ||
	    (!policy->allow_empty_expected && !policy->stale_after_ns))
		return MWR_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->next_receipt_sequence = 1;
	return MWR_OK;
}

int mwr_reconcile(struct mwr_service *service, const struct mwr_request *request,
			 const struct mwr_snapshot *expected,
			 const struct mwr_snapshot *observed,
			 struct mwr_receipt *out)
{
	uint8_t expected_digest[MWR_DIGEST_SIZE];
	uint8_t observed_digest[MWR_DIGEST_SIZE];
	uint64_t confidence_sum = 0;
	uint32_t confidence_count = 0;
	uint32_t max_severity = MWR_SEVERITY_INFO;
	uint32_t drift_count = 0;
	uint32_t i;
	int rc = MWR_OK;

	if (!service || !request || !expected || !observed || !out ||
	    !request->request_sequence ||
	    request->request_sequence <= service->last_request_sequence ||
	    service->receipt_count >= MWR_MAX_RECEIPTS ||
	    request->expected_generation != expected->world_generation ||
	    request->observed_generation != observed->world_generation ||
	    !valid_snapshot(expected, service->policy.allow_empty_expected) ||
	    !valid_snapshot(observed, 1))
		return MWR_ERR_ARGUMENT;
	if (mwr_digest_snapshot(expected, expected_digest) != MWR_OK ||
	    mwr_digest_snapshot(observed, observed_digest) != MWR_OK)
		return MWR_ERR_CORRUPT;
	if (memcmp(expected_digest, request->expected_digest, MWR_DIGEST_SIZE) != 0 ||
	    memcmp(observed_digest, request->observed_digest, MWR_DIGEST_SIZE) != 0)
		return MWR_ERR_CORRUPT;
	if (request->previous_observed_sequence &&
	    observed->snapshot_sequence != request->previous_observed_sequence + 1) {
		if (service->policy.sequence_gap_is_critical)
			return MWR_ERR_SEQUENCE_GAP;
	}
	memset(out, 0, sizeof(*out));
	out->request_sequence = request->request_sequence;
	out->expected_generation = request->expected_generation;
	out->observed_generation = request->observed_generation;
	out->receipt_sequence = service->next_receipt_sequence++;
	for (i = 0; i < observed->item_count; i++) {
		const struct mwr_item *item = &observed->items[i];
		if ((service->policy.require_measured_observation &&
		     !(item->flags & MWR_FLAG_MEASURED)) ||
		    (service->policy.reject_model_only_observation &&
		     (item->flags & MWR_FLAG_MODEL_PROPOSED) &&
		     !(item->flags & MWR_FLAG_MEASURED))) {
			rc = MWR_ERR_POLICY;
			break;
		}
	}
	if (rc == MWR_OK) {
		for (i = 0; i < expected->item_count; i++) {
			const struct mwr_item *want = &expected->items[i];
			const struct mwr_item *have = find_item(observed, want);
			struct mwr_drift *drift;
			uint32_t type = MWR_DRIFT_NONE;
			uint32_t confidence;

			if (!have)
				type = MWR_DRIFT_MISSING;
			else if (stale_item(service, have, request->now_ns))
				type = MWR_DRIFT_STALE;
			else if (have->value_hash != want->value_hash ||
				 memcmp(have->value_digest, want->value_digest,
					MWR_DIGEST_SIZE) != 0)
				type = MWR_DRIFT_CHANGED;
			if (type == MWR_DRIFT_NONE)
				continue;
			if (drift_count >= MWR_MAX_ITEMS) {
				rc = MWR_ERR_FULL;
				break;
			}
			drift = &out->drifts[drift_count++];
			memset(drift, 0, sizeof(*drift));
			drift->entity_hash = want->entity_hash;
			drift->property_hash = want->property_hash;
			drift->expected_value_hash = want->value_hash;
			drift->observed_value_hash = have ? have->value_hash : 0;
			drift->kind = want->kind;
			drift->type = type;
			drift->severity = severity_for(type, want->severity_hint);
			confidence = have ? have->confidence_ppm : want->confidence_ppm;
			drift->confidence_ppm = confidence;
			drift->source_flags = have ? have->flags : 0;
			confidence_sum += confidence;
			confidence_count++;
			if (drift->severity > max_severity)
				max_severity = drift->severity;
		}
	}
	if (rc == MWR_OK) {
		for (i = 0; i < observed->item_count; i++) {
			const struct mwr_item *have = &observed->items[i];
			struct mwr_drift *drift;
			if (find_item(expected, have))
				continue;
			if (drift_count >= MWR_MAX_ITEMS) {
				rc = MWR_ERR_FULL;
				break;
			}
			drift = &out->drifts[drift_count++];
			memset(drift, 0, sizeof(*drift));
			drift->entity_hash = have->entity_hash;
			drift->property_hash = have->property_hash;
			drift->observed_value_hash = have->value_hash;
			drift->kind = have->kind;
			drift->type = MWR_DRIFT_UNEXPECTED;
			drift->severity = severity_for(MWR_DRIFT_UNEXPECTED,
						       have->severity_hint);
			drift->confidence_ppm = have->confidence_ppm;
			drift->source_flags = have->flags;
			confidence_sum += have->confidence_ppm;
			confidence_count++;
			if (drift->severity > max_severity)
				max_severity = drift->severity;
		}
	}
	out->drift_count = drift_count;
	out->max_severity = max_severity;
	out->confidence_ppm = confidence_count ?
		(uint32_t)(confidence_sum / confidence_count) : MWR_SCORE_MAX;
	out->state = rc == MWR_OK ?
		(drift_count ? MWR_STATE_DRIFT : MWR_STATE_IN_SYNC) :
		(rc == MWR_ERR_POLICY ? MWR_STATE_REJECTED : MWR_STATE_UNCERTAIN);
	if (digest_receipt(request, out, out->digest) != MWR_OK)
		return MWR_ERR_CORRUPT;
	service->receipts[service->receipt_count++] = *out;
	service->last_request_sequence = request->request_sequence;
	return rc;
}

int mwr_verify(const struct mwr_service *service, const struct mwr_request *request,
	      const struct mwr_receipt *receipt)
{
	uint8_t digest[MWR_DIGEST_SIZE];

	if (!service || !request || !receipt)
		return MWR_ERR_ARGUMENT;
	if (receipt->expected_generation != request->expected_generation ||
	    receipt->observed_generation != request->observed_generation)
		return MWR_ERR_GENERATION;
	if (digest_receipt(request, receipt, digest) != MWR_OK)
		return MWR_ERR_CORRUPT;
	if (memcmp(digest, receipt->digest, MWR_DIGEST_SIZE) != 0)
		return MWR_ERR_CORRUPT;
	return MWR_OK;
}

int mwr_propose_only(const struct mwr_receipt *receipt,
			uint32_t action_kind, uint32_t proposer_flags)
{
	(void)proposer_flags;
	if (!receipt || !receipt->receipt_sequence || !action_kind ||
	    (receipt->state != MWR_STATE_DRIFT &&
	     receipt->state != MWR_STATE_UNCERTAIN))
		return MWR_ERR_POLICY;
	return MWR_OK;
}
