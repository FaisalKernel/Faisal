#include "faisal_research_verify.h"

#include <openssl/evp.h>
#include <string.h>

static int nonzero_digest(const uint8_t digest[MVR_DIGEST_SIZE])
{
	unsigned int i;

	if (!digest)
		return 0;
	for (i = 0; i < MVR_DIGEST_SIZE; i++)
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

static void hash_digest(EVP_MD_CTX *ctx, const uint8_t digest[MVR_DIGEST_SIZE])
{
	(void)EVP_DigestUpdate(ctx, digest, MVR_DIGEST_SIZE);
}

static int fresh(const struct mvr_service *service,
		const struct mvr_observation *observation, uint64_t now_ns)
{
	uint64_t age;
	uint64_t expiry;

	if (!service || !observation || !observation->retrieved_at_ns ||
	    observation->retrieved_at_ns > now_ns)
		return 0;
	age = now_ns - observation->retrieved_at_ns;
	if (age > service->policy.maximum_source_age_ns)
		return 0;
	if (observation->freshness_ttl_ns &&
	    now_ns - observation->retrieved_at_ns > observation->freshness_ttl_ns)
		return 0;
	if (observation->published_at_ns) {
		if (observation->published_at_ns > observation->retrieved_at_ns)
			return 0;
		if (now_ns - observation->published_at_ns > MVR_MAX_SOURCE_AGE_NS)
			return 0;
	}
	if (UINT64_MAX - observation->retrieved_at_ns < observation->freshness_ttl_ns)
		expiry = UINT64_MAX;
	else
		expiry = observation->retrieved_at_ns + observation->freshness_ttl_ns;
	if (observation->freshness_ttl_ns && now_ns > expiry)
		return 0;
	return 1;
}

static int matches(const struct mvr_observation *observation,
		   const struct mvr_request *request)
{
	return observation && request &&
		observation->request_sequence == request->request_sequence &&
		observation->research_generation == request->research_generation &&
		observation->claim_id == request->claim_id &&
		memcmp(observation->claim_digest, request->claim_digest,
		       MVR_DIGEST_SIZE) == 0;
}

static int digest_consensus(const struct mvr_service *service,
			    const struct mvr_request *request,
			    const struct mvr_consensus *consensus,
			    uint8_t digest[MVR_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	size_t i;

	if (!service || !request || !consensus || !digest ||
	    !request->request_sequence)
		return MVR_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return MVR_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return MVR_ERR_CORRUPT;
	}
	hash_u64(ctx, request->request_sequence);
	hash_u64(ctx, request->research_generation);
	hash_u64(ctx, request->claim_id);
	hash_u64(ctx, request->now_ns);
	hash_digest(ctx, request->claim_digest);
	hash_u64(ctx, consensus->request_sequence);
	hash_u64(ctx, consensus->research_generation);
	hash_u64(ctx, consensus->claim_id);
	hash_u64(ctx, consensus->consensus_sequence);
	hash_u32(ctx, consensus->selected_group);
	hash_u32(ctx, consensus->source_count);
	hash_u32(ctx, consensus->independent_domains);
	hash_u32(ctx, consensus->confidence_ppm);
	hash_u32(ctx, consensus->disagreement_ppm);
	hash_u32(ctx, consensus->state);
	for (i = 0; i < service->observation_count; i++) {
		const struct mvr_observation *observation = &service->observations[i];
		if (!matches(observation, request))
			continue;
		hash_u64(ctx, observation->source_id);
		hash_u64(ctx, observation->domain_hash);
		hash_u64(ctx, observation->retrieved_at_ns);
		hash_u64(ctx, observation->published_at_ns);
		hash_u64(ctx, observation->freshness_ttl_ns);
		hash_u32(ctx, observation->source_kind);
		hash_u32(ctx, observation->flags);
		hash_u32(ctx, observation->confidence_ppm);
		hash_u32(ctx, observation->agreement_group);
		hash_u32(ctx, observation->citation_start);
		hash_u32(ctx, observation->citation_end);
		hash_digest(ctx, observation->claim_digest);
		hash_digest(ctx, observation->url_digest);
		hash_digest(ctx, observation->content_digest);
		hash_digest(ctx, observation->citation_digest);
	}
	if (EVP_DigestFinal_ex(ctx, digest, &length) != 1 ||
	    length != MVR_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return MVR_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return MVR_OK;
}

static int source_valid(const struct mvr_service *service,
			const struct mvr_observation *observation)
{
	if (!service || !observation || !observation->request_sequence ||
	    !observation->research_generation || !observation->claim_id ||
	    !observation->domain_hash || !observation->retrieved_at_ns ||
	    !observation->agreement_group || !observation->confidence_ppm ||
	    observation->confidence_ppm > MVR_SCORE_MAX ||
	    !(service->policy.allowed_source_kinds & observation->source_kind) ||
	    !nonzero_digest(observation->claim_digest) ||
	    !nonzero_digest(observation->url_digest) ||
	    !nonzero_digest(observation->content_digest))
		return 0;
	if (service->policy.require_citation_binding &&
	    (!(observation->flags & MVR_FLAG_CITATION_BOUND) ||
	     observation->citation_end <= observation->citation_start ||
	     !nonzero_digest(observation->citation_digest)))
		return 0;
	if (service->policy.reject_model_only &&
	    (observation->flags & MVR_FLAG_MODEL_PROPOSED) &&
	    (!(observation->flags & MVR_FLAG_SEARCH_TOOL) ||
	     !(observation->flags & MVR_FLAG_URL_VERIFIED)))
		return 0;
	if (observation->freshness_ttl_ns > service->policy.maximum_source_age_ns)
		return 0;
	return 1;
}

static int group_index(uint32_t groups[MVR_MAX_SOURCES], size_t *count,
			       uint32_t group)
{
	size_t i;

	for (i = 0; i < *count; i++)
		if (groups[i] == group)
			return (int)i;
	if (*count >= MVR_MAX_SOURCES)
		return -1;
	groups[(*count)++] = group;
	return (int)(*count - 1);
}

int mvr_init(struct mvr_service *service, const struct mvr_policy *policy)
{
	if (!service || !policy || !policy->minimum_sources ||
	    !policy->minimum_independent_domains ||
	    !policy->minimum_confidence_ppm ||
	    !policy->allowed_source_kinds ||
	    !policy->maximum_source_age_ns ||
	    policy->conflict_threshold_ppm > MVR_SCORE_MAX)
		return MVR_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->next_source_id = 1;
	service->next_consensus_sequence = 1;
	return MVR_OK;
}

int mvr_observe(struct mvr_service *service,
		const struct mvr_observation *observation,
		struct mvr_observation *out)
{
	struct mvr_observation copy;

	if (!service || !observation || !out ||
	    service->observation_count >= MVR_MAX_SOURCES ||
	    !source_valid(service, observation))
		return MVR_ERR_POLICY;
	copy = *observation;
	copy.source_id = service->next_source_id++;
	service->observations[service->observation_count++] = copy;
	*out = copy;
	return MVR_OK;
}

int mvr_consensus(struct mvr_service *service, const struct mvr_request *request,
		struct mvr_consensus *out)
{
	uint32_t groups[MVR_MAX_SOURCES] = { 0 };
	uint64_t group_weight[MVR_MAX_SOURCES] = { 0 };
	uint32_t group_count[MVR_MAX_SOURCES] = { 0 };
	uint32_t group_domains[MVR_MAX_SOURCES] = { 0 };
	uint64_t total_confidence = 0;
	uint32_t valid_count = 0;
	uint32_t stale_count = 0;
	uint32_t best_group = 0;
	uint64_t best_weight = 0;
	uint32_t best_count = 0;
	uint32_t best_domains = 0;
	uint32_t disagreement = 0;
	uint32_t confidence = 0;
	size_t group_total = 0;
	size_t i;
	int rc;

	if (!service || !request || !out || !request->request_sequence ||
	    !request->research_generation || !request->claim_id ||
	    !nonzero_digest(request->claim_digest) ||
	    request->request_sequence <= service->last_consensus_request ||
	    service->consensus_count >= MVR_MAX_CONSENSUS)
		return MVR_ERR_REPLAY;
	memset(out, 0, sizeof(*out));
	out->request_sequence = request->request_sequence;
	out->research_generation = request->research_generation;
	out->claim_id = request->claim_id;
	out->consensus_sequence = service->next_consensus_sequence++;
	for (i = 0; i < service->observation_count; i++) {
		const struct mvr_observation *observation = &service->observations[i];
		int index;

		if (!matches(observation, request))
			continue;
		if (!fresh(service, observation, request->now_ns)) {
			stale_count++;
			continue;
		}
		if (observation->confidence_ppm < service->policy.minimum_confidence_ppm)
			continue;
		index = group_index(groups, &group_total,
				   observation->agreement_group);
		if (index < 0)
			return MVR_ERR_FULL;
		group_count[index]++;
		group_weight[index] += observation->confidence_ppm;
		total_confidence += observation->confidence_ppm;
		valid_count++;
	}
	for (i = 0; i < group_total; i++) {
		if (!best_group || group_weight[i] > best_weight ||
		    (group_weight[i] == best_weight && groups[i] < best_group)) {
			best_group = groups[i];
			best_weight = group_weight[i];
			best_count = group_count[i];
		}
	}
	if (valid_count)
		confidence = (uint32_t)(total_confidence / valid_count);
	if (valid_count)
		disagreement = ((valid_count - best_count) * MVR_SCORE_MAX) /
				valid_count;
	if (best_group) {
		for (i = 0; i < service->observation_count; i++) {
			const struct mvr_observation *observation = &service->observations[i];
			uint32_t j;
			int seen = 0;
			if (!matches(observation, request) ||
			    observation->agreement_group != best_group ||
			    !fresh(service, observation, request->now_ns) ||
			    observation->confidence_ppm < service->policy.minimum_confidence_ppm)
				continue;
			for (j = 0; j < i; j++) {
				const struct mvr_observation *prior = &service->observations[j];
				if (matches(prior, request) &&
				    prior->agreement_group == best_group &&
				    prior->domain_hash == observation->domain_hash &&
				    fresh(service, prior, request->now_ns) &&
				    prior->confidence_ppm >= service->policy.minimum_confidence_ppm) {
					seen = 1;
					break;
				}
			}
			if (!seen)
				group_domains[0]++;
		}
		best_domains = group_domains[0];
	}
	out->selected_group = best_group;
	out->source_count = best_count;
	out->independent_domains = best_domains;
	out->confidence_ppm = confidence;
	out->disagreement_ppm = disagreement;
	if (!valid_count) {
		out->state = stale_count ? MVR_STATE_STALE : MVR_STATE_INSUFFICIENT;
		rc = stale_count ? MVR_ERR_STALE : MVR_ERR_NO_CONSENSUS;
	} else if (best_count < service->policy.minimum_sources ||
		   best_domains < service->policy.minimum_independent_domains ||
		   confidence < service->policy.minimum_confidence_ppm) {
		out->state = MVR_STATE_INSUFFICIENT;
		rc = MVR_ERR_NO_CONSENSUS;
	} else if (disagreement > service->policy.conflict_threshold_ppm) {
		out->state = MVR_STATE_CONFLICT;
		rc = MVR_ERR_CONFLICT;
	} else {
		out->state = MVR_STATE_ACCEPTED;
		rc = MVR_OK;
	}
	if (digest_consensus(service, request, out, out->receipt_digest) != MVR_OK)
		return MVR_ERR_CORRUPT;
	service->consensuses[service->consensus_count++] = *out;
	service->last_consensus_request = request->request_sequence;
	return rc;
}

int mvr_verify(const struct mvr_service *service,
	      const struct mvr_request *request,
	      const struct mvr_consensus *consensus)
{
	uint8_t digest[MVR_DIGEST_SIZE];

	if (!service || !request || !consensus ||
	    consensus->state != MVR_STATE_ACCEPTED)
		return MVR_ERR_POLICY;
	if (consensus->research_generation != request->research_generation ||
	    consensus->request_sequence != request->request_sequence)
		return MVR_ERR_GENERATION;
	if (digest_consensus(service, request, consensus, digest) != MVR_OK)
		return MVR_ERR_CORRUPT;
	if (memcmp(digest, consensus->receipt_digest, MVR_DIGEST_SIZE) != 0)
		return MVR_ERR_CORRUPT;
	return MVR_OK;
}

int mvr_get_observation(const struct mvr_service *service, uint64_t source_id,
		       struct mvr_observation *out)
{
	size_t i;

	if (!service || !source_id || !out)
		return MVR_ERR_ARGUMENT;
	for (i = 0; i < service->observation_count; i++) {
		if (service->observations[i].source_id == source_id) {
			*out = service->observations[i];
			return MVR_OK;
		}
	}
	return MVR_ERR_NOT_FOUND;
}
