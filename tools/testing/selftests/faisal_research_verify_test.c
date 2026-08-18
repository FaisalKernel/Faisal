#include "../../faisal-research-verify/faisal_research_verify.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M232_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

static void digest_fill(uint8_t digest[MVR_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < MVR_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void base_request(struct mvr_request *request, uint64_t sequence)
{
	memset(request, 0, sizeof(*request));
	request->request_sequence = sequence;
	request->research_generation = 7;
	request->claim_id = 99;
	request->now_ns = 1000;
	digest_fill(request->claim_digest, 1);
}

static void base_observation(struct mvr_observation *observation,
			     uint64_t request_sequence, uint32_t group,
			     uint64_t domain, uint32_t confidence, uint8_t value)
{
	memset(observation, 0, sizeof(*observation));
	observation->request_sequence = request_sequence;
	observation->research_generation = 7;
	observation->claim_id = 99;
	observation->domain_hash = domain;
	observation->retrieved_at_ns = 900;
	observation->published_at_ns = 800;
	observation->freshness_ttl_ns = 10000;
	observation->source_kind = MVR_SOURCE_OFFICIAL;
	observation->flags = MVR_FLAG_CITATION_BOUND | MVR_FLAG_SEARCH_TOOL |
			     MVR_FLAG_PAGE_AGE | MVR_FLAG_URL_VERIFIED;
	observation->confidence_ppm = confidence;
	observation->agreement_group = group;
	observation->citation_start = 0;
	observation->citation_end = 20;
	digest_fill(observation->claim_digest, 1);
	digest_fill(observation->url_digest, value);
	digest_fill(observation->content_digest, value + 10);
	digest_fill(observation->citation_digest, value + 20);
}

int main(void)
{
	struct mvr_policy policy = {
		.minimum_sources = 2,
		.minimum_independent_domains = 2,
		.minimum_confidence_ppm = 700000,
		.allowed_source_kinds = MVR_SOURCE_PRIMARY | MVR_SOURCE_OFFICIAL |
					 MVR_SOURCE_CURATED | MVR_SOURCE_SECONDARY,
		.require_citation_binding = 1,
		.reject_model_only = 1,
		.maximum_source_age_ns = 20000,
		.conflict_threshold_ppm = 400000,
	};
	struct mvr_service service;
	struct mvr_request request;
	struct mvr_observation observation;
	struct mvr_observation queried;
	struct mvr_consensus consensus;
	struct mvr_consensus verified;
	int rc;

	if (mvr_init(&service, &policy) != MVR_OK)
		return fail("init", MVR_ERR_ARGUMENT);
	base_request(&request, 1);
	base_observation(&observation, 1, 1, 10, 900000, 1);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("observe one", MVR_ERR_POLICY);
	if (mvr_get_observation(&service, observation.source_id, &queried) != MVR_OK)
		return fail("query observation", MVR_ERR_NOT_FOUND);
	printf("M232_OBSERVATION_QUERY_OK source=%llu\n",
	       (unsigned long long)queried.source_id);
	base_observation(&observation, 1, 1, 11, 800000, 2);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("observe two", MVR_ERR_POLICY);
	base_observation(&observation, 1, 2, 12, 700000, 3);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("observe three", MVR_ERR_POLICY);
	if (mvr_consensus(&service, &request, &consensus) != MVR_OK ||
	    consensus.state != MVR_STATE_ACCEPTED ||
	    consensus.selected_group != 1 || consensus.source_count != 2 ||
	    consensus.independent_domains != 2)
		return fail("accepted consensus", MVR_ERR_NO_CONSENSUS);
	verified = consensus;
	printf("M232_CONSENSUS_ACCEPTED sources=%u domains=%u confidence=%u disagreement=%u\n",
	       consensus.source_count, consensus.independent_domains,
	       consensus.confidence_ppm, consensus.disagreement_ppm);
	if (mvr_verify(&service, &request, &verified) != MVR_OK)
		return fail("consensus verify", MVR_ERR_CORRUPT);
	printf("M232_CONSENSUS_VERIFY_OK\n");
	consensus.receipt_digest[0] ^= 1;
	if (mvr_verify(&service, &request, &consensus) != MVR_ERR_CORRUPT)
		return fail("receipt tamper", MVR_ERR_CORRUPT);
	printf("M232_RECEIPT_TAMPER_REJECT_OK\n");

	base_request(&request, 2);
	base_observation(&observation, 2, 1, 20, 900000, 4);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("same-domain one", MVR_ERR_POLICY);
	base_observation(&observation, 2, 1, 20, 900000, 5);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("same-domain two", MVR_ERR_POLICY);
	if (mvr_consensus(&service, &request, &consensus) != MVR_ERR_NO_CONSENSUS)
		return fail("same-domain diversity", MVR_ERR_NO_CONSENSUS);
	printf("M232_INDEPENDENT_DOMAIN_GATE_OK\n");

	base_request(&request, 3);
	base_observation(&observation, 3, 3, 30, 900000, 6);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("conflict one", MVR_ERR_POLICY);
	base_observation(&observation, 3, 4, 31, 900000, 7);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("conflict two", MVR_ERR_POLICY);
	base_observation(&observation, 3, 3, 32, 900000, 8);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("conflict three", MVR_ERR_POLICY);
	base_observation(&observation, 3, 4, 33, 900000, 9);
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("conflict four", MVR_ERR_POLICY);
	if (mvr_consensus(&service, &request, &consensus) != MVR_ERR_CONFLICT ||
	    consensus.state != MVR_STATE_CONFLICT)
		return fail("conflict gate", MVR_ERR_CONFLICT);
	printf("M232_CONFLICT_GATE_OK disagreement=%u\n", consensus.disagreement_ppm);

	base_request(&request, 4);
	base_observation(&observation, 4, 5, 40, 900000, 8);
	observation.retrieved_at_ns = 1;
	if (mvr_observe(&service, &observation, &observation) != MVR_OK)
		return fail("stale observation", MVR_ERR_POLICY);
	if (mvr_consensus(&service, &request, &consensus) != MVR_ERR_STALE)
		return fail("stale gate", MVR_ERR_STALE);
	printf("M232_FRESHNESS_GATE_OK\n");

	base_request(&request, 5);
	base_observation(&observation, 5, 6, 50, 900000, 9);
	observation.flags = MVR_FLAG_MODEL_PROPOSED | MVR_FLAG_CITATION_BOUND;
	if (mvr_observe(&service, &observation, &observation) != MVR_ERR_POLICY)
		return fail("model-only source", MVR_ERR_POLICY);
	printf("M232_MODEL_ONLY_REJECT_OK\n");

	base_request(&request, 6);
	base_observation(&observation, 6, 7, 60, 900000, 10);
	observation.flags &= ~MVR_FLAG_CITATION_BOUND;
	if (mvr_observe(&service, &observation, &observation) != MVR_ERR_POLICY)
		return fail("citation binding", MVR_ERR_POLICY);
	printf("M232_CITATION_BINDING_REJECT_OK\n");

	base_request(&request, 1);
	rc = mvr_consensus(&service, &request, &consensus);
	if (rc != MVR_ERR_REPLAY)
		return fail("request replay", MVR_ERR_REPLAY);
	printf("M232_REQUEST_REPLAY_REJECT_OK\n");
	request.research_generation = 8;
	if (mvr_verify(&service, &request, &verified) != MVR_ERR_GENERATION)
		return fail("generation fence", MVR_ERR_GENERATION);
	printf("M232_GENERATION_FENCE_OK\n");

	printf("M232_SELFTEST_EXIT=0\n");
	return 0;
}
