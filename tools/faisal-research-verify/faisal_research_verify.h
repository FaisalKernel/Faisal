#ifndef FAISAL_RESEARCH_VERIFY_H
#define FAISAL_RESEARCH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define MVR_MAX_SOURCES 64U
#define MVR_MAX_CONSENSUS 64U
#define MVR_DIGEST_SIZE 32U
#define MVR_SCORE_MAX 1000000U
#define MVR_MAX_SOURCE_AGE_NS (30ULL * 24ULL * 60ULL * 60ULL * 1000000000ULL)

#define MVR_SOURCE_PRIMARY 1U
#define MVR_SOURCE_OFFICIAL 2U
#define MVR_SOURCE_CURATED 3U
#define MVR_SOURCE_SECONDARY 4U

#define MVR_FLAG_CITATION_BOUND (1U << 0)
#define MVR_FLAG_SEARCH_TOOL    (1U << 1)
#define MVR_FLAG_PAGE_AGE       (1U << 2)
#define MVR_FLAG_MODEL_PROPOSED (1U << 3)
#define MVR_FLAG_URL_VERIFIED   (1U << 4)

#define MVR_STATE_ACCEPTED 1U
#define MVR_STATE_CONFLICT 2U
#define MVR_STATE_INSUFFICIENT 3U
#define MVR_STATE_STALE 4U
#define MVR_STATE_REJECTED 5U

enum mvr_status {
	MVR_OK = 0,
	MVR_ERR_ARGUMENT = -1,
	MVR_ERR_FULL = -2,
	MVR_ERR_REPLAY = -3,
	MVR_ERR_POLICY = -4,
	MVR_ERR_CORRUPT = -5,
	MVR_ERR_STALE = -6,
	MVR_ERR_CONFLICT = -7,
	MVR_ERR_NO_CONSENSUS = -8,
	MVR_ERR_NOT_FOUND = -9,
	MVR_ERR_GENERATION = -10
};

struct mvr_observation {
	uint64_t source_id;
	uint64_t request_sequence;
	uint64_t research_generation;
	uint64_t claim_id;
	uint64_t domain_hash;
	uint64_t retrieved_at_ns;
	uint64_t published_at_ns;
	uint64_t freshness_ttl_ns;
	uint32_t source_kind;
	uint32_t flags;
	uint32_t confidence_ppm;
	uint32_t agreement_group;
	uint32_t citation_start;
	uint32_t citation_end;
	uint8_t claim_digest[MVR_DIGEST_SIZE];
	uint8_t url_digest[MVR_DIGEST_SIZE];
	uint8_t content_digest[MVR_DIGEST_SIZE];
	uint8_t citation_digest[MVR_DIGEST_SIZE];
};

struct mvr_policy {
	uint32_t minimum_sources;
	uint32_t minimum_independent_domains;
	uint32_t minimum_confidence_ppm;
	uint32_t allowed_source_kinds;
	uint32_t require_citation_binding;
	uint32_t reject_model_only;
	uint64_t maximum_source_age_ns;
	uint32_t conflict_threshold_ppm;
};

struct mvr_request {
	uint64_t request_sequence;
	uint64_t research_generation;
	uint64_t claim_id;
	uint64_t now_ns;
	uint8_t claim_digest[MVR_DIGEST_SIZE];
};

struct mvr_consensus {
	uint64_t request_sequence;
	uint64_t research_generation;
	uint64_t claim_id;
	uint64_t consensus_sequence;
	uint32_t selected_group;
	uint32_t source_count;
	uint32_t independent_domains;
	uint32_t confidence_ppm;
	uint32_t disagreement_ppm;
	uint32_t state;
	uint8_t receipt_digest[MVR_DIGEST_SIZE];
};

struct mvr_service {
	struct mvr_policy policy;
	struct mvr_observation observations[MVR_MAX_SOURCES];
	struct mvr_consensus consensuses[MVR_MAX_CONSENSUS];
	size_t observation_count;
	size_t consensus_count;
	uint64_t next_source_id;
	uint64_t next_consensus_sequence;
	uint64_t last_consensus_request;
};

int mvr_init(struct mvr_service *service, const struct mvr_policy *policy);
int mvr_observe(struct mvr_service *service, const struct mvr_observation *observation,
		struct mvr_observation *out);
int mvr_consensus(struct mvr_service *service, const struct mvr_request *request,
		struct mvr_consensus *out);
int mvr_verify(const struct mvr_service *service, const struct mvr_request *request,
	      const struct mvr_consensus *consensus);
int mvr_get_observation(const struct mvr_service *service, uint64_t source_id,
		       struct mvr_observation *out);

#endif
