#define _GNU_SOURCE
#include "../../faisal-research-verify/faisal_research_verify.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void digest_fill(uint8_t digest[MVR_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < MVR_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void make_observation(struct mvr_observation *observation,
			     uint64_t domain, uint8_t value)
{
	memset(observation, 0, sizeof(*observation));
	observation->request_sequence = 1;
	observation->research_generation = 7;
	observation->claim_id = 99;
	observation->domain_hash = domain;
	observation->retrieved_at_ns = 900;
	observation->published_at_ns = 800;
	observation->freshness_ttl_ns = 10000;
	observation->source_kind = MVR_SOURCE_OFFICIAL;
	observation->flags = MVR_FLAG_CITATION_BOUND | MVR_FLAG_SEARCH_TOOL |
			     MVR_FLAG_PAGE_AGE | MVR_FLAG_URL_VERIFIED;
	observation->confidence_ppm = 900000;
	observation->agreement_group = 1;
	observation->citation_start = 0;
	observation->citation_end = 20;
	digest_fill(observation->claim_digest, 1);
	digest_fill(observation->url_digest, value);
	digest_fill(observation->content_digest, value + 10);
	digest_fill(observation->citation_digest, value + 20);
}

int main(void)
{
	const uint64_t rounds = 100000;
	const struct mvr_policy policy = {
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
	struct mvr_consensus consensus;
	uint64_t start;
	uint64_t elapsed;
	uint64_t operations = 0;
	uint64_t i;

	start = now_ns();
	for (i = 0; i < rounds; i++) {
		if (mvr_init(&service, &policy) != MVR_OK)
			return 1;
		memset(&request, 0, sizeof(request));
		request.request_sequence = 1;
		request.research_generation = 7;
		request.claim_id = 99;
		request.now_ns = 1000;
		digest_fill(request.claim_digest, 1);
		make_observation(&observation, 10, 1);
		if (mvr_observe(&service, &observation, &observation) != MVR_OK)
			return 2;
		make_observation(&observation, 11, 2);
		if (mvr_observe(&service, &observation, &observation) != MVR_OK)
			return 3;
		if (mvr_consensus(&service, &request, &consensus) != MVR_OK)
			return 4;
		if (mvr_verify(&service, &request, &consensus) != MVR_OK)
			return 5;
		operations += 4;
	}
	elapsed = now_ns() - start;
	printf("M232_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M232_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M232_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M232_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M232_BENCHMARK_EXIT=0\n");
	return 0;
}
