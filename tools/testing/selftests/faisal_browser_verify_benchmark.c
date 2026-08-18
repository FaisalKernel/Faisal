#define _GNU_SOURCE
#include "../../faisal-browser-verify/faisal_browser_verify.h"

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

static void fill_digest(uint8_t digest[BIV_DIGEST_SIZE], uint8_t value)
{
	size_t i;

	for (i = 0; i < BIV_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void make_observation(struct biv_observation *observation,
			     uint64_t observed_at, uint8_t dom_value)
{
	memset(observation, 0, sizeof(*observation));
	observation->page_id = 42;
	observation->frame_id = 1;
	observation->observed_at_ns = observed_at;
	fill_digest(observation->origin_digest, 0x11);
	fill_digest(observation->url_digest, 0x22);
	fill_digest(observation->dom_digest, dom_value);
	fill_digest(observation->a11y_digest, 0x33);
}

static void make_request(struct biv_action_request *request,
			 uint64_t sequence, const struct biv_observation *pre,
			 const struct biv_observation *post)
{
	memset(request, 0, sizeof(*request));
	request->action_sequence = sequence;
	request->session_generation = 7;
	request->page_generation = 3;
	request->provider_sequence = 100 + sequence;
	request->page_id = 42;
	request->action_kind = BIV_ACTION_CLICK;
	request->flags = BIV_FLAG_SEMANTIC | BIV_FLAG_DOM_OBSERVED |
		BIV_FLAG_A11Y_OBSERVED;
	request->locator.locator_kind = BIV_LOCATOR_ROLE;
	request->locator.match_count = 1;
	request->locator.confidence_ppm = 950000;
	request->locator.semantic_score_ppm = 960000;
	fill_digest(request->locator.locator_digest, 0x51);
	fill_digest(request->locator.accessible_name_digest, 0x52);
	request->pre_observation = *pre;
	memcpy(request->expected_post_digest, post->dom_digest,
	       BIV_DIGEST_SIZE);
	fill_digest(request->input_digest, 0x61);
}

int main(void)
{
	const uint64_t rounds = 100000;
	const struct biv_policy policy = {
		.session_generation = 7,
		.page_generation = 3,
		.current_time_ns = 10000,
		.max_observation_age_ns = 500,
		.minimum_semantic_confidence_ppm = 900000,
		.require_unique_locator = 1,
		.allow_coordinate_fallback = 0,
		.require_artifact_digest = 1,
		.max_actions = 2,
	};
	struct biv_service service;
	struct biv_action_request request;
	struct biv_observation pre;
	struct biv_observation post;
	struct biv_receipt receipt;
	uint64_t start;
	uint64_t elapsed;
	uint64_t operations = 0;
	uint64_t i;

	start = now_ns();
	for (i = 0; i < rounds; i++) {
		if (biv_init(&service, &policy) != BIV_OK)
			return 1;
		make_observation(&pre, 9700, 0x60);
		make_observation(&post, 9800, 0x71);
		make_request(&request, 1, &pre, &post);
		if (biv_admit(&service, &request, &receipt) != BIV_OK)
			return 2;
		if (biv_commit(&service, &request, &post, NULL, &receipt) != BIV_OK)
			return 3;
		if (biv_verify_receipt(&service, &receipt) != BIV_OK)
			return 4;
		if (biv_query_receipt(&service, 1, &receipt) != BIV_OK)
			return 5;
		operations += 4;
	}
	elapsed = now_ns() - start;
	printf("M235_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M235_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M235_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M235_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M235_BENCHMARK_EXIT=0\n");
	return 0;
}
