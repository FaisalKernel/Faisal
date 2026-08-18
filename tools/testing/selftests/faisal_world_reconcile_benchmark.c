#define _GNU_SOURCE
#include "../../faisal-world-reconcile/faisal_world_reconcile.h"

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

static void digest_fill(uint8_t digest[MWR_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < MWR_DIGEST_SIZE; i++)
		digest[i] = value;
}

static void make_snapshot(struct mwr_snapshot *snapshot, uint64_t sequence)
{
	struct mwr_item *item;

	memset(snapshot, 0, sizeof(*snapshot));
	snapshot->snapshot_sequence = sequence;
	snapshot->world_generation = 7;
	snapshot->captured_at_ns = 1000;
	snapshot->provider_kind = 1;
	snapshot->flags = MWR_FLAG_MEASURED;
	snapshot->item_count = 1;
	item = &snapshot->items[0];
	item->item_id = 111;
	item->entity_hash = 11;
	item->property_hash = 22;
	item->value_hash = 33;
	item->observed_at_ns = 1000;
	item->freshness_ttl_ns = 5000;
	item->kind = MWR_KIND_RESOURCE;
	item->flags = MWR_FLAG_MEASURED | MWR_FLAG_FRESH;
	item->confidence_ppm = 900000;
	digest_fill(item->value_digest, 7);
}

int main(void)
{
	const uint64_t rounds = 100000;
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
	uint64_t start;
	uint64_t elapsed;
	uint64_t operations = 0;
	uint64_t i;

	start = now_ns();
	for (i = 0; i < rounds; i++) {
		if (mwr_init(&service, &policy) != MWR_OK)
			return 1;
		make_snapshot(&expected, 10);
		make_snapshot(&observed, 11);
		memset(&request, 0, sizeof(request));
		request.request_sequence = 1;
		request.expected_generation = 7;
		request.observed_generation = 7;
		request.previous_observed_sequence = 10;
		request.now_ns = 1500;
		if (mwr_digest_snapshot(&expected, request.expected_digest) != MWR_OK ||
		    mwr_digest_snapshot(&observed, request.observed_digest) != MWR_OK)
			return 2;
		if (mwr_reconcile(&service, &request, &expected, &observed, &receipt) != MWR_OK)
			return 3;
		if (mwr_verify(&service, &request, &receipt) != MWR_OK)
			return 4;
		operations += 4;
	}
	elapsed = now_ns() - start;
	printf("M233_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M233_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M233_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M233_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M233_BENCHMARK_EXIT=0\n");
	return 0;
}
