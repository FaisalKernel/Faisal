#define _GNU_SOURCE
#include "../../faisal-recovery/faisal_recovery_decision.h"

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

static void fill_digest(uint8_t digest[FRD_DIGEST_SIZE], uint8_t value)
{
	unsigned int i;

	for (i = 0; i < FRD_DIGEST_SIZE; i++)
		digest[i] = value;
}

int main(void)
{
	const uint64_t rounds = 100000;
	struct frd_policy policy = {
		.allowed_actions = FRD_ACTION_RETRY,
		.max_attempts = FRD_MAX_DECISIONS,
		.require_checkpoint_for_recovery = 1,
		.max_backoff_ns = FRD_MAX_BACKOFF_NS,
	};
	struct frd_service service;
	struct frd_input input;
	struct frd_decision decision;
	uint64_t start;
	uint64_t elapsed;
	uint64_t operations = 0;
	uint64_t i;
	uint64_t window_sequence = 0;

	if (frd_init(&service, &policy) != FRD_OK)
		return 1;
	memset(&input, 0, sizeof(input));
	input.now_ns = 100;
	input.objective_id = 10;
	input.agent_id = 20;
	input.worker_id = 30;
	input.trace_id = 40;
	input.span_id = 50;
	input.parent_span_id = 60;
	input.generation = 70;
	input.action_id = 80;
	input.deadline_ns = UINT64_MAX;
	input.backoff_base_ns = 1;
	input.requested_action = FRD_ACTION_RETRY;
	input.flags = FRD_FLAG_TRACE_BOUND | FRD_FLAG_GENERATION_BOUND |
			     FRD_FLAG_OBSERVATION | FRD_FLAG_DIAGNOSIS |
			     FRD_FLAG_CHECKPOINT | FRD_FLAG_IDEMPOTENT;
	input.max_attempts = FRD_MAX_DECISIONS;
	input.attempt = 1;
	fill_digest(input.observation_digest, 1);
	fill_digest(input.diagnosis_digest, 2);
	fill_digest(input.checkpoint_digest, 3);

	start = now_ns();
	for (i = 1; i <= rounds; i++) {
		if (window_sequence == FRD_MAX_DECISIONS) {
			if (frd_init(&service, &policy) != FRD_OK)
				return 4;
			window_sequence = 0;
		}
		input.request_sequence = ++window_sequence;
		if (frd_decide(&service, &input, &decision) != FRD_OK)
			return 2;
		if (frd_verify(&service, &input, &decision, input.generation) != FRD_OK)
			return 3;
		operations += 2;
	}
	elapsed = now_ns() - start;
	printf("M231_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M231_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M231_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M231_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M231_BENCHMARK_EXIT=0\n");
	return 0;
}
