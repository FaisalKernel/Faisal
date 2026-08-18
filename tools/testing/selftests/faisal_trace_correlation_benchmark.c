#define _GNU_SOURCE
#include "../../faisal-trace-correlation/faisal_trace_correlation.h"

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

static void fill_context(struct mtc_context *context)
{
	memset(context, 0, sizeof(*context));
	context->trace_id[0] = 1;
	context->span_id[0] = 2;
}

static void make_event(struct mtc_event *event, uint64_t sequence,
		       const struct mtc_event *previous)
{
	memset(event, 0, sizeof(*event));
	event->event_sequence = sequence;
	event->generation = 9;
	event->observed_at_ns = 1000 + sequence;
	event->kind = (sequence % 2) ? MTC_KIND_OBJECTIVE : MTC_KIND_MODEL_REQUEST;
	event->flags = MTC_FLAG_MEASURED;
	if (event->kind == MTC_KIND_MODEL_REQUEST) {
		event->flags |= MTC_FLAG_MODEL_OUTPUT;
		event->provider_kind = 1;
		event->lineage.model_request_id = sequence;
	}
	event->context.trace_id[0] = 1;
	event->context.span_id[0] = (uint8_t)(sequence & 0xffU);
	event->lineage.agent_id = 41;
	event->lineage.objective_id = 42;
	event->lineage.task_id = 43;
	if (previous) {
		event->previous_event_sequence = previous->event_sequence;
		memcpy(event->previous_event_digest, previous->digest,
		       MTC_DIGEST_SIZE);
	}
}

int main(void)
{
	const uint64_t rounds = 100000;
	const struct mtc_policy policy = {
		.expected_generation = 9,
		.minimum_event_time_ns = 1000,
		.reject_external_context = 0,
		.reject_baggage = 1,
		.require_measured_external_events = 1,
		.max_events = 16,
	};
	struct mtc_service service;
	struct mtc_context root;
	struct mtc_event previous;
	struct mtc_event current;
	struct mtc_event output;
	uint64_t start;
	uint64_t elapsed;
	uint64_t operations = 0;
	uint64_t i;

	fill_context(&root);
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		if (mtc_init(&service, &policy, &root, 9) != MTC_OK)
			return 1;
		make_event(&previous, 1, NULL);
		if (mtc_record_event(&service, &previous, &previous) != MTC_OK)
			return 2;
		make_event(&current, 2, &previous);
		if (mtc_record_event(&service, &current, &current) != MTC_OK)
			return 3;
		if (mtc_verify_event(&service, &current) != MTC_OK)
			return 4;
		if (mtc_query_event(&service, 2, &output) != MTC_OK)
			return 5;
		if (mtc_verify_event(&service, &output) != MTC_OK)
			return 6;
		operations += 5;
	}
	elapsed = now_ns() - start;
	printf("M234_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M234_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M234_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M234_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M234_BENCHMARK_EXIT=0\n");
	return 0;
}
