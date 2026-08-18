#define _POSIX_C_SOURCE 200809L

#include "faisal_result_retention.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void fill_digest(uint8_t digest[RDR_DIGEST_SIZE], uint8_t seed)
{
	size_t i;

	for (i = 0U; i < RDR_DIGEST_SIZE; ++i)
		digest[i] = (uint8_t)(seed + (uint8_t)i);
}

static struct rdr_policy policy(uint64_t now, uint64_t sequence)
{
	struct rdr_policy p;

	memset(&p, 0, sizeof(p));
	p.now_ns = now;
	p.expected_objective_id = 11U;
	p.expected_trace_id = 22U;
	p.expected_agent_id = 33U;
	p.expected_tenant_id = 44U;
	p.expected_task_generation = 1U;
	p.expected_session_generation = 2U;
	p.expected_world_generation = 3U;
	p.expected_next_sequence = sequence;
	p.max_age_ns = 1000000U;
	p.require_verified = 1U;
	p.authority_granted = 1U;
	p.independent_verifier = 1U;
	return p;
}

int main(void)
{
	static struct rdr_service service;
	static struct rdr_service recovered;
	static struct rdr_event journal[RDR_MAX_EVENTS];
	struct rdr_event event;
	struct rdr_event transition;
	struct rdr_event replay[2];
	struct rdr_projection projection;
	struct rdr_replay_cursor cursor;
	uint8_t digest[RDR_DIGEST_SIZE];
	uint64_t rounds = 100000U;
	uint64_t operations = 0U;
	uint64_t start;
	uint64_t elapsed;
	uint64_t round;
	size_t count;
	int result;
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	start = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
	for (round = 0U; round < rounds; ++round) {
		struct rdr_policy p;
		struct rdr_policy commit_policy;

		if (rdr_init(&service) != RDR_OK)
			return 1;
		memset(&event, 0, sizeof(event));
		event.result_id = 100U + round;
		event.receipt_id = 1000U + round;
		event.objective_id = 11U;
		event.trace_id = 22U;
		event.agent_id = 33U;
		event.tenant_id = 44U;
		event.task_generation = 1U;
		event.session_generation = 2U;
		event.world_generation = 3U;
		event.event_at_ns = 100U;
		event.expires_at_ns = 1000100U;
		event.event_kind = RDR_EVENT_RESULT;
		event.flags = RDR_FLAG_VERIFIED;
		fill_digest(event.result_digest, 1U);
		fill_digest(event.payload_digest, 2U);
		fill_digest(event.provenance_digest, 3U);
		p = policy(110U, 1U);
		result = rdr_append_result(&service, &event, &p, &event);
		if (result != RDR_OK)
			return 2;
		operations++;
		fill_digest(digest, 9U);
		commit_policy = policy(120U, 2U);
		result = rdr_append_transition(&service, event.result_id,
			RDR_EVENT_COMMIT, digest, &commit_policy, &transition);
		if (result != RDR_OK)
			return 3;
		operations++;
		count = service.event_count;
		memcpy(journal, service.events, count * sizeof(journal[0]));
		result = rdr_recover(&recovered, journal, count,
			service.tail_chain_digest);
		if (result != RDR_OK)
			return 4;
		operations++;
		memset(&cursor, 0, sizeof(cursor));
		cursor.expected_task_generation = 1U;
		cursor.expected_session_generation = 2U;
		cursor.expected_world_generation = 3U;
		cursor.max_events = 2U;
		result = rdr_replay_since(&recovered, &cursor, replay, 2U, &count);
		if (result != RDR_OK || count != 2U)
			return 5;
		operations++;
		result = rdr_query(&recovered, event.result_id, &projection);
		if (result != RDR_OK || projection.state != RDR_STATE_COMMITTED)
			return 6;
		operations++;
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	elapsed = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec - start;
	printf("M238_RETENTION_BENCHMARK_EXIT=0 rounds=%llu operations=%llu elapsed_ns=%llu ns_per_operation=%.2f\n",
	       (unsigned long long)rounds, (unsigned long long)operations,
	       (unsigned long long)elapsed,
	       operations == 0U ? 0.0 : (double)elapsed / (double)operations);
	return 0;
}
