#include "faisal_result_retention.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_eq(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual,
			expected);
		failures++;
	}
}

static void fill_digest(uint8_t digest[RDR_DIGEST_SIZE], uint8_t seed)
{
	size_t i;

	for (i = 0U; i < RDR_DIGEST_SIZE; ++i)
		digest[i] = (uint8_t)(seed + (uint8_t)i);
}

static struct rdr_event make_result(uint64_t result_id, uint64_t event_at,
					uint64_t task_generation)
{
	struct rdr_event event;

	memset(&event, 0, sizeof(event));
	event.result_id = result_id;
	event.receipt_id = result_id + 1000U;
	event.objective_id = 11U;
	event.trace_id = 22U;
	event.agent_id = 33U;
	event.tenant_id = 44U;
	event.task_generation = task_generation;
	event.session_generation = 2U;
	event.world_generation = 3U;
	event.event_at_ns = event_at;
	event.expires_at_ns = event_at + 1000U;
	event.event_kind = RDR_EVENT_RESULT;
	event.flags = RDR_FLAG_VERIFIED;
	fill_digest(event.result_digest, 1U);
	fill_digest(event.payload_digest, 2U);
	fill_digest(event.provenance_digest, 3U);
	return event;
}

static struct rdr_policy make_policy(uint64_t now, uint64_t sequence,
					uint64_t task_generation)
{
	struct rdr_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.now_ns = now;
	policy.expected_objective_id = 11U;
	policy.expected_trace_id = 22U;
	policy.expected_agent_id = 33U;
	policy.expected_tenant_id = 44U;
	policy.expected_task_generation = task_generation;
	policy.expected_session_generation = 2U;
	policy.expected_world_generation = 3U;
	policy.expected_next_sequence = sequence;
	policy.max_age_ns = 1000U;
	policy.require_verified = 1U;
	return policy;
}

int main(void)
{
	struct rdr_service service;
	struct rdr_service recovered;
	struct rdr_event event;
	struct rdr_event committed;
	struct rdr_event discarded;
	struct rdr_event replay[4];
	struct rdr_projection projection;
	struct rdr_replay_cursor cursor;
	struct rdr_policy policy;
	uint8_t transition[RDR_DIGEST_SIZE];
	uint8_t tail[RDR_DIGEST_SIZE];
	uint8_t previous[RDR_DIGEST_SIZE];
	unsigned int mutation;
	int result;
	size_t replay_count = 0U;

	expect_eq("init", rdr_init(&service), RDR_OK);
	event = make_result(100U, 100U, 1U);
	policy = make_policy(110U, 1U, 1U);
	expect_eq("append result", rdr_append_result(&service, &event, &policy,
			&event), RDR_OK);
	expect_eq("query retained", rdr_query(&service, 100U, &projection),
			RDR_OK);
	expect_eq("retained state", (int)projection.state, RDR_STATE_RETAINED);

	fill_digest(transition, 9U);
	policy = make_policy(120U, 2U, 1U);
	expect_eq("commit without authority", rdr_append_transition(&service, 100U,
			RDR_EVENT_COMMIT, transition, &policy, &committed),
			RDR_ERR_AUTHORITY);
	policy.authority_granted = 1U;
	policy.independent_verifier = 1U;
	expect_eq("commit with authority", rdr_append_transition(&service, 100U,
			RDR_EVENT_COMMIT, transition, &policy, &committed), RDR_OK);
	expect_eq("query committed", rdr_query(&service, 100U, &projection), RDR_OK);
	expect_eq("committed state", (int)projection.state, RDR_STATE_COMMITTED);

	memcpy(tail, service.tail_chain_digest, sizeof(tail));
	expect_eq("recover journal", rdr_recover(&recovered, service.events,
			service.event_count, tail), RDR_OK);
	expect_eq("recover query", rdr_query(&recovered, 100U, &projection), RDR_OK);
	expect_eq("recovered committed", (int)projection.state,
			RDR_STATE_COMMITTED);

	memset(&cursor, 0, sizeof(cursor));
	cursor.expected_task_generation = 1U;
	cursor.expected_session_generation = 2U;
	cursor.expected_world_generation = 3U;
	cursor.max_events = 4U;
	expect_eq("replay", rdr_replay_since(&recovered, &cursor, replay, 4U,
			&replay_count), RDR_OK);
	expect_eq("replay count", (int)replay_count, 2);

	memset(previous, 0, sizeof(previous));
	for (mutation = 0U; mutation < 64U; ++mutation) {
		struct rdr_event mutated = service.events[0];
		mutated.event_digest[mutation % RDR_DIGEST_SIZE] ^= 0x80U;
		result = rdr_verify_event(&mutated, previous);
		if (result == RDR_OK)
			failures++;
	}

	cursor.expected_task_generation = 99U;
	expect_eq("replay generation fence", rdr_replay_since(&recovered, &cursor,
			replay, 4U, &replay_count), RDR_ERR_GENERATION);
	policy = make_policy(210U, 3U, 1U);
	event = make_result(101U, 200U, 1U);
	policy.authority_granted = 1U;
	policy.independent_verifier = 1U;
	expect_eq("append second result", rdr_append_result(&service, &event, &policy,
			&event), RDR_OK);
	fill_digest(transition, 19U);
	policy = make_policy(210U, 4U, 1U);
	expect_eq("discard second result", rdr_append_transition(&service, 101U,
			RDR_EVENT_DISCARD, transition, &policy, &discarded), RDR_OK);
	expect_eq("query discarded", rdr_query(&service, 101U, &projection), RDR_OK);
	expect_eq("discarded state", (int)projection.state, RDR_STATE_DISCARDED);

	event = make_result(102U, 300U, 1U);
	policy = make_policy(1301U, 5U, 1U);
	expect_eq("expired result", rdr_append_result(&service, &event, &policy,
			&event), RDR_ERR_EXPIRED);
	event = make_result(103U, 400U, 2U);
	policy = make_policy(410U, 5U, 1U);
	expect_eq("stale result generation", rdr_append_result(&service, &event,
			&policy, &event), RDR_ERR_GENERATION);
	event = make_result(104U, 500U, 1U);
	event.flags = 0U;
	policy = make_policy(510U, 5U, 1U);
	expect_eq("unverified result", rdr_append_result(&service, &event, &policy,
			&event), RDR_ERR_POLICY);

	printf("M238_RETENTION_SELFTEST_EXIT=%d cases=18 mutation_rejections=64\n",
	       failures == 0 ? 0 : 1);
	return failures == 0 ? 0 : 1;
}
