#ifndef FAISAL_RESULT_RETENTION_H
#define FAISAL_RESULT_RETENTION_H

#include <stddef.h>
#include <stdint.h>

#define RDR_ABI_VERSION 1U
#define RDR_DIGEST_SIZE 32U
#define RDR_MAX_EVENTS 256U
#define RDR_MAX_PROJECTIONS 128U
#define RDR_STATE_RETAINED 1U
#define RDR_STATE_COMMITTED 2U
#define RDR_STATE_DISCARDED 3U
#define RDR_EVENT_RESULT 1U
#define RDR_EVENT_COMMIT 2U
#define RDR_EVENT_DISCARD 3U
#define RDR_FLAG_VERIFIED (1U << 0)
#define RDR_FLAG_AUTHORITY (1U << 1)
#define RDR_FLAG_INDEPENDENT_VERIFIER (1U << 2)
#define RDR_FLAGS_ALL ((1U << 3) - 1U)

enum rdr_status {
	RDR_OK = 0,
	RDR_ERR_ARGUMENT = -1,
	RDR_ERR_POLICY = -2,
	RDR_ERR_REPLAY = -3,
	RDR_ERR_EXPIRED = -4,
	RDR_ERR_TAMPER = -5,
	RDR_ERR_AUTHORITY = -6,
	RDR_ERR_GENERATION = -7,
	RDR_ERR_SEQUENCE = -8,
	RDR_ERR_FULL = -9,
	RDR_ERR_NOT_FOUND = -10,
	RDR_ERR_STATE = -11,
	RDR_ERR_CONFLICT = -12
};

struct rdr_event {
	uint64_t event_id;
	uint64_t sequence;
	uint64_t result_id;
	uint64_t receipt_id;
	uint64_t tool_id;
	uint64_t tool_call_id;
	uint64_t objective_id;
	uint64_t trace_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t world_generation;
	uint64_t event_at_ns;
	uint64_t expires_at_ns;
	uint32_t event_kind;
	uint32_t flags;
	uint8_t result_digest[RDR_DIGEST_SIZE];
	uint8_t payload_digest[RDR_DIGEST_SIZE];
	uint8_t provenance_digest[RDR_DIGEST_SIZE];
	uint8_t transition_digest[RDR_DIGEST_SIZE];
	uint8_t previous_chain_digest[RDR_DIGEST_SIZE];
	uint8_t event_digest[RDR_DIGEST_SIZE];
	uint8_t chain_digest[RDR_DIGEST_SIZE];
};

struct rdr_projection {
	uint64_t result_id;
	uint64_t receipt_id;
	uint64_t last_sequence;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t world_generation;
	uint32_t state;
	uint32_t replay_count;
	uint8_t result_digest[RDR_DIGEST_SIZE];
	uint8_t payload_digest[RDR_DIGEST_SIZE];
	uint8_t provenance_digest[RDR_DIGEST_SIZE];
};

struct rdr_policy {
	uint64_t now_ns;
	uint64_t expected_objective_id;
	uint64_t expected_trace_id;
	uint64_t expected_agent_id;
	uint64_t expected_tenant_id;
	uint64_t expected_task_generation;
	uint64_t expected_session_generation;
	uint64_t expected_world_generation;
	uint64_t expected_next_sequence;
	uint64_t max_age_ns;
	uint32_t require_verified;
	uint32_t authority_granted;
	uint32_t independent_verifier;
};

struct rdr_replay_cursor {
	uint64_t after_sequence;
	uint64_t expected_task_generation;
	uint64_t expected_session_generation;
	uint64_t expected_world_generation;
	uint64_t max_events;
};

struct rdr_service {
	struct rdr_event events[RDR_MAX_EVENTS];
	struct rdr_projection projections[RDR_MAX_PROJECTIONS];
	size_t event_count;
	size_t projection_count;
	uint64_t next_event_id;
	uint64_t next_sequence;
	uint8_t tail_chain_digest[RDR_DIGEST_SIZE];
};

int rdr_init(struct rdr_service *service);
int rdr_append_result(struct rdr_service *service,
	const struct rdr_event *event, const struct rdr_policy *policy,
	struct rdr_event *out);
int rdr_append_transition(struct rdr_service *service, uint64_t result_id,
	uint32_t event_kind, const uint8_t transition_digest[RDR_DIGEST_SIZE],
	const struct rdr_policy *policy, struct rdr_event *out);
int rdr_recover(struct rdr_service *service, const struct rdr_event *events,
	size_t event_count, const uint8_t expected_tail[RDR_DIGEST_SIZE]);
int rdr_replay_since(const struct rdr_service *service,
	const struct rdr_replay_cursor *cursor, struct rdr_event *out,
	size_t capacity, size_t *out_count);
int rdr_query(const struct rdr_service *service, uint64_t result_id,
	struct rdr_projection *out);
int rdr_verify_event(const struct rdr_event *event,
	const uint8_t previous_chain[RDR_DIGEST_SIZE]);
int rdr_digest_event(const struct rdr_event *event,
	uint8_t digest[RDR_DIGEST_SIZE]);

#endif
