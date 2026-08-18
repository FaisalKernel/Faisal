#ifndef FAISAL_TRACE_CORRELATION_H
#define FAISAL_TRACE_CORRELATION_H

#include <stddef.h>
#include <stdint.h>

#define MTC_DIGEST_SIZE 32U
#define MTC_MAX_EVENTS 128U
#define MTC_MAX_ATTRIBUTE 64U
#define MTC_MAX_BAGGAGE 16U

#define MTC_KIND_AGENT 1U
#define MTC_KIND_OBJECTIVE 2U
#define MTC_KIND_MODEL_REQUEST 3U
#define MTC_KIND_TOOL_REQUEST 4U
#define MTC_KIND_SANDBOX 5U
#define MTC_KIND_WORLD_OBSERVATION 6U
#define MTC_KIND_RECOVERY 7U
#define MTC_KIND_COMPLETION 8U
#define MTC_KIND_KERNEL 9U

#define MTC_FLAG_MEASURED (1U << 0)
#define MTC_FLAG_MODEL_OUTPUT (1U << 1)
#define MTC_FLAG_TOOL_CALL (1U << 2)
#define MTC_FLAG_EXTERNAL_CONTEXT (1U << 3)
#define MTC_FLAG_AUTHORITY_PROPOSAL (1U << 4)
#define MTC_FLAG_AUTHORIZED (1U << 5)
#define MTC_FLAG_BAGGAGE_ALLOWED (1U << 6)

#define MTC_STATE_OPEN 0U
#define MTC_STATE_CLOSED 1U
#define MTC_STATE_REJECTED 2U

enum mtc_status {
	MTC_OK = 0,
	MTC_ERR_ARGUMENT = -1,
	MTC_ERR_FULL = -2,
	MTC_ERR_REPLAY = -3,
	MTC_ERR_CONTEXT = -4,
	MTC_ERR_CHAIN = -5,
	MTC_ERR_CORRUPT = -6,
	MTC_ERR_GENERATION = -7,
	MTC_ERR_AUTHORITY = -8,
	MTC_ERR_NOT_FOUND = -9
};

struct mtc_context {
	uint8_t trace_id[16];
	uint8_t span_id[8];
	uint8_t parent_span_id[8];
	uint8_t trace_flags;
	uint8_t reserved[7];
};

struct mtc_lineage {
	uint64_t agent_id;
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t worker_id;
	uint64_t model_request_id;
	uint64_t tool_request_id;
	uint64_t sandbox_id;
	uint64_t world_observation_id;
	uint64_t recovery_decision_id;
};

struct mtc_event {
	uint64_t event_sequence;
	uint64_t generation;
	uint64_t observed_at_ns;
	uint32_t kind;
	uint32_t flags;
	uint32_t provider_kind;
	uint32_t capability_kind;
	struct mtc_context context;
	struct mtc_lineage lineage;
	uint64_t provider_sequence;
	uint64_t cursor;
	uint8_t provider_digest[MTC_DIGEST_SIZE];
	uint64_t previous_event_sequence;
	uint8_t previous_event_digest[MTC_DIGEST_SIZE];
	char attribute[MTC_MAX_ATTRIBUTE];
	uint8_t digest[MTC_DIGEST_SIZE];
};

struct mtc_policy {
	uint64_t expected_generation;
	uint64_t minimum_event_time_ns;
	uint32_t reject_external_context;
	uint32_t reject_baggage;
	uint32_t require_measured_external_events;
	uint32_t max_events;
};

struct mtc_service {
	struct mtc_policy policy;
	struct mtc_event events[MTC_MAX_EVENTS];
	size_t event_count;
	uint64_t last_event_sequence;
	uint8_t last_event_digest[MTC_DIGEST_SIZE];
	uint64_t trace_generation;
};

int mtc_init(struct mtc_service *service, const struct mtc_policy *policy,
		 const struct mtc_context *root_context,
		 uint64_t trace_generation);
int mtc_validate_context(const struct mtc_context *context);
int mtc_record_event(struct mtc_service *service, const struct mtc_event *event,
		     struct mtc_event *out);
int mtc_verify_event(const struct mtc_service *service,
		     const struct mtc_event *event);
int mtc_query_event(const struct mtc_service *service, uint64_t event_sequence,
		   struct mtc_event *out);
int mtc_authority_check(const struct mtc_event *event);

#endif
