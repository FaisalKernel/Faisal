#ifndef FAISAL_AGENT_RUNTIME_H
#define FAISAL_AGENT_RUNTIME_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../faisal-budget/faisal_budget.h"

#define FAR_ABI_VERSION 1U
#define FAR_DIGEST_SIZE 32U
#define FAR_MAX_AGENTS 128U
#define FAR_MAX_OBJECTIVES 512U
#define FAR_MAX_EVENTS 4096U
#define FAR_MAX_TOOL_REQUESTS 512U
#define FAR_MAX_PAYLOAD 768U
#define FAR_MAX_NAME 96U
#define FAR_MAX_REASON 160U
#define FAR_EVENT_MAGIC 0x46415231U
#define FAR_EVENT_VERSION 1U

#define FAR_FLAG_MODEL_PROPOSAL     (1U << 0)
#define FAR_FLAG_AUTHORITY_GRANTED  (1U << 1)
#define FAR_FLAG_VERIFIED_INPUT     (1U << 2)
#define FAR_FLAG_CHECKPOINT_VERIFIED (1U << 3)
#define FAR_FLAG_REQUIRES_APPROVAL  (1U << 4)
#define FAR_FLAG_RECOVERY           (1U << 5)
#define FAR_FLAGS_ALL (FAR_FLAG_MODEL_PROPOSAL | FAR_FLAG_AUTHORITY_GRANTED | \
                       FAR_FLAG_VERIFIED_INPUT | FAR_FLAG_CHECKPOINT_VERIFIED | \
                       FAR_FLAG_REQUIRES_APPROVAL | FAR_FLAG_RECOVERY)

enum far_agent_state {
	FAR_AGENT_CREATED = 1U,
	FAR_AGENT_READY = 2U,
	FAR_AGENT_RUNNING = 3U,
	FAR_AGENT_WAITING = 4U,
	FAR_AGENT_RECOVERING = 5U,
	FAR_AGENT_QUARANTINED = 6U,
	FAR_AGENT_STOPPED = 7U
};

enum far_objective_state {
	FAR_OBJECTIVE_ADMITTED = 1U,
	FAR_OBJECTIVE_QUEUED = 2U,
	FAR_OBJECTIVE_RUNNING = 3U,
	FAR_OBJECTIVE_CHECKPOINTED = 4U,
	FAR_OBJECTIVE_RECOVERING = 5U,
	FAR_OBJECTIVE_SUCCEEDED = 6U,
	FAR_OBJECTIVE_FAILED = 7U,
	FAR_OBJECTIVE_CANCELLED = 8U,
	FAR_OBJECTIVE_QUARANTINED = 9U
};

enum far_event_kind {
	FAR_EVENT_REGISTER_AGENT = 1U,
	FAR_EVENT_ADMIT_OBJECTIVE = 2U,
	FAR_EVENT_DISPATCH = 3U,
	FAR_EVENT_CHECKPOINT = 4U,
	FAR_EVENT_RECOVER = 5U,
	FAR_EVENT_TOOL_REQUEST = 6U,
	FAR_EVENT_MESSAGE = 7U,
	FAR_EVENT_COMPLETE = 8U,
	FAR_EVENT_FAIL = 9U,
	FAR_EVENT_CANCEL = 10U,
	FAR_EVENT_ANOMALY = 11U
};

enum far_status {
	FAR_OK = 0,
	FAR_ERR_ARGUMENT = -1,
	FAR_ERR_IO = -2,
	FAR_ERR_FULL = -3,
	FAR_ERR_NOT_FOUND = -4,
	FAR_ERR_DUPLICATE = -5,
	FAR_ERR_STATE = -6,
	FAR_ERR_AUTHORITY = -7,
	FAR_ERR_CAPABILITY = -8,
	FAR_ERR_GENERATION = -9,
	FAR_ERR_DEADLINE = -10,
	FAR_ERR_BUDGET = -11,
	FAR_ERR_REPLAY = -12,
	FAR_ERR_TAMPER = -13,
	FAR_ERR_CHECKPOINT = -14,
	FAR_ERR_QUARANTINED = -15,
	FAR_ERR_POLICY = -16,
	FAR_ERR_CORRUPT = -17
};

struct far_policy {
	struct m240_policy budget_policy;
	uint64_t max_event_age_ns;
	uint32_t require_tool_authority;
	uint32_t require_message_authority;
	uint32_t require_verified_input;
	uint32_t reserved;
};

struct far_agent {
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t generation;
	uint64_t capability_mask;
	uint64_t last_event_sequence;
	uint64_t active_objectives;
	uint32_t state;
	uint32_t trust_ppm;
	uint32_t flags;
	uint32_t reserved;
	uint8_t identity_digest[FAR_DIGEST_SIZE];
	char name[FAR_MAX_NAME];
};

struct far_objective {
	uint64_t objective_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t trace_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t world_generation;
	uint64_t model_generation;
	uint64_t request_sequence;
	uint64_t created_at_ns;
	uint64_t deadline_ns;
	uint64_t checkpoint_sequence;
	uint64_t event_sequence;
	uint64_t required_capability_mask;
	uint32_t priority;
	uint32_t flags;
	uint32_t state;
	uint32_t anomaly_count;
	struct m240_budget budget;
	uint8_t objective_digest[FAR_DIGEST_SIZE];
	uint8_t provenance_digest[FAR_DIGEST_SIZE];
	uint8_t result_digest[FAR_DIGEST_SIZE];
	char name[FAR_MAX_NAME];
	char reason[FAR_MAX_REASON];
};

struct far_checkpoint {
	uint64_t objective_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint32_t verified;
	uint32_t reserved;
	uint8_t working_digest[FAR_DIGEST_SIZE];
	uint8_t memory_digest[FAR_DIGEST_SIZE];
	uint8_t world_digest[FAR_DIGEST_SIZE];
	uint8_t budget_digest[FAR_DIGEST_SIZE];
	uint8_t checkpoint_digest[FAR_DIGEST_SIZE];
};

struct far_tool_request {
	uint64_t request_id;
	uint64_t objective_id;
	uint64_t agent_id;
	uint64_t agent_generation;
	uint64_t capability;
	uint64_t authority_lease_id;
	uint64_t sequence;
	uint64_t issued_at_ns;
	uint64_t deadline_ns;
	uint32_t flags;
	uint32_t reserved;
	uint8_t input_digest[FAR_DIGEST_SIZE];
	uint8_t provenance_digest[FAR_DIGEST_SIZE];
	char tool_name[FAR_MAX_NAME];
};

struct far_anomaly {
	uint64_t agent_id;
	uint64_t objective_id;
	uint64_t observed_at_ns;
	uint32_t severity;
	uint32_t violation_mask;
	uint8_t evidence_digest[FAR_DIGEST_SIZE];
};

struct far_message {
	uint64_t message_id;
	uint64_t objective_id;
	uint64_t from_agent_id;
	uint64_t to_agent_id;
	uint64_t from_generation;
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint32_t flags;
	uint32_t reserved;
	uint8_t payload_digest[FAR_DIGEST_SIZE];
};

struct far_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint64_t agent_id;
	uint64_t objective_id;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FAR_DIGEST_SIZE];
	uint8_t payload_digest[FAR_DIGEST_SIZE];
	uint8_t event_digest[FAR_DIGEST_SIZE];
};

struct far_journal_attestation {
	uint64_t last_sequence;
	uint64_t record_count;
	uint64_t anomaly_count;
	uint8_t chain_digest[FAR_DIGEST_SIZE];
};

struct far_service {
	int journal_fd;
	char journal_path[4096];
	struct far_policy policy;
	struct m240_service budgets;
	struct far_agent agents[FAR_MAX_AGENTS];
	struct far_objective objectives[FAR_MAX_OBJECTIVES];
	struct far_checkpoint checkpoints[FAR_MAX_OBJECTIVES];
	struct far_tool_request tool_requests[FAR_MAX_TOOL_REQUESTS];
	size_t agent_count;
	size_t objective_count;
	size_t checkpoint_count;
	size_t tool_request_count;
	uint64_t next_agent_id;
	uint64_t next_objective_id;
	uint64_t next_message_id;
	uint64_t event_sequence;
	uint64_t anomaly_count;
	uint8_t chain_digest[FAR_DIGEST_SIZE];
	pthread_mutex_t lock;
	int lock_initialized;
};

int far_open(struct far_service *service, const char *journal_path,
	     const struct far_policy *policy);
void far_close(struct far_service *service);
int far_replay(struct far_service *service);
int far_query_journal(const struct far_service *service,
		      struct far_journal_attestation *out);
int far_register_agent(struct far_service *service, uint64_t tenant_id,
		       uint64_t capability_mask, uint32_t trust_ppm,
		       const uint8_t identity_digest[FAR_DIGEST_SIZE],
		       const char *name, struct far_agent *out);
int far_admit_objective(struct far_service *service,
			const struct far_objective *request,
			struct far_objective *out);
int far_dispatch(struct far_service *service, uint64_t objective_id,
		 uint64_t now_ns, struct far_objective *out);
int far_checkpoint(struct far_service *service, uint64_t objective_id,
		   uint64_t now_ns, const uint8_t working_digest[FAR_DIGEST_SIZE],
		   const uint8_t memory_digest[FAR_DIGEST_SIZE],
		   const uint8_t world_digest[FAR_DIGEST_SIZE],
		   struct far_checkpoint *out);
int far_recover(struct far_service *service, uint64_t objective_id,
		uint64_t now_ns, const struct far_checkpoint *checkpoint,
		struct far_objective *out);
int far_request_tool(struct far_service *service,
		     const struct far_tool_request *request);
int far_send_message(struct far_service *service,
		     const struct far_message *message);
int far_record_anomaly(struct far_service *service, uint64_t agent_id,
		       uint64_t objective_id, uint64_t now_ns,
		       uint32_t severity, uint32_t violation_mask,
		       const uint8_t evidence_digest[FAR_DIGEST_SIZE],
		       struct far_agent *agent_out,
		       struct far_objective *objective_out);
int far_complete(struct far_service *service, uint64_t objective_id,
		 uint64_t now_ns, const uint8_t result_digest[FAR_DIGEST_SIZE],
		 struct far_objective *out);
int far_fail(struct far_service *service, uint64_t objective_id,
	     uint64_t now_ns, const char *reason, struct far_objective *out);
int far_cancel(struct far_service *service, uint64_t objective_id,
	       uint64_t now_ns, struct far_objective *out);
int far_query_agent(const struct far_service *service, uint64_t agent_id,
		   struct far_agent *out);
int far_query_objective(const struct far_service *service,
		       uint64_t objective_id, struct far_objective *out);
int far_verify_event(const struct far_event *event,
		     const uint8_t payload[FAR_MAX_PAYLOAD],
		     const uint8_t previous_digest[FAR_DIGEST_SIZE]);

#endif
