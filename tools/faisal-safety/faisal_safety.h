#ifndef FAISAL_SAFETY_H
#define FAISAL_SAFETY_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FSA_ABI_VERSION 1U
#define FSA_EVENT_MAGIC 0x46534131U
#define FSA_EVENT_VERSION 1U
#define FSA_DIGEST_SIZE 32U
#define FSA_MAX_INCIDENTS 128U
#define FSA_MAX_TOKENS 128U
#define FSA_MAX_REASON 192U
#define FSA_MAX_PAYLOAD 8192U
#define FSA_MAX_POLICY_NAME 64U

#define FSA_FLAG_FAIL_CLOSED (1U << 0)
#define FSA_FLAG_REQUIRE_IDENTITY (1U << 1)
#define FSA_FLAG_REQUIRE_CAPABILITY (1U << 2)
#define FSA_FLAG_REQUIRE_RESOURCE (1U << 3)
#define FSA_FLAG_REQUIRE_PROVENANCE (1U << 4)
#define FSA_FLAG_REQUIRE_ATTESTATION (1U << 5)
#define FSA_FLAG_REQUIRE_CHECKPOINT_HIGH_RISK (1U << 6)
#define FSA_FLAG_REQUIRE_OPERATOR_HIGH_RISK (1U << 7)

#define FSA_CAP_EXECUTE (1ULL << 0)
#define FSA_CAP_COMMAND (1ULL << 1)
#define FSA_CAP_FILESYSTEM_READ (1ULL << 2)
#define FSA_CAP_FILESYSTEM_WRITE (1ULL << 3)
#define FSA_CAP_NETWORK (1ULL << 4)
#define FSA_CAP_DEVICE (1ULL << 5)
#define FSA_CAP_SECRET (1ULL << 6)
#define FSA_CAP_BROWSER (1ULL << 7)
#define FSA_CAP_DEPLOY (1ULL << 8)
#define FSA_CAP_RECOVERY (1ULL << 9)
#define FSA_CAP_DEBUG (1ULL << 10)

#define FSA_ATTESTATION_UNKNOWN 0U
#define FSA_ATTESTATION_TRUSTED 1U
#define FSA_ATTESTATION_DEGRADED 2U
#define FSA_ATTESTATION_UNAVAILABLE 3U

#define FSA_ACTION_ALLOW 1U
#define FSA_ACTION_RESTRICT 2U
#define FSA_ACTION_CHECKPOINT 3U
#define FSA_ACTION_MIGRATE 4U
#define FSA_ACTION_QUARANTINE 5U
#define FSA_ACTION_TERMINATE 6U
#define FSA_ACTION_OPERATOR_REVIEW 7U

#define FSA_INCIDENT_DETECTED 1U
#define FSA_INCIDENT_TRIAGED 2U
#define FSA_INCIDENT_CONTAINED 3U
#define FSA_INCIDENT_RECOVERING 4U
#define FSA_INCIDENT_RECOVERED 5U
#define FSA_INCIDENT_CLOSED 6U
#define FSA_INCIDENT_ESCALATED 7U
#define FSA_INCIDENT_TERMINATED 8U

#define FSA_EVENT_DECISION 1U
#define FSA_EVENT_INCIDENT_START 2U
#define FSA_EVENT_INCIDENT_TRANSITION 3U
#define FSA_EVENT_CONTAINMENT_TOKEN 4U

#define FSA_VIOLATION_ABI (1U << 0)
#define FSA_VIOLATION_IDENTITY (1U << 1)
#define FSA_VIOLATION_CAPABILITY (1U << 2)
#define FSA_VIOLATION_RESOURCE (1U << 3)
#define FSA_VIOLATION_PROVENANCE (1U << 4)
#define FSA_VIOLATION_ATTESTATION (1U << 5)
#define FSA_VIOLATION_ANOMALY (1U << 6)
#define FSA_VIOLATION_RISK (1U << 7)
#define FSA_VIOLATION_CHECKPOINT (1U << 8)
#define FSA_VIOLATION_OPERATOR (1U << 9)
#define FSA_VIOLATION_MODEL_AUTHORITY (1U << 10)
#define FSA_VIOLATION_DEADLINE (1U << 11)
#define FSA_VIOLATION_GENERATION (1U << 12)
#define FSA_VIOLATION_REPLAY (1U << 13)
#define FSA_VIOLATION_TAMPER (1U << 14)
#define FSA_VIOLATION_INCIDENT_STATE (1U << 15)

#define FSA_HIGH_RISK_CAPS (FSA_CAP_SECRET | FSA_CAP_DEVICE | FSA_CAP_DEPLOY | FSA_CAP_RECOVERY)

enum fsa_status {
	FSA_OK = 0,
	FSA_ERR_ARGUMENT = -1,
	FSA_ERR_IO = -2,
	FSA_ERR_CORRUPT = -3,
	FSA_ERR_FULL = -4,
	FSA_ERR_NOT_FOUND = -5,
	FSA_ERR_POLICY = -6,
	FSA_ERR_STATE = -7,
	FSA_ERR_STALE = -8,
	FSA_ERR_TAMPER = -9,
	FSA_ERR_REPLAY = -10,
	FSA_ERR_AUTHORITY = -11,
	FSA_ERR_GENERATION = -12,
	FSA_ERR_DEADLINE = -13,
	FSA_ERR_CONTAINMENT = -14
};

struct fsa_policy {
	uint32_t abi_version;
	uint32_t flags;
	uint32_t max_risk_ppm;
	uint32_t max_anomaly_ppm;
	uint64_t max_decision_age_ns;
	uint64_t max_token_ttl_ns;
	uint64_t generation;
	uint64_t current_time_ns;
	uint8_t policy_digest[FSA_DIGEST_SIZE];
	char name[FSA_MAX_POLICY_NAME];
};

struct fsa_request {
	uint32_t abi_version;
	uint32_t attestation_state;
	uint64_t workload_id;
	uint64_t tenant_id;
	uint64_t agent_id;
	uint64_t generation;
	uint64_t policy_generation;
	uint64_t submitted_at_ns;
	uint64_t deadline_ns;
	uint64_t requested_capabilities;
	uint64_t granted_capabilities;
	uint64_t cpu_budget_ns;
	uint64_t memory_limit_bytes;
	uint64_t network_limit_bytes;
	uint64_t storage_limit_bytes;
	uint32_t risk_ppm;
	uint32_t anomaly_ppm;
	uint32_t checkpoint_available;
	uint32_t provenance_verified;
	uint32_t artifact_verified;
	uint32_t operator_approved;
	uint32_t model_claimed_authority;
	uint32_t irreversible_action;
	uint8_t identity_digest[FSA_DIGEST_SIZE];
	uint8_t provenance_digest[FSA_DIGEST_SIZE];
	uint8_t artifact_digest[FSA_DIGEST_SIZE];
	uint8_t attestation_digest[FSA_DIGEST_SIZE];
};

struct fsa_decision {
	uint64_t decision_id;
	uint64_t workload_id;
	uint64_t agent_id;
	uint64_t policy_generation;
	uint64_t observed_at_ns;
	uint64_t expiry_ns;
	uint32_t action;
	uint32_t violation_mask;
	uint64_t restricted_capabilities;
	uint32_t requires_operator;
	uint8_t request_digest[FSA_DIGEST_SIZE];
	uint8_t decision_digest[FSA_DIGEST_SIZE];
	char reason[FSA_MAX_REASON];
};

struct fsa_incident {
	uint64_t incident_id;
	uint64_t workload_id;
	uint64_t agent_id;
	uint64_t generation;
	uint64_t opened_at_ns;
	uint64_t updated_at_ns;
	uint64_t checkpoint_id;
	uint32_t state;
	uint32_t action;
	uint32_t severity;
	uint32_t transition_count;
	uint32_t violation_mask;
	uint8_t evidence_digest[FSA_DIGEST_SIZE];
	char reason[FSA_MAX_REASON];
};

struct fsa_containment_token {
	uint64_t token_id;
	uint64_t workload_id;
	uint64_t agent_id;
	uint64_t generation;
	uint64_t issued_at_ns;
	uint64_t expires_at_ns;
	uint32_t action;
	uint64_t restricted_capabilities;
	uint8_t token_digest[FSA_DIGEST_SIZE];
};

struct fsa_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t target_id;
	uint64_t generation;
	uint64_t observed_at_ns;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FSA_DIGEST_SIZE];
	uint8_t payload_digest[FSA_DIGEST_SIZE];
	uint8_t event_digest[FSA_DIGEST_SIZE];
};

struct fsa_disk_record {
	struct fsa_event event;
	uint8_t payload[FSA_MAX_PAYLOAD];
};

struct fsa_attestation {
	uint64_t last_sequence;
	uint64_t next_decision_id;
	uint64_t next_incident_id;
	uint64_t next_token_id;
	uint64_t decisions;
	uint64_t incidents;
	uint64_t quarantines;
	uint64_t terminations;
	uint8_t chain_digest[FSA_DIGEST_SIZE];
};

struct fsa_service {
	int journal_fd;
	pthread_mutex_t lock;
	struct fsa_policy policy;
	struct fsa_incident incidents[FSA_MAX_INCIDENTS];
	struct fsa_containment_token tokens[FSA_MAX_TOKENS];
	size_t incident_count;
	size_t token_count;
	uint64_t next_decision_id;
	uint64_t next_incident_id;
	uint64_t next_token_id;
	uint64_t decisions;
	uint64_t quarantines;
	uint64_t terminations;
	uint64_t next_sequence;
	uint8_t chain_digest[FSA_DIGEST_SIZE];
};

int fsa_open(struct fsa_service *service, const char *journal_path,
	     const struct fsa_policy *policy);
void fsa_close(struct fsa_service *service);
int fsa_replay(struct fsa_service *service);
int fsa_advance_time(struct fsa_service *service, uint64_t now_ns);
int fsa_query_attestation(const struct fsa_service *service,
			  struct fsa_attestation *out);
int fsa_evaluate(struct fsa_service *service, const struct fsa_request *request,
		struct fsa_decision *out);
int fsa_open_incident(struct fsa_service *service, uint64_t workload_id,
		      uint64_t agent_id, uint64_t generation, uint64_t now_ns,
		      uint32_t severity, uint32_t action, uint32_t violation_mask,
		      const char *reason, struct fsa_incident *out);
int fsa_transition_incident(struct fsa_service *service, uint64_t incident_id,
			    uint64_t generation, uint64_t now_ns, uint32_t next_state,
			    uint64_t checkpoint_id,
			    const uint8_t evidence_digest[FSA_DIGEST_SIZE],
			    const char *reason, struct fsa_incident *out);
int fsa_issue_containment(struct fsa_service *service, uint64_t workload_id,
			  uint64_t agent_id, uint64_t generation, uint64_t now_ns,
			  uint64_t ttl_ns, uint32_t action,
			  uint64_t restricted_capabilities,
			  struct fsa_containment_token *out);
int fsa_verify_containment(const struct fsa_service *service,
			   const struct fsa_containment_token *token,
			   uint64_t now_ns, uint64_t workload_id, uint64_t agent_id,
			   uint64_t generation);
int fsa_query_incident(const struct fsa_service *service, uint64_t incident_id,
			   struct fsa_incident *out);
int fsa_test_model_authority_denial(struct fsa_service *service,
				    const struct fsa_request *request);
int fsa_test_invalid_incident_transition(struct fsa_service *service,
					 uint64_t incident_id);
int fsa_test_corrupt_tail(const struct fsa_service *service);

#endif
