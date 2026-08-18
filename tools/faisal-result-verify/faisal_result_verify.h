#ifndef FAISAL_RESULT_VERIFY_H
#define FAISAL_RESULT_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define FSV_ABI_VERSION 1U
#define FSV_DIGEST_SIZE 32U
#define FSV_MAX_CONTRACTS 64U
#define FSV_MAX_RECORDS 128U
#define FSV_MAX_NAME 64U
#define FSV_MAX_TOOL_CALL 96U
#define FSV_FLAG_MODEL_PROPOSAL (1U << 0)
#define FSV_FLAG_PROMOTION_REQUEST (1U << 1)
#define FSV_FLAG_PROVIDER_ERROR (1U << 2)
#define FSV_FLAG_ARTIFACT_PRESENT (1U << 3)
#define FSV_FLAGS_ALL ((1U << 4) - 1U)
#define FSV_OUTPUT_STRUCTURED 1U
#define FSV_OUTPUT_TEXT 2U
#define FSV_OUTPUT_BINARY 3U
#define FSV_STATE_VERIFIED 1U
#define FSV_STATE_PROMOTED 2U
#define FSV_STATE_REJECTED 3U
#define FSV_DECISION_VERIFIED 1U
#define FSV_DECISION_PROMOTED 2U

enum fsv_status {
	FSV_OK = 0,
	FSV_ERR_ARGUMENT = -1,
	FSV_ERR_POLICY = -2,
	FSV_ERR_REPLAY = -3,
	FSV_ERR_EXPIRED = -4,
	FSV_ERR_TAMPER = -5,
	FSV_ERR_AUTHORITY = -6,
	FSV_ERR_SCHEMA = -7,
	FSV_ERR_PROVIDER = -8,
	FSV_ERR_STATE = -9,
	FSV_ERR_GENERATION = -10,
	FSV_ERR_PROVENANCE = -11,
	FSV_ERR_ARTIFACT = -12,
	FSV_ERR_WORLD = -13,
	FSV_ERR_NOT_FOUND = -14,
	FSV_ERR_FULL = -15,
	FSV_ERR_CONFLICT = -16
};

struct fsv_tool_contract {
	uint64_t tool_id;
	uint64_t registry_generation;
	uint64_t schema_generation;
	uint32_t output_kind;
	uint32_t active;
	uint8_t schema_digest[FSV_DIGEST_SIZE];
	uint8_t implementation_digest[FSV_DIGEST_SIZE];
	char name[FSV_MAX_NAME];
};

struct fsv_result_request {
	uint64_t result_id;
	uint64_t tool_id;
	uint64_t tool_call_id;
	uint64_t objective_id;
	uint64_t trace_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t task_generation;
	uint64_t registry_generation;
	uint64_t schema_generation;
	uint64_t session_generation;
	uint64_t expected_world_generation;
	uint64_t request_sequence;
	uint64_t nonce;
	uint64_t issued_at_ns;
	uint64_t observed_at_ns;
	uint64_t deadline_ns;
	uint32_t result_code;
	uint32_t schema_valid;
	uint32_t is_error;
	uint32_t output_kind;
	uint32_t artifact_count;
	uint32_t validator_id;
	uint32_t flags;
	uint8_t input_digest[FSV_DIGEST_SIZE];
	uint8_t arguments_digest[FSV_DIGEST_SIZE];
	uint8_t schema_digest[FSV_DIGEST_SIZE];
	uint8_t payload_digest[FSV_DIGEST_SIZE];
	uint8_t provenance_digest[FSV_DIGEST_SIZE];
	uint8_t validator_digest[FSV_DIGEST_SIZE];
	uint8_t artifact_digest[FSV_DIGEST_SIZE];
	char tool_call[FSV_MAX_TOOL_CALL];
};

struct fsv_policy {
	uint64_t now_ns;
	uint64_t expected_tool_id;
	uint64_t expected_tool_call_id;
	uint64_t expected_objective_id;
	uint64_t expected_trace_id;
	uint64_t expected_agent_id;
	uint64_t expected_tenant_id;
	uint64_t expected_task_generation;
	uint64_t expected_registry_generation;
	uint64_t expected_schema_generation;
	uint64_t expected_session_generation;
	uint64_t expected_world_generation;
	uint64_t max_age_ns;
	uint64_t max_latency_ns;
	uint32_t expected_validator_id;
	uint32_t expected_output_kind;
	uint32_t require_schema;
	uint32_t require_provenance;
	uint32_t require_validator;
	uint32_t require_artifact;
	uint32_t authority_granted;
	uint32_t independent_verifier;
};

struct fsv_receipt {
	uint64_t receipt_id;
	uint64_t result_id;
	uint64_t tool_id;
	uint64_t tool_call_id;
	uint64_t receipt_sequence;
	uint64_t world_generation;
	uint32_t decision;
	uint32_t state;
	uint8_t request_digest[FSV_DIGEST_SIZE];
	uint8_t payload_digest[FSV_DIGEST_SIZE];
	uint8_t validation_digest[FSV_DIGEST_SIZE];
	uint8_t receipt_digest[FSV_DIGEST_SIZE];
};

struct fsv_record {
	struct fsv_result_request request;
	struct fsv_receipt receipt;
	uint32_t state;
	uint32_t reserved;
};

struct fsv_service {
	struct fsv_tool_contract contracts[FSV_MAX_CONTRACTS];
	struct fsv_record records[FSV_MAX_RECORDS];
	size_t contract_count;
	size_t record_count;
	uint64_t next_result_id;
	uint64_t next_receipt_id;
	uint64_t receipt_sequence;
	uint64_t last_request_sequence;
};

int fsv_init(struct fsv_service *service);
int fsv_register_tool(struct fsv_service *service,
	const struct fsv_tool_contract *contract, uint64_t *out_tool_id);
int fsv_admit_result(struct fsv_service *service,
	const struct fsv_result_request *request,
	const struct fsv_policy *policy, struct fsv_receipt *out);
int fsv_promote_result(struct fsv_service *service, uint64_t result_id,
	const struct fsv_policy *policy, struct fsv_receipt *out);
int fsv_query_result(const struct fsv_service *service, uint64_t result_id,
	struct fsv_record *out);
int fsv_verify_receipt(const struct fsv_service *service,
	const struct fsv_receipt *receipt);
int fsv_digest_request(const struct fsv_result_request *request,
	uint8_t digest[FSV_DIGEST_SIZE]);

#endif
