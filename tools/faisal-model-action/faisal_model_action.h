#ifndef FAISAL_MODEL_ACTION_H
#define FAISAL_MODEL_ACTION_H

#include <stdint.h>

#define FMA_ABI_VERSION 1U
#define FMA_DIGEST_SIZE 32U
#define FMA_MAX_PROVIDER 64U
#define FMA_MAX_MODEL 96U
#define FMA_MAX_TOOL 96U
#define FMA_PROVIDER_OPENAI 1U
#define FMA_PROVIDER_ANTHROPIC 2U
#define FMA_PROVIDER_GEMINI 3U
#define FMA_PROVIDER_QWEN 4U
#define FMA_PROVIDER_LOCAL 5U
#define FMA_ACTION_TOOL 1U
#define FMA_ACTION_STRUCTURED_RESPONSE 2U
#define FMA_ACTION_REFUSAL 3U
#define FMA_AUTH_NONE 0U
#define FMA_AUTH_POLICY 1U
#define FMA_AUTH_KERNEL 2U
#define FMA_AUTH_MODEL 3U
#define FMA_STATE_REJECTED 1U
#define FMA_STATE_ADMITTED 2U
#define FMA_STATE_COMPLETED 3U
#define FMA_STATE_FAILED 4U
#define FMA_VIOLATION_ABI 1U
#define FMA_VIOLATION_IDENTITY 2U
#define FMA_VIOLATION_SCHEMA 4U
#define FMA_VIOLATION_REFUSAL 8U
#define FMA_VIOLATION_AUTHORITY 16U
#define FMA_VIOLATION_PROVIDER 32U
#define FMA_VIOLATION_ACTION 64U
#define FMA_VIOLATION_EXPIRY 128U
#define FMA_VIOLATION_REPLAY 256U
#define FMA_VIOLATION_PROVENANCE 512U
#define FMA_VIOLATION_TAMPER 1024U
#define FMA_VIOLATION_RESULT 2048U

enum fma_status {
	FMA_OK = 0,
	FMA_ERR_ARGUMENT = -1,
	FMA_ERR_POLICY = -2,
	FMA_ERR_REPLAY = -3,
	FMA_ERR_EXPIRED = -4,
	FMA_ERR_TAMPER = -5,
	FMA_ERR_AUTHORITY = -6,
	FMA_ERR_SCHEMA = -7,
	FMA_ERR_PROVIDER = -8,
	FMA_ERR_STATE = -9
};

struct fma_action_envelope {
	uint32_t abi_version;
	uint32_t action_kind;
	uint32_t provider_kind;
	uint32_t schema_valid;
	uint32_t model_refusal;
	uint32_t authority_source;
	uint32_t reserved0;
	uint32_t reserved1;
	uint64_t request_id;
	uint64_t agent_id;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t tool_id;
	uint64_t registry_generation;
	uint64_t revocation_generation;
	uint64_t authority_lease_id;
	uint64_t request_sequence;
	uint64_t nonce;
	uint64_t issued_at_ns;
	uint64_t expires_at_ns;
	uint32_t confidence_ppm;
	uint32_t reserved2;
	uint8_t input_digest[FMA_DIGEST_SIZE];
	uint8_t schema_digest[FMA_DIGEST_SIZE];
	uint8_t arguments_digest[FMA_DIGEST_SIZE];
	uint8_t model_provenance_digest[FMA_DIGEST_SIZE];
	char provider[FMA_MAX_PROVIDER];
	char model[FMA_MAX_MODEL];
	char tool[FMA_MAX_TOOL];
};

struct fma_policy {
	uint64_t now_ns;
	uint64_t expected_agent_id;
	uint64_t expected_objective_id;
	uint64_t expected_tenant_id;
	uint64_t expected_tool_id;
	uint64_t expected_registry_generation;
	uint64_t expected_revocation_generation;
	uint64_t expected_authority_lease_id;
	uint64_t max_ttl_ns;
	uint32_t allowed_provider_mask;
	uint32_t allowed_action_mask;
	uint32_t authority_granted;
	uint32_t require_schema;
	uint32_t require_provenance;
};

struct fma_decision {
	uint32_t state;
	uint32_t violation_mask;
	uint64_t request_id;
	uint64_t admitted_sequence;
	uint64_t nonce;
	uint8_t envelope_digest[FMA_DIGEST_SIZE];
};

struct fma_completion {
	uint64_t request_id;
	uint64_t observed_at_ns;
	uint32_t result_code;
	uint32_t verifier_authorized;
	uint8_t result_digest[FMA_DIGEST_SIZE];
};

struct fma_verifier {
	uint64_t last_sequence;
	uint64_t last_nonce;
	uint64_t active_request_id;
	uint8_t active_envelope_digest[FMA_DIGEST_SIZE];
	uint32_t active_state;
};

int fma_init(struct fma_verifier *verifier);
int fma_digest(const struct fma_action_envelope *envelope,
	uint8_t digest[FMA_DIGEST_SIZE]);
int fma_admit(struct fma_verifier *verifier,
	const struct fma_action_envelope *envelope,
	const struct fma_policy *policy,
	struct fma_decision *decision);
int fma_complete(struct fma_verifier *verifier,
	const struct fma_action_envelope *envelope,
	const struct fma_decision *decision,
	const struct fma_completion *completion);
int fma_query(const struct fma_verifier *verifier,
	struct fma_decision *decision);

#endif
