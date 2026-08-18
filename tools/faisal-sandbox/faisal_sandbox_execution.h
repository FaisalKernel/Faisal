#ifndef FAISAL_SANDBOX_EXECUTION_H
#define FAISAL_SANDBOX_EXECUTION_H

#include <stdint.h>

#define FSE_ABI_VERSION 1U
#define FSE_DIGEST_SIZE 32U
#define FSE_MAX_PROVIDER 64U
#define FSE_MAX_HANDLE 96U
#define FSE_STATE_REJECTED 1U
#define FSE_STATE_ADMITTED 2U
#define FSE_STATE_RUNNING 3U
#define FSE_STATE_CHECKPOINTED 4U
#define FSE_STATE_CANCELLED 5U
#define FSE_STATE_COMPLETED 6U
#define FSE_STATE_FAILED 7U
#define FSE_VIOLATION_ABI 1U
#define FSE_VIOLATION_IDENTITY 2U
#define FSE_VIOLATION_CAPABILITY 4U
#define FSE_VIOLATION_RESOURCE 8U
#define FSE_VIOLATION_DEADLINE 16U
#define FSE_VIOLATION_AUTHORITY 32U
#define FSE_VIOLATION_PROVENANCE 64U
#define FSE_VIOLATION_REPLAY 128U
#define FSE_VIOLATION_GENERATION 256U
#define FSE_VIOLATION_CHECKPOINT 512U
#define FSE_VIOLATION_CANCEL 1024U
#define FSE_VIOLATION_TAMPER 2048U
#define FSE_VIOLATION_FUEL 4096U

enum fse_status {
	FSE_OK = 0,
	FSE_ERR_ARGUMENT = -1,
	FSE_ERR_POLICY = -2,
	FSE_ERR_CAPABILITY = -3,
	FSE_ERR_RESOURCE = -4,
	FSE_ERR_DEADLINE = -5,
	FSE_ERR_AUTHORITY = -6,
	FSE_ERR_REPLAY = -7,
	FSE_ERR_GENERATION = -8,
	FSE_ERR_CHECKPOINT = -9,
	FSE_ERR_CANCELLED = -10,
	FSE_ERR_TAMPER = -11,
	FSE_ERR_FUEL = -12,
	FSE_ERR_STATE = -13
};

struct fse_request {
	uint32_t abi_version;
	uint32_t reserved0;
	uint64_t request_id;
	uint64_t sandbox_id;
	uint64_t agent_id;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t sandbox_generation;
	uint64_t capability_mask;
	uint64_t cpu_budget_ns;
	uint64_t memory_budget_bytes;
	uint64_t io_budget_bytes;
	uint64_t fuel_budget;
	uint64_t deadline_ns;
	uint64_t authority_lease_id;
	uint64_t request_sequence;
	uint64_t nonce;
	uint64_t checkpoint_sequence;
	uint8_t input_digest[FSE_DIGEST_SIZE];
	uint8_t program_digest[FSE_DIGEST_SIZE];
	uint8_t imports_digest[FSE_DIGEST_SIZE];
	char provider[FSE_MAX_PROVIDER];
	char provider_handle[FSE_MAX_HANDLE];
	char stream_cursor[FSE_MAX_HANDLE];
};

struct fse_policy {
	uint64_t now_ns;
	uint64_t expected_sandbox_id;
	uint64_t expected_agent_id;
	uint64_t expected_objective_id;
	uint64_t expected_tenant_id;
	uint64_t expected_generation;
	uint64_t allowed_capability_mask;
	uint64_t max_cpu_budget_ns;
	uint64_t max_memory_budget_bytes;
	uint64_t max_io_budget_bytes;
	uint64_t max_fuel_budget;
	uint64_t max_runtime_ns;
	uint64_t expected_authority_lease_id;
	uint32_t authority_granted;
	uint32_t require_provider_handle;
	uint32_t require_stream_cursor;
};

struct fse_decision {
	uint32_t state;
	uint32_t violation_mask;
	uint64_t request_id;
	uint64_t admitted_sequence;
	uint64_t checkpoint_sequence;
	uint64_t consumed_fuel;
	uint8_t request_digest[FSE_DIGEST_SIZE];
	uint8_t checkpoint_digest[FSE_DIGEST_SIZE];
};

struct fse_checkpoint {
	uint64_t request_id;
	uint64_t checkpoint_sequence;
	uint64_t observed_ns;
	uint64_t remaining_fuel;
	uint8_t state_digest[FSE_DIGEST_SIZE];
	uint8_t request_digest[FSE_DIGEST_SIZE];
	uint8_t checkpoint_digest[FSE_DIGEST_SIZE];
};

struct fse_completion {
	uint64_t request_id;
	uint64_t observed_ns;
	uint64_t consumed_cpu_ns;
	uint64_t consumed_memory_bytes;
	uint64_t consumed_io_bytes;
	uint64_t consumed_fuel;
	uint32_t result_code;
	uint32_t authority_verified;
	uint8_t result_digest[FSE_DIGEST_SIZE];
};

struct fse_verifier {
	uint64_t last_sequence;
	uint64_t last_nonce;
	uint64_t active_request_id;
	uint64_t active_generation;
	uint64_t active_deadline_ns;
	uint64_t fuel_budget;
	uint64_t consumed_fuel;
	uint64_t checkpoint_sequence;
	uint32_t active_state;
	uint32_t violation_mask;
	uint8_t request_digest[FSE_DIGEST_SIZE];
	uint8_t checkpoint_digest[FSE_DIGEST_SIZE];
};

int fse_init(struct fse_verifier *verifier);
int fse_digest_request(const struct fse_request *request,
	uint8_t digest[FSE_DIGEST_SIZE]);
int fse_admit(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_policy *policy,
	struct fse_decision *decision);
int fse_start(struct fse_verifier *verifier, uint64_t now_ns);
int fse_consume_fuel(struct fse_verifier *verifier, uint64_t amount,
	uint64_t now_ns);
int fse_checkpoint(struct fse_verifier *verifier,
	const struct fse_request *request,
	uint64_t checkpoint_sequence,
	uint64_t observed_ns,
	const uint8_t state_digest[FSE_DIGEST_SIZE],
	struct fse_checkpoint *checkpoint);
int fse_resume(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_checkpoint *checkpoint,
	uint64_t now_ns);
int fse_cancel(struct fse_verifier *verifier);
int fse_complete(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_completion *completion);
int fse_query(const struct fse_verifier *verifier,
	struct fse_decision *decision);

#endif
