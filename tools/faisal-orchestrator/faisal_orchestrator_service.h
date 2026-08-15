#ifndef FAISAL_ORCHESTRATOR_SERVICE_H
#define FAISAL_ORCHESTRATOR_SERVICE_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"

#define FMO_MAX_MODEL_ID 96
#define FMO_MAX_OUTPUT 512
#define FMO_MAX_RUNS 8
#define FMO_DIGEST_SIZE FMS_DIGEST_SIZE

#define FMO_WORKLOAD_INFERENCE 1U
#define FMO_WORKLOAD_TRAINING 2U
#define FMO_WORKLOAD_EVALUATION 3U
#define FMO_WORKLOAD_MAX FMO_WORKLOAD_EVALUATION

enum fmo_state {
	FMO_DENIED = 0,
	FMO_ADMITTED = 1,
	FMO_CHECKPOINTED = 2,
	FMO_OUTPUT_PROPOSED = 3,
	FMO_ROLLED_BACK = 4
};

struct fmo_policy {
	uint64_t max_cpu_time_ns;
	uint64_t max_memory_pages;
	uint64_t policy_generation;
	uint32_t require_supervisor;
	uint32_t require_operator;
};

struct fmo_request {
	char model_id[FMO_MAX_MODEL_ID];
	uint8_t model_digest[FMO_DIGEST_SIZE];
	uint64_t cpu_time_ns;
	uint64_t memory_pages;
	uint32_t workload;
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint32_t reserved;
	uint64_t supervisor_nonce;
	uint64_t operator_nonce;
	uint64_t proposed_action_mask;
};

struct fmo_run {
	uint64_t run_id;
	uint64_t policy_generation;
	uint64_t checkpoint_id;
	uint64_t checkpoint_sequence;
	uint64_t parent_sequence;
	uint64_t recovery_sequence;
	uint32_t state;
	uint32_t recovery_state;
	uint8_t model_digest[FMO_DIGEST_SIZE];
	uint8_t state_digest[FMO_DIGEST_SIZE];
	uint8_t manifest_digest[FMO_DIGEST_SIZE];
	uint8_t output_digest[FMO_DIGEST_SIZE];
	uint64_t proposed_action_mask;
	uint64_t memory_record_id;
	uint64_t memory_capability;
	struct agi_lc_handoff handoff;
};

struct fmo_service {
	struct fms_service memory;
	struct fmo_policy policy;
	struct fmo_run runs[FMO_MAX_RUNS];
	uint32_t run_count;
};

void fmo_policy_default(struct fmo_policy *policy);
int fmo_open(struct fmo_service *service, const char *journal_path);
void fmo_close(struct fmo_service *service);
int fmo_admit(struct fmo_service *service, const struct fmo_request *request,
		      struct fmo_run *out);
int fmo_record_output(struct fmo_service *service, struct fmo_run *run,
		      const char *output, uint32_t policy_accepts_format);
int fmo_rollback(struct fmo_service *service, struct fmo_run *run);
int fmo_test_policy_denials(struct fmo_service *service,
			     const struct fmo_request *valid_request);
int fmo_test_output_is_untrusted(const struct fmo_run *run);

#endif
