#ifndef FAISAL_DEPLOY_SUPERVISOR_H
#define FAISAL_DEPLOY_SUPERVISOR_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"

#define M78_MAX_BUILD_ID 96
#define M78_MAX_AUDIT 32
#define M78_MAX_FUZZ 64
#define M78_DIGEST_SIZE FMS_DIGEST_SIZE

#define M78_APPROVAL_SUPERVISOR (1U << 0)
#define M78_APPROVAL_OPERATOR (1U << 1)
#define M78_APPROVAL_INTEGRITY (1U << 2)
#define M78_APPROVAL_CANARY (1U << 3)

enum m78_state {
	M78_STATE_DENIED = 0,
	M78_STATE_CANDIDATE = 1,
	M78_STATE_CHECKPOINTED = 2,
	M78_STATE_CANARY = 3,
	M78_STATE_ACTIVE = 4,
	M78_STATE_ROLLBACK_PENDING = 5,
	M78_STATE_ROLLED_BACK = 6,
	M78_STATE_FAILED = 7
};

struct m78_candidate {
	char build_id[M78_MAX_BUILD_ID];
	uint8_t artifact_digest[M78_DIGEST_SIZE];
	uint8_t state_digest[M78_DIGEST_SIZE];
	uint64_t policy_generation;
	uint64_t cpu_budget_ns;
	uint64_t memory_limit_pages;
	uint64_t canary_window_ns;
	uint32_t required_approvals;
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint32_t integrity_measured;
	uint32_t reserved;
	uint64_t supervisor_nonce;
	uint64_t operator_nonce;
};

struct m78_audit_record {
	uint64_t sequence;
	uint64_t candidate_generation;
	uint32_t state;
	uint32_t reason;
	uint64_t checkpoint_id;
	uint64_t recovery_sequence;
	uint64_t provenance_sequence;
	uint64_t sampled_at_ns;
	uint32_t measured_mask;
	uint32_t unavailable_mask;
	uint32_t unsupported_mask;
	uint8_t artifact_digest[M78_DIGEST_SIZE];
};

struct m78_deployment {
	struct m78_candidate candidate;
	struct agi_lc_checkpoint checkpoint;
	struct agi_lc_checkpoint_manifest manifest;
	struct agi_lc_verify verification;
	struct agi_lc_handoff handoff;
	struct agi_lc_recovery recovery;
	struct agi_lc_resource_snapshot snapshot;
	struct agi_lc_observability observability;
	struct m78_audit_record audit[M78_MAX_AUDIT];
	uint32_t audit_count;
	uint32_t state;
	uint32_t canary_passed;
	uint32_t rollback_reason;
	uint64_t audit_sequence;
	uint64_t provenance_sequence;
};

struct m78_service {
	struct fms_service memory;
	struct m78_deployment deployment;
};

int m78_open(struct m78_service *service, const char *journal_path);
void m78_close(struct m78_service *service);
uint64_t m78_candidate_digest(const struct m78_candidate *candidate);
int m78_compute_candidate_digest(const struct m78_candidate *candidate,
				 uint8_t digest[M78_DIGEST_SIZE]);
int m78_validate_candidate(const struct m78_candidate *candidate);
int m78_admit(struct m78_service *service, const struct m78_candidate *candidate);
int m78_checkpoint(struct m78_service *service);
int m78_canary(struct m78_service *service, uint32_t health_ok);
int m78_activate(struct m78_service *service);
int m78_rollback(struct m78_service *service, uint32_t reason);
int m78_test_approval_denial(struct m78_service *service,
			     const struct m78_candidate *candidate);
int m78_test_manifest_fuzz(const struct m78_candidate *candidate);
int m78_test_model_authority_denial(struct m78_service *service);

#endif
