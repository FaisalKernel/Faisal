#ifndef FAISAL_INFERENCE_CONTRACT_H
#define FAISAL_INFERENCE_CONTRACT_H

#include <stddef.h>
#include <stdint.h>
#include "../faisal-model-router/faisal_model_router.h"

#define FIC_ABI_VERSION 1U
#define FIC_MAX_REASON 256U
#define FIC_DIGEST_SIZE 32U
#define FIC_PHASE_PREFILL 1U
#define FIC_PHASE_DECODE 2U
#define FIC_PHASE_BOTH (FIC_PHASE_PREFILL | FIC_PHASE_DECODE)
#define FIC_KV_GPU 1U
#define FIC_KV_HOST 2U
#define FIC_KV_LOCAL_STORAGE 4U
#define FIC_KV_REMOTE 8U
#define FIC_ROUTE_ALLOW_REMOTE 1U
#define FIC_ROUTE_REQUIRE_KV_LOCALITY 2U
#define FIC_ROUTE_FAIL_CLOSED 4U
#define FIC_VIOLATION_TTFT 1U
#define FIC_VIOLATION_ITL 2U
#define FIC_VIOLATION_COST 4U
#define FIC_VIOLATION_KV_LOCALITY 8U
#define FIC_VIOLATION_PHASE 16U
#define FIC_VIOLATION_BUDGET 32U
#define FIC_VIOLATION_AUTHORITY 64U
#define FIC_MAX_TENANT 64U
#define FIC_MAX_OBJECTIVE 96U

enum fic_status {
	FIC_OK = 0,
	FIC_ERR_ARGUMENT = -1,
	FIC_ERR_POLICY = -2,
	FIC_ERR_NO_ROUTE = -3,
	FIC_ERR_SLO = -4,
	FIC_ERR_TAMPER = -5,
	FIC_ERR_STATE = -6
};

enum fic_admission_state {
	FIC_ADMITTED = 1,
	FIC_REJECTED = 2,
	FIC_COMPLETED = 3,
	FIC_VIOLATED = 4
};

struct fic_objective {
	uint32_t abi_version;
	uint32_t requested_phases;
	uint32_t kv_tier_mask;
	uint32_t route_flags;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t deadline_ns;
	uint64_t max_ttft_ns;
	uint64_t max_itl_ns;
	uint64_t max_cost_micro;
	uint64_t max_accelerator_memory_bytes;
	uint64_t required_hardware_mask;
	uint64_t required_locality_mask;
	uint32_t difficulty;
	uint32_t required_modalities;
	uint32_t privacy_level;
	uint32_t min_accuracy_ppm;
	char tenant[FIC_MAX_TENANT];
	char objective[FIC_MAX_OBJECTIVE];
	uint8_t model_digest[FIC_DIGEST_SIZE];
	uint8_t input_digest[FIC_DIGEST_SIZE];
	uint64_t reserved[2];
};

struct fic_route_decision {
	uint32_t admission_state;
	uint32_t route_state;
	uint32_t violation_mask;
	uint32_t selected_phases;
	uint32_t selected_kv_tier;
	uint32_t reserved;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t model_id;
	uint64_t estimated_ttft_ns;
	uint64_t estimated_cost_micro;
	uint64_t decision_sequence;
	uint8_t provenance_digest[FIC_DIGEST_SIZE];
	char reason[FIC_MAX_REASON];
};

struct fic_completion {
	uint64_t ttft_ns;
	uint64_t itl_ns;
	uint64_t cost_micro;
	uint64_t accelerator_memory_bytes;
	uint32_t completed_phases;
	uint32_t observed_kv_tier;
	uint32_t authorized_result;
	uint32_t reserved;
};

struct fic_service {
	struct fmr_router *router;
	uint64_t next_sequence;
};

int fic_init(struct fic_service *service, struct fmr_router *router);
int fic_validate_objective(const struct fic_objective *objective);
int fic_admit_and_route(struct fic_service *service,
	const struct fic_objective *objective,
	struct fic_route_decision *decision);
int fic_verify_decision(const struct fic_service *service,
	const struct fic_objective *objective,
	const struct fic_route_decision *decision);
int fic_record_completion(struct fic_service *service,
	const struct fic_objective *objective,
	struct fic_route_decision *decision,
	const struct fic_completion *completion);
int fic_test_policy_boundaries(struct fic_service *service);

#endif
