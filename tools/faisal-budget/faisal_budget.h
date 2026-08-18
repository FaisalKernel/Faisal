#ifndef FAISAL_BUDGET_H
#define FAISAL_BUDGET_H

#include <stddef.h>
#include <stdint.h>

#define M240_DIGEST_SIZE 32U
#define M240_MAX_RECORDS 128U
#define M240_MAX_RECEIPTS 256U
#define M240_PPM_SCALE 1000000U

#define M240_FLAG_MODEL_PROPOSAL      (1U << 0)
#define M240_FLAG_VERIFIED_INPUT     (1U << 1)
#define M240_FLAG_AUTHORITY_GRANTED  (1U << 2)
#define M240_FLAG_HARD_DEADLINE      (1U << 3)
#define M240_FLAG_ENERGY_SENSITIVE   (1U << 4)
#define M240_FLAGS_ALL (M240_FLAG_MODEL_PROPOSAL | M240_FLAG_VERIFIED_INPUT | \
                        M240_FLAG_AUTHORITY_GRANTED | M240_FLAG_HARD_DEADLINE | \
                        M240_FLAG_ENERGY_SENSITIVE)

enum m240_state {
	M240_STATE_DENIED = 0U,
	M240_STATE_ADMITTED = 1U,
	M240_STATE_ACTIVE = 2U,
	M240_STATE_EXHAUSTED = 3U,
	M240_STATE_COMPLETED = 4U,
	M240_STATE_CANCELLED = 5U,
	M240_STATE_EXPIRED = 6U,
	M240_STATE_TAMPERED = 7U
};

enum m240_status {
	M240_OK = 0,
	M240_ERR_ARGUMENT = -1,
	M240_ERR_FULL = -2,
	M240_ERR_DUPLICATE = -3,
	M240_ERR_NOT_FOUND = -4,
	M240_ERR_GENERATION = -5,
	M240_ERR_REPLAY = -6,
	M240_ERR_POLICY = -7,
	M240_ERR_AUTHORITY = -8,
	M240_ERR_DEADLINE = -9,
	M240_ERR_BUDGET = -10,
	M240_ERR_STATE = -11,
	M240_ERR_TAMPER = -12
};

struct m240_budget {
	uint64_t cpu_ns;
	uint64_t memory_bytes;
	uint64_t gpu_ns;
	uint64_t npu_ns;
	uint64_t network_bytes;
	uint64_t storage_bytes;
	uint64_t cost_micro;
	uint64_t energy_uj;
};

struct m240_policy {
	uint64_t current_time_ns;
	uint64_t expected_tenant_id;
	uint64_t expected_agent_id;
	uint64_t expected_task_generation;
	uint64_t expected_session_generation;
	uint64_t expected_world_generation;
	uint64_t expected_model_generation;
	uint64_t max_deadline_horizon_ns;
	struct m240_budget maximum;
	uint32_t minimum_priority;
	uint32_t require_authority;
	uint32_t require_verified_input;
	uint32_t reserved;
};

struct m240_request {
	uint64_t objective_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t trace_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t world_generation;
	uint64_t model_generation;
	uint64_t request_sequence;
	uint64_t issued_at_ns;
	uint64_t deadline_ns;
	uint32_t priority;
	uint32_t flags;
	struct m240_budget requested;
	uint8_t objective_digest[M240_DIGEST_SIZE];
	uint8_t provenance_digest[M240_DIGEST_SIZE];
};

struct m240_receipt {
	uint64_t receipt_id;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t trace_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t receipt_sequence;
	uint64_t observed_at_ns;
	uint32_t state;
	int32_t status;
	struct m240_budget remaining;
	uint8_t request_digest[M240_DIGEST_SIZE];
	uint8_t usage_digest[M240_DIGEST_SIZE];
	uint8_t receipt_digest[M240_DIGEST_SIZE];
};

struct m240_record {
	struct m240_request request;
	struct m240_budget remaining;
	struct m240_budget consumed;
	uint8_t request_digest[M240_DIGEST_SIZE];
	uint32_t state;
	uint32_t reserved;
	struct m240_receipt receipt;
};

struct m240_service {
	struct m240_policy policy;
	struct m240_record records[M240_MAX_RECORDS];
	struct m240_receipt receipts[M240_MAX_RECEIPTS];
	size_t record_count;
	size_t receipt_count;
	uint64_t next_receipt_id;
	uint64_t receipt_sequence;
};

int m240_init(struct m240_service *service, const struct m240_policy *policy);
int m240_admit(struct m240_service *service, const struct m240_request *request,
	       struct m240_receipt *out);
int m240_consume(struct m240_service *service, uint64_t objective_id,
		 uint64_t task_generation, uint64_t session_generation,
		 const struct m240_budget *usage, uint64_t observed_at_ns,
		 struct m240_receipt *out);
int m240_complete(struct m240_service *service, uint64_t objective_id,
		  uint64_t task_generation, uint64_t session_generation,
		  uint64_t observed_at_ns, struct m240_receipt *out);
int m240_cancel(struct m240_service *service, uint64_t objective_id,
		uint64_t task_generation, uint64_t session_generation,
		uint64_t observed_at_ns, struct m240_receipt *out);
int m240_query(const struct m240_service *service, uint64_t objective_id,
	      struct m240_record *out);
int m240_verify_receipt(const struct m240_receipt *receipt);
int m240_authority_check(const struct m240_request *request,
			 const struct m240_policy *policy);

#endif
