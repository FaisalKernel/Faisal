#ifndef FAISAL_KV_TIER_H
#define FAISAL_KV_TIER_H

#include <stddef.h>
#include <stdint.h>

#define RKV_ABI_VERSION 1U
#define RKV_DIGEST_SIZE 32U
#define RKV_MAX_RECORDS 128U
#define RKV_TIER_HBM 1U
#define RKV_TIER_DDR 2U
#define RKV_TIER_NVME 3U
#define RKV_TIER_NETWORK 4U
#define RKV_TIER_MASK(tier) (1U << (tier))
#define RKV_STATE_ADMITTED 1U
#define RKV_STATE_RESIDENT 2U
#define RKV_STATE_MIGRATING 3U
#define RKV_STATE_EVICTED 4U
#define RKV_FLAG_VERIFIED (1U << 0)
#define RKV_FLAG_AUTHORIZED (1U << 1)
#define RKV_FLAG_PREDICTED (1U << 2)
#define RKV_FLAGS_ALL ((1U << 3) - 1U)

enum rkv_status {
	RKV_OK = 0,
	RKV_ERR_ARGUMENT = -1,
	RKV_ERR_POLICY = -2,
	RKV_ERR_FULL = -3,
	RKV_ERR_NOT_FOUND = -4,
	RKV_ERR_GENERATION = -5,
	RKV_ERR_EXPIRED = -6,
	RKV_ERR_TAMPER = -7,
	RKV_ERR_STATE = -8,
	RKV_ERR_CAPACITY = -9,
	RKV_ERR_REPLAY = -10,
	RKV_ERR_AUTHORITY = -11
};

struct rkv_request {
	uint64_t cache_id;
	uint64_t model_id;
	uint64_t objective_id;
	uint64_t trace_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t world_generation;
	uint64_t model_generation;
	uint64_t request_sequence;
	uint64_t issued_at_ns;
	uint64_t observed_at_ns;
	uint64_t deadline_ns;
	uint64_t bytes;
	uint64_t page_count;
	uint64_t locality_domain;
	uint64_t bandwidth_bytes_s;
	uint64_t latency_ns;
	uint32_t source_tier;
	uint32_t target_tier;
	uint32_t pressure_ppm;
	uint32_t flags;
	uint8_t content_digest[RKV_DIGEST_SIZE];
	uint8_t metadata_digest[RKV_DIGEST_SIZE];
	uint8_t provenance_digest[RKV_DIGEST_SIZE];
};

struct rkv_policy {
	uint64_t now_ns;
	uint64_t expected_model_id;
	uint64_t expected_objective_id;
	uint64_t expected_trace_id;
	uint64_t expected_agent_id;
	uint64_t expected_tenant_id;
	uint64_t expected_task_generation;
	uint64_t expected_session_generation;
	uint64_t expected_world_generation;
	uint64_t expected_model_generation;
	uint64_t expected_sequence;
	uint64_t max_age_ns;
	uint64_t max_latency_ns;
	uint32_t allowed_tier_mask;
	uint32_t require_provenance;
	uint32_t authority_granted;
};

struct rkv_receipt {
	uint64_t receipt_id;
	uint64_t cache_id;
	uint64_t receipt_sequence;
	uint64_t observed_generation;
	uint32_t state;
	uint32_t source_tier;
	uint32_t target_tier;
	uint8_t request_digest[RKV_DIGEST_SIZE];
	uint8_t transition_digest[RKV_DIGEST_SIZE];
	uint8_t receipt_digest[RKV_DIGEST_SIZE];
};

struct rkv_record {
	struct rkv_request request;
	struct rkv_receipt receipt;
	uint32_t state;
	uint32_t reserved;
};

struct rkv_service {
	struct rkv_record records[RKV_MAX_RECORDS];
	size_t record_count;
	uint64_t next_cache_id;
	uint64_t next_receipt_id;
	uint64_t receipt_sequence;
};

int rkv_init(struct rkv_service *service);
int rkv_admit(struct rkv_service *service, const struct rkv_request *request,
	const struct rkv_policy *policy, struct rkv_receipt *out);
int rkv_transition(struct rkv_service *service, uint64_t cache_id,
	uint32_t target_tier, uint64_t observed_generation,
	uint64_t observed_at_ns, uint64_t bytes_moved,
	const uint8_t transfer_digest[RKV_DIGEST_SIZE],
	const struct rkv_policy *policy, struct rkv_receipt *out);
int rkv_query(const struct rkv_service *service, uint64_t cache_id,
	struct rkv_record *out);
int rkv_verify_receipt(const struct rkv_receipt *receipt);
int rkv_digest_request(const struct rkv_request *request,
	uint8_t digest[RKV_DIGEST_SIZE]);

#endif
