#ifndef FAISAL_WORLD_RECONCILE_H
#define FAISAL_WORLD_RECONCILE_H

#include <stddef.h>
#include <stdint.h>

#define MWR_MAX_ITEMS 64U
#define MWR_MAX_RECEIPTS 64U
#define MWR_DIGEST_SIZE 32U
#define MWR_SCORE_MAX 1000000U

#define MWR_KIND_ENTITY 1U
#define MWR_KIND_RESOURCE 2U
#define MWR_KIND_SERVICE 3U
#define MWR_KIND_AGENT 4U
#define MWR_KIND_MODEL 5U
#define MWR_KIND_DEPLOYMENT 6U
#define MWR_KIND_NETWORK 7U

#define MWR_DRIFT_NONE 0U
#define MWR_DRIFT_MISSING 1U
#define MWR_DRIFT_UNEXPECTED 2U
#define MWR_DRIFT_CHANGED 3U
#define MWR_DRIFT_STALE 4U
#define MWR_DRIFT_UNCERTAIN 5U

#define MWR_SEVERITY_INFO 0U
#define MWR_SEVERITY_LOW 1U
#define MWR_SEVERITY_MEDIUM 2U
#define MWR_SEVERITY_HIGH 3U
#define MWR_SEVERITY_CRITICAL 4U

#define MWR_FLAG_MEASURED (1U << 0)
#define MWR_FLAG_PROVIDER_EVIDENCE (1U << 1)
#define MWR_FLAG_MODEL_PROPOSED (1U << 2)
#define MWR_FLAG_AUTHORIZED (1U << 3)
#define MWR_FLAG_FRESH (1U << 4)
#define MWR_FLAG_REMEDIATION_PROPOSAL (1U << 5)

enum mwr_status {
	MWR_OK = 0,
	MWR_ERR_ARGUMENT = -1,
	MWR_ERR_FULL = -2,
	MWR_ERR_REPLAY = -3,
	MWR_ERR_POLICY = -4,
	MWR_ERR_CORRUPT = -5,
	MWR_ERR_STALE = -6,
	MWR_ERR_GENERATION = -7,
	MWR_ERR_SEQUENCE_GAP = -8,
	MWR_ERR_NO_DRIFT = -9,
	MWR_ERR_NOT_FOUND = -10
};

struct mwr_item {
	uint64_t item_id;
	uint64_t entity_hash;
	uint64_t property_hash;
	uint64_t value_hash;
	uint64_t observed_at_ns;
	uint64_t freshness_ttl_ns;
	uint32_t kind;
	uint32_t flags;
	uint32_t confidence_ppm;
	uint32_t severity_hint;
	uint8_t value_digest[MWR_DIGEST_SIZE];
};

struct mwr_snapshot {
	uint64_t snapshot_sequence;
	uint64_t world_generation;
	uint64_t captured_at_ns;
	uint32_t item_count;
	uint32_t provider_kind;
	uint32_t flags;
	uint8_t snapshot_digest[MWR_DIGEST_SIZE];
	struct mwr_item items[MWR_MAX_ITEMS];
};

struct mwr_policy {
	uint32_t minimum_observation_confidence_ppm;
	uint64_t stale_after_ns;
	uint32_t require_measured_observation;
	uint32_t reject_model_only_observation;
	uint32_t sequence_gap_is_critical;
	uint32_t allow_empty_expected;
};

struct mwr_request {
	uint64_t request_sequence;
	uint64_t expected_generation;
	uint64_t observed_generation;
	uint64_t previous_observed_sequence;
	uint64_t now_ns;
	uint8_t expected_digest[MWR_DIGEST_SIZE];
	uint8_t observed_digest[MWR_DIGEST_SIZE];
};

struct mwr_drift {
	uint64_t entity_hash;
	uint64_t property_hash;
	uint64_t expected_value_hash;
	uint64_t observed_value_hash;
	uint32_t kind;
	uint32_t type;
	uint32_t severity;
	uint32_t confidence_ppm;
	uint32_t source_flags;
};

struct mwr_receipt {
	uint64_t request_sequence;
	uint64_t expected_generation;
	uint64_t observed_generation;
	uint64_t receipt_sequence;
	uint32_t drift_count;
	uint32_t max_severity;
	uint32_t confidence_ppm;
	uint32_t state;
	uint8_t digest[MWR_DIGEST_SIZE];
	struct mwr_drift drifts[MWR_MAX_ITEMS];
};

#define MWR_STATE_IN_SYNC 0U
#define MWR_STATE_DRIFT 1U
#define MWR_STATE_UNCERTAIN 2U
#define MWR_STATE_REJECTED 3U

struct mwr_service {
	struct mwr_policy policy;
	struct mwr_receipt receipts[MWR_MAX_RECEIPTS];
	size_t receipt_count;
	uint64_t next_receipt_sequence;
	uint64_t last_request_sequence;
};

int mwr_init(struct mwr_service *service, const struct mwr_policy *policy);
int mwr_digest_snapshot(const struct mwr_snapshot *snapshot,
			uint8_t digest[MWR_DIGEST_SIZE]);
int mwr_reconcile(struct mwr_service *service, const struct mwr_request *request,
			 const struct mwr_snapshot *expected,
			 const struct mwr_snapshot *observed,
			 struct mwr_receipt *out);
int mwr_verify(const struct mwr_service *service, const struct mwr_request *request,
	      const struct mwr_receipt *receipt);
int mwr_propose_only(const struct mwr_receipt *receipt,
			uint32_t action_kind, uint32_t proposer_flags);

#endif
