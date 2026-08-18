#ifndef FAISAL_BROWSER_VERIFY_H
#define FAISAL_BROWSER_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define BIV_DIGEST_SIZE 32U
#define BIV_MAX_ACTIONS 128U
#define BIV_MAX_ATTRIBUTE 96U
#define BIV_PPM_SCALE 1000000U

#define BIV_FLAG_SEMANTIC (1U << 0)
#define BIV_FLAG_COORDINATE_FALLBACK (1U << 1)
#define BIV_FLAG_MODEL_PROPOSAL (1U << 2)
#define BIV_FLAG_OPERATOR_CONFIRMED (1U << 3)
#define BIV_FLAG_DOM_OBSERVED (1U << 4)
#define BIV_FLAG_A11Y_OBSERVED (1U << 5)
#define BIV_FLAG_SCREENSHOT_OBSERVED (1U << 6)
#define BIV_FLAG_ARTIFACT_EXPECTED (1U << 7)

#define BIV_LOCATOR_ROLE 1U
#define BIV_LOCATOR_LABEL 2U
#define BIV_LOCATOR_TEXT 3U
#define BIV_LOCATOR_PLACEHOLDER 4U
#define BIV_LOCATOR_ALT_TEXT 5U
#define BIV_LOCATOR_TITLE 6U
#define BIV_LOCATOR_TEST_ID 7U
#define BIV_LOCATOR_CSS 8U
#define BIV_LOCATOR_XPATH 9U
#define BIV_LOCATOR_COORDINATE 10U

#define BIV_ACTION_NAVIGATE 1U
#define BIV_ACTION_CLICK 2U
#define BIV_ACTION_TYPE 3U
#define BIV_ACTION_SCROLL 4U
#define BIV_ACTION_DOM_INSPECT 5U
#define BIV_ACTION_A11Y_INSPECT 6U
#define BIV_ACTION_SCREENSHOT 7U
#define BIV_ACTION_DOWNLOAD 8U
#define BIV_ACTION_UPLOAD 9U
#define BIV_ACTION_VERIFY 10U

enum biv_status {
	BIV_OK = 0,
	BIV_ERR_ARGUMENT = -1,
	BIV_ERR_POLICY = -2,
	BIV_ERR_STALE = -3,
	BIV_ERR_AMBIGUOUS = -4,
	BIV_ERR_REPLAY = -5,
	BIV_ERR_TAMPER = -6,
	BIV_ERR_NOT_FOUND = -7,
	BIV_ERR_AUTHORITY = -8,
	BIV_ERR_CONFLICT = -9,
	BIV_ERR_ARTIFACT = -10
};

enum biv_decision {
	BIV_DECISION_DENIED = 0,
	BIV_DECISION_ADMITTED = 1,
	BIV_DECISION_COMMITTED = 2,
	BIV_DECISION_STALE = 3,
	BIV_DECISION_AMBIGUOUS = 4,
	BIV_DECISION_TAMPERED = 5
};

struct biv_policy {
	uint64_t session_generation;
	uint64_t page_generation;
	uint64_t current_time_ns;
	uint64_t max_observation_age_ns;
	uint32_t minimum_semantic_confidence_ppm;
	uint32_t require_unique_locator;
	uint32_t allow_coordinate_fallback;
	uint32_t require_artifact_digest;
	uint32_t max_actions;
};

struct biv_locator_evidence {
	uint32_t locator_kind;
	uint32_t match_count;
	uint32_t confidence_ppm;
	uint32_t semantic_score_ppm;
	uint8_t locator_digest[BIV_DIGEST_SIZE];
	uint8_t accessible_name_digest[BIV_DIGEST_SIZE];
};

struct biv_observation {
	uint64_t page_id;
	uint64_t frame_id;
	uint64_t observed_at_ns;
	uint8_t origin_digest[BIV_DIGEST_SIZE];
	uint8_t url_digest[BIV_DIGEST_SIZE];
	uint8_t dom_digest[BIV_DIGEST_SIZE];
	uint8_t a11y_digest[BIV_DIGEST_SIZE];
	uint8_t screenshot_digest[BIV_DIGEST_SIZE];
};

struct biv_action_request {
	uint64_t action_sequence;
	uint64_t session_generation;
	uint64_t page_generation;
	uint64_t provider_sequence;
	uint64_t page_id;
	uint32_t action_kind;
	uint32_t flags;
	uint32_t operator_confirmed;
	uint32_t reserved;
	struct biv_locator_evidence locator;
	struct biv_observation pre_observation;
	uint8_t input_digest[BIV_DIGEST_SIZE];
	uint8_t expected_post_digest[BIV_DIGEST_SIZE];
	uint8_t expected_artifact_digest[BIV_DIGEST_SIZE];
	char attribute[BIV_MAX_ATTRIBUTE];
};

struct biv_receipt {
	uint32_t decision;
	int32_t status;
	uint64_t action_sequence;
	uint64_t session_generation;
	uint64_t page_generation;
	uint64_t action_id;
	struct biv_observation post_observation;
	uint8_t artifact_digest[BIV_DIGEST_SIZE];
	uint8_t request_digest[BIV_DIGEST_SIZE];
	uint8_t receipt_digest[BIV_DIGEST_SIZE];
};

struct biv_service {
	struct biv_policy policy;
	struct biv_receipt receipts[BIV_MAX_ACTIONS];
	size_t receipt_count;
	uint64_t last_action_sequence;
	uint64_t next_action_id;
};

int biv_init(struct biv_service *service, const struct biv_policy *policy);
int biv_admit(struct biv_service *service,
	      const struct biv_action_request *request,
	      struct biv_receipt *out);
int biv_commit(struct biv_service *service,
	       const struct biv_action_request *request,
	       const struct biv_observation *post_observation,
	       const uint8_t artifact_digest[BIV_DIGEST_SIZE],
	       struct biv_receipt *out);
int biv_verify_receipt(const struct biv_service *service,
		       const struct biv_receipt *receipt);
int biv_query_receipt(const struct biv_service *service,
		      uint64_t action_sequence,
		      struct biv_receipt *out);
int biv_authority_check(const struct biv_action_request *request);

#endif
