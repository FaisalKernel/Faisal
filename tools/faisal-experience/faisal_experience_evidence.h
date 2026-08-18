#ifndef FAISAL_EXPERIENCE_EVIDENCE_H
#define FAISAL_EXPERIENCE_EVIDENCE_H

#include <stddef.h>
#include <stdint.h>

#define FEE_ABI_VERSION 1U
#define FEE_DIGEST_SIZE 32U
#define FEE_MAX_RECORDS 64U
#define FEE_MAX_KEY 128U
#define FEE_MAX_TEXT 768U
#define FEE_MAX_SKILL 256U
#define FEE_MAX_SOURCE 128U
#define FEE_MAX_PROVIDER 128U
#define FEE_MAX_MODEL 128U
#define FEE_MAX_TOOL 128U
#define FEE_MAX_SANDBOX 128U
#define FEE_MAX_VERIFIER 128U
#define FEE_MAX_REUSE 4096U
#define FEE_SCORE_MAX 1000000U

#define FEE_VERIFICATION_UNVERIFIED 0U
#define FEE_VERIFICATION_VERIFIED 1U
#define FEE_VERIFICATION_REJECTED 2U

#define FEE_PROVENANCE_SOURCE (1U << 0)
#define FEE_PROVENANCE_PROVIDER (1U << 1)
#define FEE_PROVENANCE_MODEL (1U << 2)
#define FEE_PROVENANCE_TOOL (1U << 3)
#define FEE_PROVENANCE_SANDBOX (1U << 4)
#define FEE_PROVENANCE_VERIFIER (1U << 5)
#define FEE_PROVENANCE_ALL ((1U << 6) - 1U)

enum fee_state {
	FEE_STATE_RECORDED = 1,
	FEE_STATE_REUSABLE = 2,
	FEE_STATE_SUPERSEDED = 3,
	FEE_STATE_CONFLICT = 4,
	FEE_STATE_EXPIRED = 5,
	FEE_STATE_REJECTED = 6,
};

enum fee_status {
	FEE_OK = 0,
	FEE_ERR_ARGUMENT = -1,
	FEE_ERR_FULL = -2,
	FEE_ERR_CORRUPT = -3,
	FEE_ERR_CONFLICT = -4,
	FEE_ERR_STALE = -5,
	FEE_ERR_POLICY = -6,
	FEE_ERR_REPLAY = -7,
	FEE_ERR_NOT_FOUND = -8,
	FEE_ERR_EXPIRED = -9,
};

struct fee_provenance {
	uint32_t present_mask;
	uint32_t reserved;
	uint64_t source_sequence;
	uint64_t provider_generation;
	uint64_t sandbox_generation;
	uint64_t verifier_sequence;
	uint64_t observed_at_ns;
	uint64_t expires_at_ns;
	char source[FEE_MAX_SOURCE];
	char provider[FEE_MAX_PROVIDER];
	char model[FEE_MAX_MODEL];
	char tool[FEE_MAX_TOOL];
	char sandbox[FEE_MAX_SANDBOX];
	char verifier[FEE_MAX_VERIFIER];
};

struct fee_input {
	uint64_t request_sequence;
	uint64_t supersedes_sequence;
	uint32_t verification_status;
	uint32_t authority_grant;
	uint32_t confidence_ppm;
	uint32_t impact_ppm;
	uint32_t novelty_ppm;
	uint32_t recurrence_ppm;
	uint64_t now_ns;
	struct fee_provenance provenance;
	char key[FEE_MAX_KEY];
	char action[FEE_MAX_TEXT];
	char observation[FEE_MAX_TEXT];
	char result[FEE_MAX_TEXT];
	char lesson[FEE_MAX_TEXT];
	char skill[FEE_MAX_SKILL];
};

struct fee_record {
	uint64_t sequence;
	uint64_t request_sequence;
	uint64_t supersedes_sequence;
	uint64_t reuse_count;
	uint32_t state;
	uint32_t verification_status;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint64_t created_at_ns;
	uint64_t last_reused_at_ns;
	struct fee_provenance provenance;
	uint8_t action_digest[FEE_DIGEST_SIZE];
	uint8_t observation_digest[FEE_DIGEST_SIZE];
	uint8_t result_digest[FEE_DIGEST_SIZE];
	uint8_t lesson_digest[FEE_DIGEST_SIZE];
	uint8_t skill_digest[FEE_DIGEST_SIZE];
	uint8_t binding_digest[FEE_DIGEST_SIZE];
	char key[FEE_MAX_KEY];
	char action[FEE_MAX_TEXT];
	char observation[FEE_MAX_TEXT];
	char result[FEE_MAX_TEXT];
	char lesson[FEE_MAX_TEXT];
	char skill[FEE_MAX_SKILL];
};

struct fee_policy {
	uint32_t required_provenance_mask;
	uint32_t minimum_confidence_ppm;
	uint32_t minimum_importance_ppm;
	uint32_t allow_simulation;
	uint32_t reserved;
};

struct fee_stats {
	uint32_t recorded;
	uint32_t reusable;
	uint32_t superseded;
	uint32_t conflicts;
	uint32_t expired;
	uint32_t rejected;
	uint32_t verified;
	uint32_t provenance_complete;
};

struct fee_service {
	uint64_t next_sequence;
	uint64_t last_request_sequence;
	struct fee_policy policy;
	struct fee_record records[FEE_MAX_RECORDS];
	uint32_t count;
};

void fee_init(struct fee_service *service, const struct fee_policy *policy);
int fee_record(struct fee_service *service, const struct fee_input *input,
	       struct fee_record *out);
int fee_verify(const struct fee_service *service, const struct fee_record *record);
int fee_retrieve(const struct fee_service *service, const char *key,
		 uint64_t now_ns, struct fee_record *out);
int fee_reuse(struct fee_service *service, uint64_t sequence, uint64_t now_ns,
	      struct fee_record *out);
int fee_correct(struct fee_service *service, uint64_t sequence,
		const struct fee_input *correction, struct fee_record *out);
int fee_expire(struct fee_service *service, uint64_t now_ns,
	       uint32_t *expired_count);
int fee_stats_get(const struct fee_service *service, uint64_t now_ns,
		 struct fee_stats *out);

#endif
