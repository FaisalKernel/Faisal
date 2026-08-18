#ifndef FAISAL_EVOLUTION_H
#define FAISAL_EVOLUTION_H

#include <stddef.h>
#include <stdint.h>

#define FEV_ABI_VERSION 1U
#define FEV_DIGEST_SIZE 32U
#define FEV_MAX_CANDIDATES 64U
#define FEV_MAX_HEAD 41U
#define FEV_MAX_TAG 96U
#define FEV_MAX_REASON 192U
#define FEV_JOURNAL_MAGIC 0x46455631U
#define FEV_JOURNAL_VERSION 1U
#define FEV_FLAG_MODEL_PROPOSAL (1U << 0)
#define FEV_FLAG_EXPERIMENTAL (1U << 1)
#define FEV_FLAG_EXTERNAL_EFFECTS (1U << 2)
#define FEV_FLAGS_ALL (FEV_FLAG_MODEL_PROPOSAL | FEV_FLAG_EXPERIMENTAL | FEV_FLAG_EXTERNAL_EFFECTS)
#define FEV_METRIC_LOWER_BETTER 0U
#define FEV_METRIC_HIGHER_BETTER 1U

enum fev_state {
	FEV_STATE_DRAFT = 1,
	FEV_STATE_ISOLATED = 2,
	FEV_STATE_VALIDATED = 3,
	FEV_STATE_PROMOTED = 4,
	FEV_STATE_ROLLED_BACK = 5,
	FEV_STATE_REJECTED = 6
};

enum fev_status {
	FEV_OK = 0,
	FEV_ERR_ARGUMENT = -1,
	FEV_ERR_IO = -2,
	FEV_ERR_FULL = -3,
	FEV_ERR_NOT_FOUND = -4,
	FEV_ERR_STATE = -5,
	FEV_ERR_POLICY = -6,
	FEV_ERR_TAMPER = -7,
	FEV_ERR_REPLAY = -8,
	FEV_ERR_CONFLICT = -9,
	FEV_ERR_OVERFLOW = -10
};

struct fev_policy {
	uint32_t min_improvement_ppm;
	uint32_t max_regression_ppm;
	uint32_t require_reproducible;
	uint32_t require_rollback;
	uint32_t require_research;
	uint32_t require_external_approval;
	uint32_t reserved[2];
};

struct fev_candidate {
	uint64_t candidate_id;
	uint64_t generation;
	uint32_t state;
	uint32_t flags;
	uint32_t metric_kind;
	uint32_t validation_passed;
	uint32_t reproducible;
	uint32_t reserved;
	uint64_t baseline_metric;
	uint64_t candidate_metric;
	uint64_t improvement_ppm;
	uint64_t regression_ppm;
	uint64_t validation_sequence;
	char source_head[FEV_MAX_HEAD];
	char parent_head[FEV_MAX_HEAD];
	char rollback_tag[FEV_MAX_TAG];
	uint8_t research_digest[FEV_DIGEST_SIZE];
	uint8_t baseline_digest[FEV_DIGEST_SIZE];
	uint8_t candidate_digest[FEV_DIGEST_SIZE];
	uint8_t evidence_digest[FEV_DIGEST_SIZE];
	uint8_t approval_digest[FEV_DIGEST_SIZE];
	uint8_t rollback_reason_digest[FEV_DIGEST_SIZE];
	struct fev_policy policy;
	char reason[FEV_MAX_REASON];
};

struct fev_receipt {
	uint64_t journal_sequence;
	uint64_t candidate_id;
	uint32_t state;
	uint32_t reserved;
	uint8_t candidate_digest[FEV_DIGEST_SIZE];
	uint8_t receipt_digest[FEV_DIGEST_SIZE];
};

struct fev_disk_record;
struct fev_service {
	int journal_fd;
	uint64_t next_sequence;
	uint8_t last_digest[FEV_DIGEST_SIZE];
	size_t count;
	struct fev_candidate candidates[FEV_MAX_CANDIDATES];
};

int fev_open(struct fev_service *service, const char *path);
void fev_close(struct fev_service *service);
int fev_propose(struct fev_service *service, uint64_t candidate_id,
		uint64_t generation, uint32_t flags, uint32_t metric_kind,
		uint64_t baseline_metric, const char *source_head,
		const char *parent_head, const char *rollback_tag,
		const uint8_t research_digest[FEV_DIGEST_SIZE],
		const uint8_t baseline_digest[FEV_DIGEST_SIZE],
		const uint8_t candidate_digest[FEV_DIGEST_SIZE],
		const struct fev_policy *policy, struct fev_candidate *out);
int fev_isolate(struct fev_service *service, uint64_t candidate_id,
		struct fev_candidate *out);
int fev_record_validation(struct fev_service *service, uint64_t candidate_id,
		uint32_t validation_passed, uint32_t reproducible,
		uint64_t candidate_metric, const uint8_t evidence_digest[FEV_DIGEST_SIZE],
		const uint8_t approval_digest[FEV_DIGEST_SIZE],
		struct fev_candidate *out);
int fev_promote(struct fev_service *service, uint64_t candidate_id,
		struct fev_candidate *out, struct fev_receipt *receipt);
int fev_rollback(struct fev_service *service, uint64_t candidate_id,
		const uint8_t reason_digest[FEV_DIGEST_SIZE],
		struct fev_candidate *out, struct fev_receipt *receipt);
int fev_query(const struct fev_service *service, uint64_t candidate_id,
	      struct fev_candidate *out);
int fev_verify_candidate(const struct fev_candidate *candidate);
int fev_verify_receipt(const struct fev_receipt *receipt);

#endif
