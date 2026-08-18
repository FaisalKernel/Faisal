#ifndef FAISAL_RECOVERY_DECISION_H
#define FAISAL_RECOVERY_DECISION_H

#include <stddef.h>
#include <stdint.h>

#define FRD_MAX_DECISIONS 128U
#define FRD_MAX_REASON 192U
#define FRD_DIGEST_SIZE 32U
#define FRD_MAX_BACKOFF_NS (300ULL * 1000000000ULL)
#define FRD_SCORE_MAX 1000000U

#define FRD_FLAG_TRACE_BOUND       (1U << 0)
#define FRD_FLAG_GENERATION_BOUND  (1U << 1)
#define FRD_FLAG_OBSERVATION       (1U << 2)
#define FRD_FLAG_DIAGNOSIS         (1U << 3)
#define FRD_FLAG_CANDIDATE         (1U << 4)
#define FRD_FLAG_CHECKPOINT        (1U << 5)
#define FRD_FLAG_AUTHORITY         (1U << 6)
#define FRD_FLAG_COMPENSATION      (1U << 7)
#define FRD_FLAG_IDEMPOTENT        (1U << 8)
#define FRD_FLAG_CANARY_PASSED     (1U << 9)
#define FRD_FLAG_IRREVERSIBLE     (1U << 10)
#define FRD_FLAG_MODEL_PROPOSAL    (1U << 11)

#define FRD_ACTION_RETRY       (1U << 0)
#define FRD_ACTION_REROUTE     (1U << 1)
#define FRD_ACTION_REPLAN      (1U << 2)
#define FRD_ACTION_COMPENSATE  (1U << 3)
#define FRD_ACTION_ROLLBACK    (1U << 4)
#define FRD_ACTION_QUARANTINE (1U << 5)
#define FRD_ACTION_ESCALATE   (1U << 6)
#define FRD_ACTION_ALL (FRD_ACTION_RETRY | FRD_ACTION_REROUTE | \
			    FRD_ACTION_REPLAN | FRD_ACTION_COMPENSATE | \
			    FRD_ACTION_ROLLBACK | FRD_ACTION_QUARANTINE | \
			    FRD_ACTION_ESCALATE)

enum frd_status {
	FRD_OK = 0,
	FRD_ERR_ARGUMENT = -1,
	FRD_ERR_FULL = -2,
	FRD_ERR_REPLAY = -3,
	FRD_ERR_POLICY = -4,
	FRD_ERR_CORRUPT = -5,
	FRD_ERR_STALE = -6,
	FRD_ERR_DEADLINE = -7,
	FRD_ERR_RETRY_LIMIT = -8,
	FRD_ERR_AUTHORITY = -9,
	FRD_ERR_NOT_FOUND = -10
};

enum frd_decision_status {
	FRD_DECISION_ACCEPTED = 1,
	FRD_DECISION_REFUSED = 2
};

struct frd_input {
	uint64_t request_sequence;
	uint64_t now_ns;
	uint64_t objective_id;
	uint64_t agent_id;
	uint64_t worker_id;
	uint64_t trace_id;
	uint64_t span_id;
	uint64_t parent_span_id;
	uint64_t generation;
	uint64_t action_id;
	uint64_t deadline_ns;
	uint64_t backoff_base_ns;
	uint32_t requested_action;
	uint32_t flags;
	uint32_t attempt;
	uint32_t max_attempts;
	uint32_t failure_class;
	uint32_t severity;
	uint8_t observation_digest[FRD_DIGEST_SIZE];
	uint8_t diagnosis_digest[FRD_DIGEST_SIZE];
	uint8_t candidate_digest[FRD_DIGEST_SIZE];
	uint8_t checkpoint_digest[FRD_DIGEST_SIZE];
};

struct frd_policy {
	uint32_t allowed_actions;
	uint32_t max_attempts;
	uint32_t require_operator_irreversible;
	uint32_t require_compensation_irreversible;
	uint32_t require_checkpoint_for_recovery;
	uint32_t require_canary_for_candidate;
	uint64_t max_backoff_ns;
};

struct frd_decision {
	uint64_t request_sequence;
	uint64_t decision_sequence;
	uint64_t objective_id;
	uint64_t trace_id;
	uint64_t generation;
	uint64_t action_id;
	uint64_t next_attempt_ns;
	uint32_t action;
	uint32_t status;
	uint32_t attempt;
	uint32_t retry_count;
	uint8_t receipt_digest[FRD_DIGEST_SIZE];
	char reason[FRD_MAX_REASON];
};

struct frd_service {
	struct frd_policy policy;
	struct frd_decision decisions[FRD_MAX_DECISIONS];
	size_t decision_count;
	uint64_t next_decision_sequence;
	uint64_t last_request_sequence;
};

int frd_init(struct frd_service *service, const struct frd_policy *policy);
int frd_decide(struct frd_service *service, const struct frd_input *input,
	       struct frd_decision *out);
int frd_verify(const struct frd_service *service, const struct frd_input *input,
	      const struct frd_decision *decision, uint64_t current_generation);
int frd_get(const struct frd_service *service, uint64_t decision_sequence,
	    struct frd_decision *out);

#endif
