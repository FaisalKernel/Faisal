#ifndef FAISAL_TASK_SERVICE_H
#define FAISAL_TASK_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>

#define FTS_MAX_TASKS 128U
#define FTS_MAX_DEPENDENCIES 8U
#define FTS_MAX_IDEMPOTENCY 96U
#define FTS_MAX_OBJECTIVE 256U
#define FTS_MAX_RESULT 256U
#define FTS_MAX_FAILURE 256U
#define FTS_MAX_JOURNAL_PATH 4096U
#define FTS_DIGEST_SIZE 32U
#define FTS_JOURNAL_MAGIC 0x46545331U
#define FTS_JOURNAL_VERSION 1U
#define FTS_MAX_RETRIES 16U
#define FTS_DEFAULT_LEASE_NS (30ULL * 1000000000ULL)
#define FTS_MAX_LEASE_NS (7ULL * 24ULL * 60ULL * 60ULL * 1000000000ULL)
#define FTS_MAX_BACKOFF_NS (24ULL * 60ULL * 60ULL * 1000000000ULL)
#define FTS_MAX_BRANCHES 64U
#define FTS_MAX_EVIDENCE 8U
#define FTS_MAX_CONTINUITY 64U
#define FTS_MAX_ACTION 256U
#define FTS_MAX_EVIDENCE_DETAIL 128U
#define FTS_CAUSAL_JOURNAL_MAGIC 0x46434131U
#define FTS_CAUSAL_JOURNAL_VERSION 1U
#define FTS_CONTINUITY_JOURNAL_MAGIC 0x46434331U
#define FTS_CONTINUITY_JOURNAL_VERSION 1U

/* Task state is persisted; numeric values are part of the journal contract. */
enum fts_task_state {
	FTS_TASK_READY = 1,
	FTS_TASK_LEASED = 2,
	FTS_TASK_RUNNING = 3,
	FTS_TASK_RETRY_WAIT = 4,
	FTS_TASK_SUCCEEDED = 5,
	FTS_TASK_FAILED = 6,
	FTS_TASK_CANCELLED = 7,
	FTS_TASK_DEAD_LETTER = 8
};

enum fts_failure_class {
	FTS_FAILURE_NONE = 0,
	FTS_FAILURE_TRANSIENT = 1,
	FTS_FAILURE_SYSTEMIC = 2,
	FTS_FAILURE_MODEL = 3,
	FTS_FAILURE_TOOL = 4,
	FTS_FAILURE_DATA = 5,
	FTS_FAILURE_SECURITY = 6,
	FTS_FAILURE_POLICY = 7,
	FTS_FAILURE_PLANNING = 8,
	FTS_FAILURE_EXECUTION = 9,
	FTS_FAILURE_HUMAN_DEPENDENCY = 10,
	FTS_FAILURE_ECONOMIC = 11
};

enum fts_stop_reason {
	FTS_STOP_NONE = 0,
	FTS_STOP_SUCCESS = 1,
	FTS_STOP_IMPOSSIBLE = 2,
	FTS_STOP_BUDGET = 3,
	FTS_STOP_DEADLINE = 4,
	FTS_STOP_POLICY = 5,
	FTS_STOP_RISK = 6,
	FTS_STOP_DEPENDENCY = 7,
	FTS_STOP_NEGATIVE_VALUE = 8,
	FTS_STOP_CANCELLED = 9
};

enum fts_branch_state {
	FTS_BRANCH_PROPOSED = 1,
	FTS_BRANCH_PREPARED = 2,
	FTS_BRANCH_COMMITTED = 3,
	FTS_BRANCH_REJECTED = 4,
	FTS_BRANCH_INVALIDATED = 5
};

enum fts_evidence_kind {
	FTS_EVIDENCE_OBSERVATION = 1,
	FTS_EVIDENCE_RESULT = 2,
	FTS_EVIDENCE_VERIFICATION = 3,
	FTS_EVIDENCE_RESOURCE = 4,
	FTS_EVIDENCE_PROVENANCE = 5
};

enum fts_continuity_state {
	FTS_CONTINUITY_SEALED = 1,
	FTS_CONTINUITY_INVALIDATED = 2
};

enum fts_status {
	FTS_OK = 0,
	FTS_ERR_ARGUMENT = -1,
	FTS_ERR_IO = -2,
	FTS_ERR_CORRUPT = -3,
	FTS_ERR_FULL = -4,
	FTS_ERR_NOT_FOUND = -5,
	FTS_ERR_CONFLICT = -6,
	FTS_ERR_STATE = -7,
	FTS_ERR_DEPENDENCY = -8,
	FTS_ERR_LEASE = -9,
	FTS_ERR_POLICY = -10,
	FTS_ERR_DEADLINE = -11,
	FTS_ERR_BUDGET = -12,
	FTS_ERR_STOPPED = -13,
	FTS_ERR_KERNEL = -14,
	FTS_ERR_STALE = -15,
	FTS_ERR_INCOMPLETE = -16,
	FTS_ERR_REVOKED = -17
};

struct fts_task {
	uint64_t task_id;
	uint64_t goal_id;
	uint64_t parent_task_id;
	uint64_t sequence;
	uint64_t owner_agent_id;
	uint64_t owner_capability;
	uint64_t required_intent_lease;
	uint64_t created_at_ns;
	uint64_t updated_at_ns;
	uint64_t deadline_ns;
	uint64_t lease_until_ns;
	uint64_t next_attempt_ns;
	uint64_t cpu_budget_ns;
	uint64_t money_budget_micro;
	uint64_t consumed_cpu_ns;
	uint64_t consumed_money_micro;
	uint64_t idempotency_hash;
	uint64_t lease_generation;
	uint32_t state;
	uint32_t retry_count;
	uint32_t max_retries;
	uint32_t failure_class;
	uint32_t stop_reason;
	uint32_t dependency_count;
	uint32_t completed_dependencies;
	uint32_t priority;
	uint32_t risk_class;
	uint32_t dependency_ids[FTS_MAX_DEPENDENCIES];
	uint8_t objective_digest[FTS_DIGEST_SIZE];
	char idempotency_key[FTS_MAX_IDEMPOTENCY];
	char objective[FTS_MAX_OBJECTIVE];
	char result[FTS_MAX_RESULT];
	char failure[FTS_MAX_FAILURE];
};

struct fts_evidence {
	uint32_t kind;
	uint32_t verified;
	uint64_t sequence;
	uint8_t digest[FTS_DIGEST_SIZE];
	char detail[FTS_MAX_EVIDENCE_DETAIL];
};

struct fts_authority_ref {
	uint64_t lease_id;
	uint64_t grant_id;
	uint64_t grant_capability;
	uint64_t agent_id;
	uint64_t agent_capability;
	uint64_t lineage_id;
	uint64_t scope_id;
	uint64_t generation;
	uint32_t flags;
	uint32_t operation_class;
	uint32_t resource_mask;
	uint32_t reserved;
	uint8_t intent_digest[FTS_DIGEST_SIZE];
};

struct fts_branch {
	uint64_t branch_id;
	uint64_t task_id;
	uint64_t objective_generation;
	uint64_t observation_generation;
	struct fts_authority_ref authority;
	uint64_t resource_admission;
	uint64_t causal_sequence;
	uint64_t prepared_at_ns;
	uint64_t committed_at_ns;
	uint32_t required_operation;
	uint32_t resource_mask;
	uint32_t state;
	uint32_t evidence_count;
	uint32_t evidence_required;
	uint32_t evidence_verified;
	uint32_t rejection_reason;
	uint8_t action_digest[FTS_DIGEST_SIZE];
	uint8_t observation_digest[FTS_DIGEST_SIZE];
	uint8_t branch_digest[FTS_DIGEST_SIZE];
	char action[FTS_MAX_ACTION];
	struct fts_evidence evidence[FTS_MAX_EVIDENCE];
};

struct fts_continuity {
	uint64_t capsule_id;
	uint64_t branch_id;
	uint64_t task_id;
	uint64_t objective_generation;
	uint64_t causal_sequence;
	uint64_t created_at_ns;
	uint64_t invalidated_at_ns;
	uint32_t state;
	uint32_t invalidation_reason;
	uint8_t working_state_digest[FTS_DIGEST_SIZE];
	uint8_t world_state_digest[FTS_DIGEST_SIZE];
	uint8_t resource_state_digest[FTS_DIGEST_SIZE];
	uint8_t branch_digest[FTS_DIGEST_SIZE];
	uint8_t capsule_digest[FTS_DIGEST_SIZE];
};

struct fts_service {
	int kernel_fd;
	int journal_fd;
	int causal_fd;
	int continuity_fd;
	int require_kernel;
	uint64_t session_id;
	uint64_t agent_id;
	uint64_t agent_capability;
	uint64_t next_task_id;
	uint64_t next_sequence;
	uint64_t journal_sequence;
	uint64_t causal_sequence;
	uint64_t continuity_sequence;
	uint64_t next_branch_id;
	uint64_t next_capsule_id;
	char journal_path[FTS_MAX_JOURNAL_PATH];
	char causal_journal_path[FTS_MAX_JOURNAL_PATH];
	char continuity_journal_path[FTS_MAX_JOURNAL_PATH];
	struct fts_task tasks[FTS_MAX_TASKS];
	size_t task_count;
	struct fts_branch branches[FTS_MAX_BRANCHES];
	size_t branch_count;
	struct fts_continuity capsules[FTS_MAX_CONTINUITY];
	size_t capsule_count;
	pthread_mutex_t lock;
	int lock_initialized;
};

int fts_open(struct fts_service *service, const char *journal_path,
	     int require_kernel);
void fts_close(struct fts_service *service);
int fts_replay(struct fts_service *service);
int fts_submit(struct fts_service *service, uint64_t goal_id,
	       const char *idempotency_key, const char *objective,
	       uint64_t deadline_ns, uint64_t cpu_budget_ns,
	       uint64_t money_budget_micro, uint32_t priority,
	       uint32_t risk_class, uint32_t max_retries,
	       const uint32_t *dependency_ids, uint32_t dependency_count,
	       struct fts_task *out);
int fts_claim(struct fts_service *service, uint64_t task_id,
	      uint64_t now_ns, uint64_t lease_ns, struct fts_task *out);
int fts_heartbeat(struct fts_service *service, uint64_t task_id,
			  uint64_t lease_generation, uint64_t now_ns,
			  uint64_t extend_ns, struct fts_task *out);
int fts_handoff(struct fts_service *service, uint64_t task_id,
			uint64_t lease_generation, uint64_t new_owner_agent_id,
			uint64_t now_ns, uint64_t lease_ns, struct fts_task *out);

int fts_complete(struct fts_service *service, uint64_t task_id,
		 uint64_t lease_generation, uint64_t now_ns,
		 const char *result, uint64_t cpu_used_ns,
		 uint64_t money_used_micro, struct fts_task *out);
int fts_fail(struct fts_service *service, uint64_t task_id,
	    uint64_t lease_generation, uint64_t now_ns,
	    uint32_t failure_class, const char *failure,
	    int retryable, struct fts_task *out);
int fts_cancel(struct fts_service *service, uint64_t task_id,
	       uint32_t stop_reason, struct fts_task *out);
int fts_query(const struct fts_service *service, uint64_t task_id,
	      struct fts_task *out);
int fts_recover_expired(struct fts_service *service, uint64_t now_ns,
			uint32_t *recovered, uint32_t *dead_lettered);
int fts_test_corrupt_tail(const struct fts_service *service);
int fts_branch_propose(struct fts_service *service, uint64_t task_id,
		       const struct fts_authority_ref *authority,
		       uint32_t required_operation, uint32_t resource_mask,
		       uint64_t resource_admission,
		       const uint8_t action_digest[FTS_DIGEST_SIZE],
		       const uint8_t observation_digest[FTS_DIGEST_SIZE],
		       const char *action, struct fts_branch *out);
int fts_branch_add_evidence(struct fts_service *service, uint64_t branch_id,
			    uint32_t kind, const uint8_t digest[FTS_DIGEST_SIZE],
			    uint32_t verified, const char *detail, struct fts_branch *out);
int fts_branch_prepare(struct fts_service *service, uint64_t branch_id,
			   uint64_t now_ns, struct fts_branch *out);
int fts_branch_commit(struct fts_service *service, uint64_t branch_id,
			  uint64_t now_ns, struct fts_branch *out);
int fts_branch_invalidate(struct fts_service *service, uint64_t branch_id,
			      uint32_t reason, struct fts_branch *out);
int fts_branch_query(const struct fts_service *service, uint64_t branch_id,
			struct fts_branch *out);
int fts_test_causal_corrupt_tail(const struct fts_service *service);
int fts_continuity_seal(struct fts_service *service, uint64_t branch_id,
			uint64_t now_ns,
			const uint8_t working_state_digest[FTS_DIGEST_SIZE],
			const uint8_t world_state_digest[FTS_DIGEST_SIZE],
			const uint8_t resource_state_digest[FTS_DIGEST_SIZE],
			struct fts_continuity *out);
int fts_continuity_check(struct fts_service *service, uint64_t capsule_id,
			const uint8_t working_state_digest[FTS_DIGEST_SIZE],
			const uint8_t world_state_digest[FTS_DIGEST_SIZE],
			const uint8_t resource_state_digest[FTS_DIGEST_SIZE],
			struct fts_continuity *out);
int fts_continuity_invalidate(struct fts_service *service, uint64_t capsule_id,
			uint64_t now_ns, uint32_t reason, struct fts_continuity *out);
int fts_continuity_query(const struct fts_service *service, uint64_t capsule_id,
			struct fts_continuity *out);
int fts_test_continuity_corrupt_tail(const struct fts_service *service);

#endif
