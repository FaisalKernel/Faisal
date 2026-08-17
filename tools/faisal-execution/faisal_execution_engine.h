#ifndef FAISAL_EXECUTION_ENGINE_H
#define FAISAL_EXECUTION_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include "../faisal-task/faisal_task_service.h"

#define FEX_MAX_OBJECTIVES 16U
#define FEX_MAX_NODES 64U
#define FEX_MAX_WORKERS 16U
#define FEX_MAX_INTENT 256U
#define FEX_MAX_REASON 160U
#define FEX_MAX_RESULT FTS_MAX_RESULT
#define FEX_ENGINE_MAGIC 0x46455831U
#define FEX_ENGINE_VERSION 2U
#define FEX_DIGEST_SIZE FTS_DIGEST_SIZE
#define FEX_MAX_WORKER_RESTARTS 3U
#define FEX_HANDOFF_TOKEN_MAX_AGE_NS 1000000000ULL
#define FEX_MAX_HANDOFF_LEASE_NS (60ULL * 1000000000ULL)
#define FEX_HANDOFF_TOKEN_SIZE (sizeof(uint64_t) + FEX_DIGEST_SIZE)
#define FEX_MAX_CONSUMED_HANDOFF_TOKENS 128U

/* Persisted objective state is a replay contract, not a model claim. */
enum fex_objective_state {
	FEX_OBJECTIVE_CREATED = 1,
	FEX_OBJECTIVE_READY = 2,
	FEX_OBJECTIVE_RUNNING = 3,
	FEX_OBJECTIVE_WAITING = 4,
	FEX_OBJECTIVE_VERIFYING = 5,
	FEX_OBJECTIVE_ADAPTING = 6,
	FEX_OBJECTIVE_SUCCEEDED = 7,
	FEX_OBJECTIVE_FAILED = 8,
	FEX_OBJECTIVE_CANCELLED = 9,
	FEX_OBJECTIVE_RECOVERING = 10
};

enum fex_event_kind {
	FEX_EVENT_OBJECTIVE = 1,
	FEX_EVENT_NODE = 2,
	FEX_EVENT_CHECKPOINT = 3,
	FEX_EVENT_WORKER = 4,
	FEX_EVENT_RECOVERY = 5,
	FEX_EVENT_ADAPTATION = 6
};

enum fex_worker_health {
	FEX_WORKER_UNKNOWN = 0,
	FEX_WORKER_HEALTHY = 1,
	FEX_WORKER_TIMED_OUT = 2,
	FEX_WORKER_REASSIGNED = 3,
	FEX_WORKER_COMPLETED = 4,
	FEX_WORKER_DEAD_LETTER = 5,
	FEX_WORKER_QUARANTINED = 6
};

enum fex_status {
	FEX_OK = 0,
	FEX_ERR_ARGUMENT = -1,
	FEX_ERR_IO = -2,
	FEX_ERR_CORRUPT = -3,
	FEX_ERR_FULL = -4,
	FEX_ERR_NOT_FOUND = -5,
	FEX_ERR_STATE = -6,
	FEX_ERR_KERNEL = -7,
	FEX_ERR_AUTHORITY = -8,
	FEX_ERR_CONFLICT = -9,
	FEX_ERR_INCOMPLETE = -10,
	FEX_ERR_POLICY = -11
};

struct fex_objective {
	uint64_t objective_id;
	uint64_t generation;
	uint64_t created_at_ns;
	uint64_t updated_at_ns;
	uint64_t deadline_ns;
	uint64_t cpu_budget_ns;
	uint64_t money_budget_micro;
	uint64_t checkpoint_sequence;
	uint32_t state;
	uint32_t node_count;
	uint32_t completed_nodes;
	uint32_t failed_nodes;
	uint32_t active_workers;
	uint32_t max_workers;
	uint32_t reserved;
	uint8_t intent_digest[FEX_DIGEST_SIZE];
	uint8_t plan_digest[FEX_DIGEST_SIZE];
	uint8_t state_digest[FEX_DIGEST_SIZE];
	char intent[FEX_MAX_INTENT];
	char reason[FEX_MAX_REASON];
};

struct fex_node {
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t owner_agent_id;
	uint64_t lease_generation;
	uint64_t last_checkpoint;
	uint32_t state;
	uint32_t deterministic;
	uint32_t speculative;
	uint32_t fallback_class;
	uint8_t action_digest[FEX_DIGEST_SIZE];
	uint8_t evidence_digest[FEX_DIGEST_SIZE];
	char objective[FTS_MAX_OBJECTIVE];
	char result[FEX_MAX_RESULT];
};

struct fex_worker {
	uint64_t task_id;
	uint64_t objective_id;
	uint64_t worker_id;
	uint64_t lease_generation;
	uint64_t last_heartbeat_ns;
	uint64_t lease_deadline_ns;
	uint64_t last_transition_ns;
	uint32_t health;
	uint32_t restart_count;
	uint32_t reassignment_count;
	uint32_t handoff_count;
	uint32_t failure_class;
};

struct fex_checkpoint {
	uint64_t objective_id;
	uint64_t sequence;
	uint64_t created_at_ns;
	uint32_t node_count;
	uint32_t verified;
	uint8_t working_digest[FEX_DIGEST_SIZE];
	uint8_t world_digest[FEX_DIGEST_SIZE];
	uint8_t resource_digest[FEX_DIGEST_SIZE];
	uint8_t checkpoint_digest[FEX_DIGEST_SIZE];
};

struct fex_journal_attestation {
	uint32_t format_version;
	uint32_t consumed_handoff_token_count;
	uint64_t last_sequence;
	uint64_t record_count;
	uint8_t chain_digest[FEX_DIGEST_SIZE];
};

struct fex_service {
	struct fts_service tasks;
	int engine_fd;
	int require_kernel;
	int lock_initialized;
	uint64_t next_objective_id;
	uint64_t next_event_sequence;
	char engine_path[FTS_MAX_JOURNAL_PATH];
	struct fex_objective objectives[FEX_MAX_OBJECTIVES];
	struct fex_node nodes[FEX_MAX_NODES];
	struct fex_worker workers[FEX_MAX_WORKERS];
	uint8_t consumed_handoff_tokens[FEX_MAX_CONSUMED_HANDOFF_TOKENS][FEX_HANDOFF_TOKEN_SIZE];
	uint32_t consumed_handoff_token_count;
	uint8_t journal_chain_digest[FEX_DIGEST_SIZE];
	uint64_t journal_record_count;
	size_t objective_count;
	size_t node_count;
	size_t worker_count;
	pthread_mutex_t lock;
};

int fex_open(struct fex_service *service, const char *journal_prefix,
		     int require_kernel);
void fex_close(struct fex_service *service);
int fex_replay(struct fex_service *service);
int fex_query_journal_attestation(struct fex_service *service,
				  struct fex_journal_attestation *out);
int fex_create_objective(struct fex_service *service, const char *intent,
			 uint64_t deadline_ns, uint64_t cpu_budget_ns,
			 uint64_t money_budget_micro, uint32_t max_workers,
			 uint64_t now_ns, struct fex_objective *out);
int fex_add_node(struct fex_service *service, uint64_t objective_id,
			 const char *idempotency_key, const char *node_objective,
			 uint32_t priority, uint32_t risk_class, uint32_t max_retries,
			 const uint32_t *dependencies, uint32_t dependency_count,
			 uint32_t deterministic, uint32_t speculative,
			 struct fex_node *out);
int fex_dispatch(struct fex_service *service, uint64_t objective_id,
			 uint64_t now_ns, uint32_t lease_ns, uint32_t *claimed);
int fex_heartbeat(struct fex_service *service, uint64_t task_id,
					 uint64_t now_ns, uint64_t extend_ns);
int fex_handoff(struct fex_service *service, uint64_t task_id,
					 uint64_t new_worker_id, uint64_t now_ns, uint64_t lease_ns);
int fex_handoff_verified(struct fex_service *service, uint64_t task_id,
					 uint64_t new_worker_id, uint64_t now_ns,
					 uint64_t lease_ns,
					 const uint8_t checkpoint_digest[FEX_DIGEST_SIZE]);
int fex_make_handoff_token(const struct fex_service *service, uint64_t task_id,
					 uint64_t new_worker_id, uint64_t now_ns,
					 uint8_t token[FEX_HANDOFF_TOKEN_SIZE]);
int fex_handoff_token_verified(struct fex_service *service, uint64_t task_id,
					 uint64_t new_worker_id, uint64_t now_ns,
					 uint64_t lease_ns,
					 const uint8_t token[FEX_HANDOFF_TOKEN_SIZE]);

int fex_supervise(struct fex_service *service, uint64_t now_ns,
				 uint64_t timeout_ns, uint32_t *reassigned,
				 uint32_t *dead_lettered);
int fex_query_worker(const struct fex_service *service, uint64_t task_id,
				 struct fex_worker *out);

int fex_complete(struct fex_service *service, uint64_t task_id,
			 uint64_t now_ns, const char *result,
			 const uint8_t evidence_digest[FEX_DIGEST_SIZE]);
int fex_fail(struct fex_service *service, uint64_t task_id,
		    uint64_t now_ns, uint32_t failure_class, const char *reason,
		    int retryable, uint32_t fallback_class);
int fex_checkpoint(struct fex_service *service, uint64_t objective_id,
			 uint64_t now_ns, const uint8_t working_digest[FEX_DIGEST_SIZE],
			 const uint8_t world_digest[FEX_DIGEST_SIZE],
			 const uint8_t resource_digest[FEX_DIGEST_SIZE],
			 struct fex_checkpoint *out);
int fex_recover(struct fex_service *service, uint64_t now_ns,
			 uint32_t *recovered, uint32_t *dead_lettered);
int fex_cancel(struct fex_service *service, uint64_t objective_id);
int fex_query_objective(const struct fex_service *service, uint64_t objective_id,
			       struct fex_objective *out);
int fex_query_node(const struct fex_service *service, uint64_t task_id,
			   struct fex_node *out);
int fex_test_model_output_untrusted(struct fex_service *service,
				    uint64_t task_id, const uint8_t output_digest[FEX_DIGEST_SIZE]);

#endif
