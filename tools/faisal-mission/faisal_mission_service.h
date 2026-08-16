#ifndef FAISAL_MISSION_SERVICE_H
#define FAISAL_MISSION_SERVICE_H

#include <stdint.h>
#include "../faisal-task/faisal_task_service.h"

#define M98_MAX_MISSIONS 16U
#define M98_MAX_PLAN 192U
#define M98_MAX_REASON 160U
#define M98_MAX_EVENT 128U
#define M98_MISSION_JOURNAL_MAGIC 0x464d3938U
#define M98_MISSION_JOURNAL_VERSION 1U
#define M98_DIGEST_SIZE FTS_DIGEST_SIZE

enum m98_mission_state {
	M98_MISSION_NEW = 1,
	M98_MISSION_ACTIVE = 2,
	M98_MISSION_OBSERVE_REQUIRED = 3,
	M98_MISSION_PROPOSAL_REQUIRED = 4,
	M98_MISSION_PREPARED = 5,
	M98_MISSION_EXECUTION_PENDING = 6,
	M98_MISSION_EVIDENCE_PENDING = 7,
	M98_MISSION_COMMITTED = 8,
	M98_MISSION_REPLAN_REQUIRED = 9,
	M98_MISSION_SUCCEEDED = 10,
	M98_MISSION_STOPPED = 11,
	M98_MISSION_ESCALATED = 12
};

enum m98_trigger_kind {
	M98_TRIGGER_MANUAL = 1,
	M98_TRIGGER_EVENT = 2,
	M98_TRIGGER_TIMER = 3,
	M98_TRIGGER_RECOVERY = 4
};

enum m98_decision {
	M98_DECISION_CONTINUE = 1,
	M98_DECISION_REPLAN = 2,
	M98_DECISION_STOP = 3,
	M98_DECISION_ESCALATE = 4,
	M98_DECISION_SUCCEED = 5
};

enum m98_status {
	M98_OK = 0,
	M98_ERR_ARGUMENT = -1,
	M98_ERR_IO = -2,
	M98_ERR_CORRUPT = -3,
	M98_ERR_FULL = -4,
	M98_ERR_NOT_FOUND = -5,
	M98_ERR_STATE = -6,
	M98_ERR_POLICY = -7,
	M98_ERR_DEADLINE = -8,
	M98_ERR_BUDGET = -9,
	M98_ERR_STALE = -10,
	M98_ERR_AUTHORITY = -11,
	M98_ERR_EVIDENCE = -12,
	M98_ERR_ESCALATED = -13
};

struct m98_policy {
	uint64_t deadline_ns;
	uint64_t cpu_budget_ns;
	uint64_t money_budget_micro;
	uint32_t max_steps;
	uint32_t max_retries;
	uint32_t risk_ceiling;
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint64_t supervisor_nonce;
	uint64_t operator_nonce;
};

struct m98_mission {
	uint64_t mission_id;
	uint64_t task_id;
	uint64_t created_at_ns;
	uint64_t updated_at_ns;
	uint64_t deadline_ns;
	uint64_t next_wakeup_ns;
	uint64_t event_sequence;
	uint64_t objective_generation;
	uint64_t step;
	uint64_t retry_count;
	uint64_t consumed_cpu_ns;
	uint64_t consumed_money_micro;
	uint64_t cpu_budget_ns;
	uint64_t money_budget_micro;
	uint64_t supervisor_nonce;
	uint64_t operator_nonce;
	uint32_t max_steps;
	uint32_t max_retries;
	uint32_t risk_ceiling;
	uint32_t reserved;
	uint64_t branch_id;
	uint64_t capsule_id;
	uint32_t state;
	uint32_t trigger;
	uint32_t decision;
	uint32_t risk_class;
	uint32_t stop_reason;
	uint32_t escalation_reason;
	uint8_t working_state_digest[M98_DIGEST_SIZE];
	uint8_t world_state_digest[M98_DIGEST_SIZE];
	uint8_t resource_state_digest[M98_DIGEST_SIZE];
	uint8_t plan_digest[M98_DIGEST_SIZE];
	uint8_t model_provenance_digest[M98_DIGEST_SIZE];
	uint8_t action_digest[M98_DIGEST_SIZE];
	char objective[FTS_MAX_OBJECTIVE];
	char plan[M98_MAX_PLAN];
	char last_event[M98_MAX_EVENT];
	char reason[M98_MAX_REASON];
};

struct m98_service {
	struct fts_service tasks;
	int mission_fd;
	int lock_initialized;
	uint64_t next_mission_id;
	uint64_t mission_sequence;
	char mission_path[FTS_MAX_JOURNAL_PATH];
	struct m98_mission missions[M98_MAX_MISSIONS];
	size_t mission_count;
	pthread_mutex_t lock;
};

int m98_open(struct m98_service *service, const char *journal_prefix,
		     int require_kernel);
void m98_close(struct m98_service *service);
int m98_replay(struct m98_service *service);
int m98_create(struct m98_service *service, const char *objective,
		       const struct m98_policy *policy, uint64_t now_ns,
		       struct m98_mission *out);
int m98_observe(struct m98_service *service, uint64_t mission_id,
		       uint64_t now_ns, uint64_t event_sequence,
		       uint32_t trigger, const uint8_t working_digest[M98_DIGEST_SIZE],
		       const uint8_t world_digest[M98_DIGEST_SIZE],
		       const uint8_t resource_digest[M98_DIGEST_SIZE],
		       const char *event, struct m98_mission *out);
int m98_propose(struct m98_service *service, uint64_t mission_id,
			uint64_t now_ns, const struct fts_authority_ref *authority,
			const uint8_t plan_digest[M98_DIGEST_SIZE],
			const uint8_t model_provenance_digest[M98_DIGEST_SIZE],
			const uint8_t action_digest[M98_DIGEST_SIZE],
			uint32_t risk_class, uint32_t resource_mask,
			uint64_t resource_admission, const char *plan,
			const char *action, struct m98_mission *out);
int m98_execute_result(struct m98_service *service, uint64_t mission_id,
			       uint64_t now_ns, uint64_t cpu_used_ns,
			       uint64_t money_used_micro, uint32_t decision,
			       uint32_t verification_ok, const char *result,
			       struct m98_mission *out);
int m98_tick(struct m98_service *service, uint64_t mission_id,
		    uint64_t now_ns, struct m98_mission *out);
int m98_query(const struct m98_service *service, uint64_t mission_id,
		      struct m98_mission *out);
int m98_test_corrupt_tail(const struct m98_service *service);

#endif
