#ifndef FAISAL_SELF_HEALING_H
#define FAISAL_SELF_HEALING_H

#include <stdint.h>
#include "../faisal-deploy/faisal_deploy_supervisor.h"

#define FAS_MAX_SIGNALS 32
#define FAS_MAX_ATTEMPTS 3
#define FAS_MAX_DETAIL 192
#define FAS_MAX_REPAIR_ID 96

#define FAS_APPROVAL_AUTOMATIC_ROLLBACK (1U << 0)
#define FAS_APPROVAL_REPAIR_CANDIDATE (1U << 1)

#define FAS_SIGNAL_HEALTH 1U
#define FAS_SIGNAL_RESOURCE 2U
#define FAS_SIGNAL_CORRUPTION 3U
#define FAS_SIGNAL_SECURITY 4U
#define FAS_SIGNAL_TIMEOUT 5U
#define FAS_SIGNAL_DEPENDENCY 6U

#define FAS_REASON_HEALTH 1U
#define FAS_REASON_RESOURCE 2U
#define FAS_REASON_CORRUPTION 3U
#define FAS_REASON_SECURITY 4U
#define FAS_REASON_TIMEOUT 5U
#define FAS_REASON_DEPENDENCY 6U
#define FAS_REASON_POLICY 7U
#define FAS_REASON_VALIDATION 8U
#define FAS_REASON_CANARY 9U
#define FAS_REASON_RETRY_LIMIT 10U

#define FAS_ACTION_ROLLBACK 1U
#define FAS_ACTION_REPAIR 2U
#define FAS_ACTION_QUARANTINE 3U

#define FAS_OK 0
#define FAS_ERR_ARGUMENT -1
#define FAS_ERR_IO -2
#define FAS_ERR_POLICY -3
#define FAS_ERR_STATE -4
#define FAS_ERR_VALIDATION -5
#define FAS_ERR_CANARY -6
#define FAS_ERR_ROLLBACK -7
#define FAS_ERR_RETRY_LIMIT -8

/* A signal is an observation; it is never itself an authorization. */
struct fas_signal {
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint32_t kind;
	uint32_t severity;
	int32_t status;
	uint64_t correlation;
	char detail[FAS_MAX_DETAIL];
};

enum fas_state {
	FAS_STATE_IDLE = 0,
	FAS_STATE_OBSERVED = 1,
	FAS_STATE_DETECTED = 2,
	FAS_STATE_DIAGNOSED = 3,
	FAS_STATE_REPAIR_VALIDATED = 4,
	FAS_STATE_CANARY = 5,
	FAS_STATE_RECOVERED = 6,
	FAS_STATE_ROLLBACK_REQUIRED = 7,
	FAS_STATE_QUARANTINED = 8,
	FAS_STATE_FAILED = 9
};

struct fas_diagnosis {
	uint32_t reason;
	uint32_t action;
	uint32_t severity;
	uint32_t reserved;
	uint64_t signal_sequence;
	char explanation[FAS_MAX_DETAIL];
};

struct fas_policy {
	uint32_t allowed_automatic_actions;
	uint32_t max_attempts;
	uint32_t require_operator_for_repair;
	uint32_t require_canary;
	uint64_t max_candidate_cpu_budget_ns;
	uint64_t max_candidate_memory_pages;
};

struct fas_audit_record {
	uint64_t sequence;
	uint64_t signal_sequence;
	uint64_t sampled_at_ns;
	uint32_t state;
	uint32_t action;
	uint32_t reason;
	int32_t status;
	uint8_t candidate_digest[M78_DIGEST_SIZE];
};

struct fas_service {
	struct m78_service deployment;
	struct fas_policy policy;
	struct fas_signal signals[FAS_MAX_SIGNALS];
	struct fas_diagnosis diagnosis;
	struct fas_audit_record audit[FAS_MAX_SIGNALS];
	uint32_t signal_count;
	uint32_t audit_count;
	uint32_t attempts;
	uint32_t state;
	uint64_t audit_sequence;
	uint64_t last_recovery_sequence;
};

int fas_open(struct fas_service *service, const char *journal_path);
void fas_close(struct fas_service *service);
int fas_register_signal(struct fas_service *service,
			const struct fas_signal *signal);
int fas_detect(struct fas_service *service);
int fas_diagnose(struct fas_service *service);
int fas_validate_repair(struct fas_service *service,
			const struct m78_candidate *candidate);
int fas_execute_repair(struct fas_service *service,
			const struct m78_candidate *candidate,
			uint32_t canary_health);
int fas_execute_automatic_recovery(struct fas_service *service);
int fas_run_self_heal(struct fas_service *service,
			const struct fas_signal *signal,
			const struct m78_candidate *candidate,
			uint32_t canary_health);
int fas_test_retry_limit(struct fas_service *service);

#endif
