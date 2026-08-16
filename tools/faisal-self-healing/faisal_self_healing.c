#include "faisal_self_healing.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void copy_detail(char dst[FAS_MAX_DETAIL], const char *src)
{
	if (!src) {
		dst[0] = '\0';
		return;
	}
	snprintf(dst, FAS_MAX_DETAIL, "%s", src);
}

static void audit_append(struct fas_service *service, uint32_t action,
			 uint32_t reason, int32_t status, uint64_t signal_sequence)
{
	struct fas_audit_record *record;
	struct fms_entry entry;
	char payload[FMS_MAX_CONTENT];

	if (!service || service->audit_count >= FAS_MAX_SIGNALS)
		return;
	record = &service->audit[service->audit_count++];
	memset(record, 0, sizeof(*record));
	record->sequence = ++service->audit_sequence;
	record->signal_sequence = signal_sequence;
	record->sampled_at_ns = now_ns();
	record->state = service->state;
	record->action = action;
	record->reason = reason;
	record->status = status;
	memcpy(record->candidate_digest,
	       service->deployment.deployment.candidate.artifact_digest,
	       M78_DIGEST_SIZE);
	/* Do not mutate a checkpointed journal before recovery verification. */
	if (service->deployment.memory.checkpoint_valid)
		return;
	if (snprintf(payload, sizeof(payload),
		     "FAS audit=%llu signal=%llu state=%u action=%u reason=%u status=%d",
		     (unsigned long long)record->sequence,
		     (unsigned long long)signal_sequence, record->state,
		     action, reason, status) > 0)
		(void)fms_put(&service->deployment.memory, payload,
			      AGI_LC_MEMORY_TIER_EPISODIC, 1000000, 1000000,
			      record->sampled_at_ns, &entry);
}

static void set_state(struct fas_service *service, uint32_t state,
		      uint32_t action, uint32_t reason, int32_t status)
{
	if (!service)
		return;
	service->state = state;
	audit_append(service, action, reason, status,
		     service->diagnosis.signal_sequence);
}

int fas_open(struct fas_service *service, const char *journal_path)
{
	if (!service || !journal_path || !*journal_path)
		return FAS_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy.allowed_automatic_actions =
		FAS_APPROVAL_AUTOMATIC_ROLLBACK | FAS_APPROVAL_REPAIR_CANDIDATE;
	service->policy.max_attempts = FAS_MAX_ATTEMPTS;
	service->policy.require_operator_for_repair = 1;
	service->policy.require_canary = 1;
	service->policy.max_candidate_cpu_budget_ns = 60000000000ULL;
	service->policy.max_candidate_memory_pages = 1ULL << 20;
	if (m78_open(&service->deployment, journal_path) != 0)
		return FAS_ERR_IO;
	service->state = FAS_STATE_IDLE;
	return FAS_OK;
}

void fas_close(struct fas_service *service)
{
	if (service)
		m78_close(&service->deployment);
}

int fas_register_signal(struct fas_service *service,
			const struct fas_signal *signal)
{
	struct fas_signal *slot;
	struct fms_entry entry;
	char payload[FMS_MAX_CONTENT];

	if (!service || !signal || !signal->sequence || !signal->kind ||
	    signal->severity > 5 || service->signal_count >= FAS_MAX_SIGNALS)
		return FAS_ERR_ARGUMENT;
	slot = &service->signals[service->signal_count++];
	*slot = *signal;
	if (snprintf(payload, sizeof(payload),
		     "FAS signal=%llu kind=%u severity=%u status=%d detail=%s",
		     (unsigned long long)signal->sequence, signal->kind,
		     signal->severity, signal->status, signal->detail) <= 0)
		return FAS_ERR_IO;
	/* Preserve the checkpoint digest; post-checkpoint signals stay in the
	 * bounded supervisor audit until recovery has completed. */
	if (!service->deployment.memory.checkpoint_valid &&
	    fms_put(&service->deployment.memory, payload,
		    AGI_LC_MEMORY_TIER_EPISODIC, 1000000, 1000000,
		    signal->observed_at_ns, &entry) != FMS_OK)
		return FAS_ERR_IO;
	service->state = FAS_STATE_OBSERVED;
	audit_append(service, 0, 0, signal->status, signal->sequence);
	return FAS_OK;
}

int fas_detect(struct fas_service *service)
{
	const struct fas_signal *signal;

	if (!service || !service->signal_count)
		return FAS_ERR_STATE;
	signal = &service->signals[service->signal_count - 1];
	if (signal->severity == 0 && signal->status == 0)
		return FAS_ERR_STATE;
	service->state = FAS_STATE_DETECTED;
	audit_append(service, 0, 0, signal->status, signal->sequence);
	return FAS_OK;
}

int fas_diagnose(struct fas_service *service)
{
	const struct fas_signal *signal;
	uint32_t reason;
	uint32_t action;

	if (!service || service->state != FAS_STATE_DETECTED ||
	    !service->signal_count)
		return FAS_ERR_STATE;
	signal = &service->signals[service->signal_count - 1];
	switch (signal->kind) {
	case FAS_SIGNAL_HEALTH:
		reason = FAS_REASON_HEALTH;
		action = FAS_ACTION_ROLLBACK;
		break;
	case FAS_SIGNAL_RESOURCE:
		reason = FAS_REASON_RESOURCE;
		action = FAS_ACTION_ROLLBACK;
		break;
	case FAS_SIGNAL_CORRUPTION:
		reason = FAS_REASON_CORRUPTION;
		action = FAS_ACTION_ROLLBACK;
		break;
	case FAS_SIGNAL_SECURITY:
		reason = FAS_REASON_SECURITY;
		action = FAS_ACTION_QUARANTINE;
		break;
	case FAS_SIGNAL_TIMEOUT:
		reason = FAS_REASON_TIMEOUT;
		action = FAS_ACTION_ROLLBACK;
		break;
	case FAS_SIGNAL_DEPENDENCY:
		reason = FAS_REASON_DEPENDENCY;
		action = FAS_ACTION_REPAIR;
		break;
	default:
		return FAS_ERR_ARGUMENT;
	}
	memset(&service->diagnosis, 0, sizeof(service->diagnosis));
	service->diagnosis.reason = reason;
	service->diagnosis.action = action;
	service->diagnosis.severity = signal->severity;
	service->diagnosis.signal_sequence = signal->sequence;
	copy_detail(service->diagnosis.explanation, signal->detail);
	service->state = FAS_STATE_DIAGNOSED;
	audit_append(service, action, reason, signal->status, signal->sequence);
	return FAS_OK;
}

int fas_validate_repair(struct fas_service *service,
			const struct m78_candidate *candidate)
{
	uint8_t digest[M78_DIGEST_SIZE];

	if (!service || !candidate || service->state != FAS_STATE_DIAGNOSED ||
	    service->diagnosis.action != FAS_ACTION_REPAIR)
		return FAS_ERR_STATE;
	if (m78_compute_candidate_digest(candidate, digest) != 0 ||
	    memcmp(digest, candidate->artifact_digest, M78_DIGEST_SIZE) != 0 ||
	    !(service->policy.allowed_automatic_actions &
	      FAS_APPROVAL_REPAIR_CANDIDATE) ||
	    (service->policy.require_operator_for_repair &&
	     !candidate->operator_approved) ||
	    m78_validate_candidate(candidate) != 0 ||
	    candidate->cpu_budget_ns > service->policy.max_candidate_cpu_budget_ns ||
	    candidate->memory_limit_pages > service->policy.max_candidate_memory_pages)
		return FAS_ERR_POLICY;
	service->state = FAS_STATE_REPAIR_VALIDATED;
	audit_append(service, FAS_ACTION_REPAIR, FAS_REASON_VALIDATION, 0,
		     service->diagnosis.signal_sequence);
	return FAS_OK;
}

int fas_execute_repair(struct fas_service *service,
			const struct m78_candidate *candidate,
			uint32_t canary_health)
{
	int rc;

	if (!service || !candidate || service->state != FAS_STATE_REPAIR_VALIDATED)
		return FAS_ERR_STATE;
	if (++service->attempts > service->policy.max_attempts)
		return FAS_ERR_RETRY_LIMIT;
	rc = m78_admit(&service->deployment, candidate);
	if (rc != 0)
		goto fail;
	rc = m78_checkpoint(&service->deployment);
	if (rc != 0)
		goto fail;
	service->state = FAS_STATE_CANARY;
	audit_append(service, FAS_ACTION_REPAIR, FAS_REASON_CANARY, 0,
		     service->diagnosis.signal_sequence);
	if (service->policy.require_canary) {
		rc = m78_canary(&service->deployment, canary_health);
		if (rc != 0 || !canary_health)
			goto rollback;
	}
	rc = m78_activate(&service->deployment);
	if (rc != 0)
		goto rollback;
	set_state(service, FAS_STATE_RECOVERED, FAS_ACTION_REPAIR, 0, 0);
	return FAS_OK;
rollback:
	service->deployment.deployment.state = M78_STATE_ROLLBACK_PENDING;
	if (m78_rollback(&service->deployment, FAS_REASON_CANARY) != 0) {
		set_state(service, FAS_STATE_FAILED, FAS_ACTION_ROLLBACK,
			  FAS_REASON_CANARY, FAS_ERR_ROLLBACK);
		return FAS_ERR_ROLLBACK;
	}
	service->last_recovery_sequence =
		service->deployment.deployment.recovery.recovery_sequence;
	set_state(service, FAS_STATE_RECOVERED, FAS_ACTION_ROLLBACK,
		  FAS_REASON_CANARY, FAS_ERR_CANARY);
	return FAS_ERR_CANARY;
fail:
	set_state(service, FAS_STATE_FAILED, FAS_ACTION_QUARANTINE,
		  FAS_REASON_VALIDATION, rc);
	return FAS_ERR_VALIDATION;
}

int fas_execute_automatic_recovery(struct fas_service *service)
{
	int rc;

	if (!service || service->state != FAS_STATE_DIAGNOSED ||
	    service->diagnosis.action != FAS_ACTION_ROLLBACK)
		return FAS_ERR_STATE;
	if (!(service->policy.allowed_automatic_actions &
	      FAS_APPROVAL_AUTOMATIC_ROLLBACK) ||
	    ++service->attempts > service->policy.max_attempts) {
		set_state(service, FAS_STATE_QUARANTINED, FAS_ACTION_QUARANTINE,
			  service->attempts > service->policy.max_attempts ?
			  FAS_REASON_RETRY_LIMIT : FAS_REASON_POLICY,
			  FAS_ERR_POLICY);
		return FAS_ERR_POLICY;
	}
	service->deployment.deployment.state = M78_STATE_ROLLBACK_PENDING;
	set_state(service, FAS_STATE_ROLLBACK_REQUIRED, FAS_ACTION_ROLLBACK,
		  service->diagnosis.reason, 0);
	rc = m78_rollback(&service->deployment, service->diagnosis.reason);
	if (rc != 0) {
		set_state(service, FAS_STATE_FAILED, FAS_ACTION_ROLLBACK,
			  service->diagnosis.reason, FAS_ERR_ROLLBACK);
		return FAS_ERR_ROLLBACK;
	}
	service->last_recovery_sequence =
		service->deployment.deployment.recovery.recovery_sequence;
	set_state(service, FAS_STATE_RECOVERED, FAS_ACTION_ROLLBACK,
		  service->diagnosis.reason, 0);
	return FAS_OK;
}

int fas_run_self_heal(struct fas_service *service,
			const struct fas_signal *signal,
			const struct m78_candidate *candidate,
			uint32_t canary_health)
{
	int rc;

	if (!service || !signal)
		return FAS_ERR_ARGUMENT;
	if (fas_register_signal(service, signal) != FAS_OK ||
	    fas_detect(service) != FAS_OK || fas_diagnose(service) != FAS_OK)
		return FAS_ERR_STATE;
	if (service->diagnosis.action == FAS_ACTION_ROLLBACK)
		return fas_execute_automatic_recovery(service);
	if (service->diagnosis.action == FAS_ACTION_QUARANTINE) {
		set_state(service, FAS_STATE_QUARANTINED, FAS_ACTION_QUARANTINE,
			  service->diagnosis.reason, FAS_ERR_POLICY);
		return FAS_ERR_POLICY;
	}
	if (!candidate)
		return FAS_ERR_POLICY;
	rc = fas_validate_repair(service, candidate);
	if (rc != FAS_OK)
		return rc;
	return fas_execute_repair(service, candidate, canary_health);
}

int fas_test_retry_limit(struct fas_service *service)
{
	if (!service)
		return FAS_ERR_ARGUMENT;
	service->attempts = service->policy.max_attempts;
	return FAS_OK;
}
