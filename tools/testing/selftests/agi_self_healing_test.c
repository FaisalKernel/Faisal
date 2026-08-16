#include "../../faisal-self-healing/faisal_self_healing.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FAS_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void cleanup(const char *path)
{
	char sidecar[256];
	unlink(path);
	snprintf(sidecar, sizeof(sidecar), "%s.ckpt", path);
	unlink(sidecar);
}

static int make_candidate(struct m78_candidate *candidate, uint64_t generation)
{
	memset(candidate, 0, sizeof(*candidate));
	snprintf(candidate->build_id, sizeof(candidate->build_id),
		 "faisal-repair-candidate-%llu", (unsigned long long)generation);
	memset(candidate->state_digest, (int)(0x40 + generation),
	       sizeof(candidate->state_digest));
	candidate->policy_generation = generation;
	candidate->cpu_budget_ns = 5000000000ULL;
	candidate->memory_limit_pages = 16384;
	candidate->canary_window_ns = 1000000000ULL;
	candidate->required_approvals = M78_APPROVAL_SUPERVISOR |
		M78_APPROVAL_OPERATOR | M78_APPROVAL_INTEGRITY | M78_APPROVAL_CANARY;
	candidate->supervisor_approved = 1;
	candidate->operator_approved = 1;
	candidate->integrity_measured = 1;
	candidate->supervisor_nonce = 0x84000000ULL + generation * 2;
	candidate->operator_nonce = 0x84000001ULL + generation * 2;
	return m78_compute_candidate_digest(candidate, candidate->artifact_digest);
}

static void make_signal(struct fas_signal *signal, uint64_t sequence,
			uint32_t kind, uint32_t severity, int32_t status,
			const char *detail)
{
	memset(signal, 0, sizeof(*signal));
	signal->sequence = sequence;
	signal->observed_at_ns = sequence * 1000;
	signal->kind = kind;
	signal->severity = severity;
	signal->status = status;
	signal->correlation = 84000 + sequence;
	snprintf(signal->detail, sizeof(signal->detail), "%s", detail);
}

static int setup_active(struct fas_service *service, const char *path,
			struct m78_candidate *candidate, uint64_t generation)
{
	if (make_candidate(candidate, generation) != 0 ||
	    fas_open(service, path) != FAS_OK ||
	    m78_admit(&service->deployment, candidate) != 0 ||
	    m78_checkpoint(&service->deployment) != 0 ||
	    m78_canary(&service->deployment, 1) != 0 ||
	    m78_activate(&service->deployment) != 0)
		return -1;
	return 0;
}

int main(void)
{
	const char *rollback_path = "/tmp/faisal-self-heal-rollback";
	const char *repair_path = "/tmp/faisal-self-heal-repair";
	const char *canary_path = "/tmp/faisal-self-heal-canary";
	const char *security_path = "/tmp/faisal-self-heal-security";
	struct fas_service service;
	struct fas_signal signal;
	struct m78_candidate candidate;
	int rc;

	cleanup(rollback_path);
	memset(&service, 0, sizeof(service));
	if (setup_active(&service, rollback_path, &candidate, 1) != 0)
		return fail("rollback setup", -1);
	make_signal(&signal, 1, FAS_SIGNAL_HEALTH, 5, -EIO,
		    "health monitor observed failed canary dependency");
	rc = fas_run_self_heal(&service, &signal, NULL, 0);
	if (rc != FAS_OK || service.state != FAS_STATE_RECOVERED ||
	    service.deployment.deployment.state != M78_STATE_ROLLED_BACK ||
	    !service.last_recovery_sequence)
		return fail("automatic rollback", rc);
	printf("FAS_AUTOMATIC_ROLLBACK_OK recovery=%llu\n",
	       (unsigned long long)service.last_recovery_sequence);
	if (service.audit_count < 5)
		return fail("rollback audit", -1);
	printf("FAS_AUDIT_RETENTION_OK records=%u\n", service.audit_count);
	fas_close(&service);
	cleanup(rollback_path);

	memset(&service, 0, sizeof(service));
	if (fas_open(&service, repair_path) != FAS_OK ||
	    make_candidate(&candidate, 2) != 0)
		return fail("repair open", -1);
	make_signal(&signal, 2, FAS_SIGNAL_DEPENDENCY, 3, -EAGAIN,
		    "dependency restart requested by trusted monitor");
	rc = fas_run_self_heal(&service, &signal, &candidate, 1);
	if (rc != FAS_OK || service.state != FAS_STATE_RECOVERED ||
	    service.deployment.deployment.state != M78_STATE_ACTIVE)
		return fail("approved repair", rc);
	printf("FAS_APPROVED_REPAIR_CANARY_OK attempts=%u\n", service.attempts);
	fas_close(&service);
	cleanup(repair_path);

	memset(&service, 0, sizeof(service));
	if (fas_open(&service, canary_path) != FAS_OK ||
	    make_candidate(&candidate, 3) != 0)
		return fail("canary open", -1);
	make_signal(&signal, 3, FAS_SIGNAL_DEPENDENCY, 4, -EIO,
		    "candidate canary health failure");
	rc = fas_run_self_heal(&service, &signal, &candidate, 0);
	if (rc != FAS_ERR_CANARY || service.state != FAS_STATE_RECOVERED ||
	    service.deployment.deployment.state != M78_STATE_ROLLED_BACK)
		return fail("canary rollback", rc);
	printf("FAS_CANARY_FAILURE_ROLLBACK_OK\n");
	fas_close(&service);
	cleanup(canary_path);

	memset(&service, 0, sizeof(service));
	if (fas_open(&service, security_path) != FAS_OK)
		return fail("security open", -1);
	make_signal(&signal, 4, FAS_SIGNAL_SECURITY, 5, -EPERM,
		    "security monitor denied repair authority");
	rc = fas_run_self_heal(&service, &signal, NULL, 0);
	if (rc != FAS_ERR_POLICY || service.state != FAS_STATE_QUARANTINED)
		return fail("security quarantine", rc);
	printf("FAS_SECURITY_QUARANTINE_OK\n");
	fas_close(&service);
	cleanup(security_path);

	memset(&service, 0, sizeof(service));
	if (fas_open(&service, rollback_path) != FAS_OK ||
	    setup_active(&service, rollback_path, &candidate, 5) != 0)
		return fail("retry setup", -1);
	if (fas_test_retry_limit(&service) != FAS_OK)
		return fail("retry fixture", -1);
	make_signal(&signal, 5, FAS_SIGNAL_HEALTH, 5, -EIO,
		    "repeated recovery failure");
	rc = fas_run_self_heal(&service, &signal, NULL, 0);
	if (rc != FAS_ERR_POLICY || service.state != FAS_STATE_QUARANTINED)
		return fail("retry quarantine", rc);
	printf("FAS_RETRY_LIMIT_QUARANTINE_OK attempts=%u\n", service.attempts);
	fas_close(&service);
	cleanup(rollback_path);

	printf("FAS_SELFTEST_EXIT=0\n");
	return 0;
}
