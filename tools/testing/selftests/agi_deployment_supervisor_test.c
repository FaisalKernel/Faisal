#define _GNU_SOURCE
#include "../../faisal-deploy/faisal_deploy_supervisor.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M78_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void cleanup(const char *path)
{
	char sidecar[256];
	unlink(path);
	snprintf(sidecar, sizeof(sidecar), "%s.ckpt", path);
	unlink(sidecar);
}

static int make_candidate(struct m78_candidate *candidate)
{
	memset(candidate, 0, sizeof(*candidate));
	strncpy(candidate->build_id, "faisal-test-candidate-78",
		sizeof(candidate->build_id) - 1);
	memset(candidate->state_digest, 0x5a, sizeof(candidate->state_digest));
	candidate->policy_generation = 78;
	candidate->cpu_budget_ns = 5000000000ULL;
	candidate->memory_limit_pages = 16384;
	candidate->canary_window_ns = 1000000000ULL;
	candidate->required_approvals = M78_APPROVAL_SUPERVISOR |
		M78_APPROVAL_OPERATOR | M78_APPROVAL_INTEGRITY | M78_APPROVAL_CANARY;
	candidate->supervisor_approved = 1;
	candidate->operator_approved = 1;
	candidate->integrity_measured = 1;
	candidate->supervisor_nonce = 0x78000001ULL;
	candidate->operator_nonce = 0x78000002ULL;
	return m78_compute_candidate_digest(candidate, candidate->artifact_digest);
}

int main(void)
{
	const char *path = "/tmp/faisal-m78-deployment";
	struct m78_service service;
	struct m78_candidate candidate;
	int rc;
	memset(&service, 0, sizeof(service));
	if (make_candidate(&candidate) != 0)
		return fail("candidate digest", -1);
	cleanup(path);
	if (m78_open(&service, path) != 0)
		return fail("open", -1);
	if (m78_test_approval_denial(&service, &candidate) != 0)
		return fail("approval denial", -1);
	printf("M78_INDEPENDENT_APPROVAL_DENIAL_OK\n");
	if (m78_test_manifest_fuzz(&candidate) != 0)
		return fail("manifest fuzz", -1);
	printf("M78_MANIFEST_FUZZ_REJECT_OK iterations=64\n");
	if (m78_admit(&service, &candidate) != 0 ||
	    service.deployment.state != M78_STATE_CANDIDATE)
		return fail("admit", -1);
	printf("M78_CANDIDATE_INTEGRITY_OK\n");
	if (m78_checkpoint(&service) != 0 ||
	    service.deployment.state != M78_STATE_CHECKPOINTED ||
	    service.deployment.verification.state != AGI_LC_VERIFY_MATCHED)
		return fail("checkpoint", -1);
	printf("M78_CHECKPOINT_VERIFIED_OK checkpoint=%llu\n",
	       (unsigned long long)service.deployment.checkpoint.checkpoint_id);
	rc = m78_canary(&service, 0);
	if (rc != 1 || service.deployment.state != M78_STATE_ROLLBACK_PENDING ||
	    service.deployment.snapshot.sampled_at_ns == 0)
		return fail("canary failure", rc);
	printf("M78_CANARY_HEALTH_FAILURE_OK measured=0x%x unavailable=0x%x unsupported=0x%x\n",
	       service.deployment.snapshot.measured_mask,
	       service.deployment.snapshot.unavailable_mask,
	       service.deployment.snapshot.unsupported_mask);
	if (m78_rollback(&service, 1) != 0 ||
	    service.deployment.state != M78_STATE_ROLLED_BACK)
		return fail("rollback", -1);
	printf("M78_ROLLBACK_OK recovery=%llu\n",
	       (unsigned long long)service.deployment.recovery.recovery_sequence);
	if (service.deployment.audit_count < 3)
		return fail("audit records", -1);
	printf("M78_AUDIT_PROVENANCE_OK records=%u\n", service.deployment.audit_count);
	m78_close(&service);
	cleanup(path);

	if (m78_open(&service, path) != 0 || m78_admit(&service, &candidate) != 0 ||
	    m78_checkpoint(&service) != 0 || m78_canary(&service, 1) != 0 ||
	    m78_activate(&service) != 0 ||
	    service.deployment.state != M78_STATE_ACTIVE)
		return fail("successful activation", -1);
	if (m78_test_model_authority_denial(&service) != 0)
		return fail("model authority boundary", -1);
	printf("M78_CANARY_ACTIVE_OK\n");
	printf("M78_MODEL_OUTPUT_NO_AUTHORITY_OK\n");
	m78_close(&service);
	cleanup(path);
	printf("M78_SELFTEST_EXIT=0\n");
	return 0;
}
