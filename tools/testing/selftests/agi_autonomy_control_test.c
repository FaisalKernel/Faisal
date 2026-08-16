// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FAC_FAIL:%s rc=%d errno=%d\n", what, rc, errno);
	return 1;
}

static int setup_session(void)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	int fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);

	if (fd < 0 || ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	return fd;
}

static int record_evidence(int fd, struct agi_lc_autonomy_control *control,
			   __u64 mask, __u8 fill)
{
	struct agi_lc_autonomy_control evidence = *control;

	evidence.operation = AGI_LC_AUTONOMY_RECORD_EVIDENCE;
	evidence.state = 0;
	evidence.evidence_mask = mask;
	evidence.required_evidence_mask = 0;
	evidence.status = 0;
	memset(evidence.evidence_digest, fill, sizeof(evidence.evidence_digest));
	return ioctl(fd, AGI_LC_AUTONOMY_CONTROL, &evidence);
}

static int advance_state(int fd, struct agi_lc_autonomy_control *control,
			 __u32 state)
{
	struct agi_lc_autonomy_control advance = *control;

	advance.operation = AGI_LC_AUTONOMY_ADVANCE;
	advance.state = state;
	advance.evidence_mask = 0;
	advance.required_evidence_mask = 0;
	advance.status = 0;
	return ioctl(fd, AGI_LC_AUTONOMY_CONTROL, &advance);
}

static int approve(int fd, struct agi_lc_autonomy_control *control,
		   __u32 operation)
{
	struct agi_lc_autonomy_control approval = *control;

	approval.operation = operation;
	approval.state = 0;
	approval.evidence_mask = 0;
	approval.required_evidence_mask = 0;
	approval.status = 0;
	return ioctl(fd, AGI_LC_AUTONOMY_CONTROL, &approval);
}

int main(void)
{
	const __u64 required = AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION |
		AGI_LC_AUTONOMY_EVIDENCE_DIAGNOSIS |
		AGI_LC_AUTONOMY_EVIDENCE_PATCH |
		AGI_LC_AUTONOMY_EVIDENCE_BUILD |
		AGI_LC_AUTONOMY_EVIDENCE_TEST |
		AGI_LC_AUTONOMY_EVIDENCE_FUZZ |
		AGI_LC_AUTONOMY_EVIDENCE_SECURITY;
	struct agi_lc_autonomy_control control = {
		.size = sizeof(control),
		.operation = AGI_LC_AUTONOMY_CREATE,
		.flags = AGI_LC_AUTONOMY_FLAG_REQUIRE_SIGNED_EVIDENCE |
			AGI_LC_AUTONOMY_FLAG_REQUIRE_SUPERVISOR |
			AGI_LC_AUTONOMY_FLAG_REQUIRE_OPERATOR,
		.required_evidence_mask = required,
		.expires_ns = 300000000000ULL,
		.correlation = 104001,
	};
	int owner = setup_session();
	int supervisor = setup_session();
	int operator_fd = setup_session();
	struct agi_lc_autonomy_control query;
	int supervisor_rc;
	int operator_rc;

	if (owner < 0 || supervisor < 0 || operator_fd < 0)
		return fail("session setup", -1);
	if (ioctl(owner, AGI_LC_AUTONOMY_CONTROL, &control) < 0 ||
	    !control.control_id || !control.capability ||
	    control.state != AGI_LC_AUTONOMY_STATE_OBSERVE)
		return fail("create", -1);
	printf("FAC_CONTROL_CREATED id=%llu\n",
	       (unsigned long long)control.control_id);
	if (record_evidence(supervisor, &control,
			    AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION, 0xa1) == 0 ||
	    errno != EACCES)
		return fail("owner-only evidence", -1);
	if (record_evidence(owner, &control,
			    AGI_LC_AUTONOMY_EVIDENCE_OBSERVATION, 0xa1) < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_DIAGNOSE) < 0)
		return fail("observation to diagnosis", -1);
	if (record_evidence(owner, &control,
			    AGI_LC_AUTONOMY_EVIDENCE_DIAGNOSIS, 0xa2) < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_PROPOSE) < 0)
		return fail("diagnosis to proposal", -1);
	if (record_evidence(owner, &control,
			    AGI_LC_AUTONOMY_EVIDENCE_PATCH |
			    AGI_LC_AUTONOMY_EVIDENCE_BUILD |
			    AGI_LC_AUTONOMY_EVIDENCE_TEST |
			    AGI_LC_AUTONOMY_EVIDENCE_FUZZ |
			    AGI_LC_AUTONOMY_EVIDENCE_SECURITY, 0xa3) < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_VERIFY) < 0)
		return fail("verification evidence", -1);
	if (advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_CANARY) == 0 ||
	    errno != EACCES)
		return fail("approval gate", -1);
	printf("FAC_DEPLOY_BLOCKED_WITHOUT_APPROVALS_OK\n");
	supervisor_rc = approve(supervisor, &control,
				AGI_LC_AUTONOMY_SUPERVISOR_APPROVE);
	operator_rc = approve(operator_fd, &control,
			      AGI_LC_AUTONOMY_OPERATOR_APPROVE);
	if (supervisor_rc < 0 || operator_rc < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_CANARY) < 0)
		return fail("independent approvals", -1);
	if (record_evidence(owner, &control,
			    AGI_LC_AUTONOMY_EVIDENCE_CANARY, 0xa4) < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_DEPLOY) < 0 ||
	    advance_state(owner, &control, AGI_LC_AUTONOMY_STATE_MONITOR) < 0)
		return fail("canary deployment monitor", -1);
	printf("FAC_INDEPENDENT_APPROVAL_CANARY_DEPLOY_OK\n");
	memset(&query, 0, sizeof(query));
	query.size = sizeof(query);
	query.operation = AGI_LC_AUTONOMY_QUERY;
	query.control_id = control.control_id;
	query.capability = control.capability;
	if (ioctl(supervisor, AGI_LC_AUTONOMY_CONTROL, &query) < 0 ||
	    query.state != AGI_LC_AUTONOMY_STATE_MONITOR ||
	    !(query.evidence_mask & AGI_LC_AUTONOMY_EVIDENCE_CANARY))
		return fail("query monitor state", -1);
	control = query;
	{
		struct agi_lc_autonomy_control rollback = {
			.size = sizeof(rollback),
			.operation = AGI_LC_AUTONOMY_ROLLBACK,
			.control_id = control.control_id,
			.capability = control.capability,
		};

		if (ioctl(owner, AGI_LC_AUTONOMY_CONTROL, &rollback) < 0)
			return fail("rollback", -1);
	}
	printf("FAC_ROLLBACK_OK\nFAC_SELFTEST_EXIT=0\n");
	close(owner);
	close(supervisor);
	close(operator_fd);
	return 0;
}
