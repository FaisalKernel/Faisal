#define _GNU_SOURCE
#include "faisal_stress_service.h"

#include "../faisal-coordinator/faisal_coordinator_service.h"
#include "../faisal-deploy/faisal_deploy_supervisor.h"
#include "../faisal-accelerator/faisal_accelerator_validation.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int stress_fail(const char *stage)
{
	fprintf(stderr, "M80_STAGE_FAIL:%s errno=%d\n", stage, errno);
	return -1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 80001,
	};
	struct agi_lc_agent selected = { .size = sizeof(selected) };
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	selected.agent_id = light.agent_id;
	selected.correlation = 80002;
	return ioctl(fd, AGI_LC_SET_AGENT, &selected);
}

static void fill_model_digest(uint8_t digest[FMS_DIGEST_SIZE])
{
	unsigned int i;
	for (i = 0; i < FMS_DIGEST_SIZE; i++)
		digest[i] = (uint8_t)(0xa0U + (i & 0x0fU));
}

static void fill_candidate(struct m78_candidate *candidate)
{
	memset(candidate, 0, sizeof(*candidate));
	strncpy(candidate->build_id, "faisal-m80-canary-candidate",
		sizeof(candidate->build_id) - 1);
	memset(candidate->state_digest, 0x66, sizeof(candidate->state_digest));
	candidate->policy_generation = 80;
	candidate->cpu_budget_ns = 5000000000ULL;
	candidate->memory_limit_pages = 16384;
	candidate->canary_window_ns = 1000000000ULL;
	candidate->required_approvals = M78_APPROVAL_SUPERVISOR |
		M78_APPROVAL_OPERATOR | M78_APPROVAL_INTEGRITY | M78_APPROVAL_CANARY;
	candidate->supervisor_approved = 1;
	candidate->operator_approved = 1;
	candidate->integrity_measured = 1;
	candidate->supervisor_nonce = 0x80000001ULL;
	candidate->operator_nonce = 0x80000002ULL;
	m78_compute_candidate_digest(candidate, candidate->artifact_digest);
}

int m80_test_malformed_uapi(uint32_t *accepted)
{
	int fd;
	uint32_t i;
	uint32_t count = 0;
	struct agi_lc_subscribe subscribe;
	if (!accepted)
		return -1;
	*accepted = 0;
	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0 || setup_session(fd) < 0) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	for (i = 0; i < M80_MALFORMED_CASES; i++) {
		memset(&subscribe, 0, sizeof(subscribe));
		subscribe.size = sizeof(subscribe);
		subscribe.correlation = 80010 + i;
		switch (i & 3U) {
		case 0:
			subscribe.size = sizeof(subscribe) - 1;
			break;
		case 1:
			subscribe.flags = 1;
			break;
		case 2:
			subscribe.reserved[0] = 1;
			break;
		default:
			subscribe.reserved[1] = 1;
			break;
		}
		if (ioctl(fd, AGI_LC_SUBSCRIBE, &subscribe) == 0)
			count++;
	}
	close(fd);
	*accepted = count;
	return count == 0 ? 0 : -1;
}

int m80_test_resource_pressure(uint32_t *samples)
{
	int fd;
	uint32_t i;
	struct agi_lc_memory_budget budget = {
		.size = sizeof(budget),
		.limit_pages = 1,
		.correlation = 80020,
	};
	struct agi_lc_resource_snapshot snapshot;
	if (!samples)
		return -1;
	*samples = 0;
	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0 || setup_session(fd) < 0) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	if (ioctl(fd, AGI_LC_SET_MEMORY_BUDGET, &budget) < 0) {
		close(fd);
		return -1;
	}
	for (i = 0; i < M80_RESOURCE_SAMPLES; i++) {
		memset(&snapshot, 0, sizeof(snapshot));
		snapshot.size = sizeof(snapshot);
		snapshot.correlation = 80021 + i;
		if (ioctl(fd, AGI_LC_GET_RESOURCE_SNAPSHOT, &snapshot) < 0 ||
		    !snapshot.sampled_at_ns ||
		    (snapshot.measured_mask & ~AGI_LC_RESOURCE_ALL) ||
		    (snapshot.unavailable_mask & ~AGI_LC_RESOURCE_ALL) ||
		    (snapshot.unsupported_mask & ~AGI_LC_RESOURCE_ALL) ||
		    (snapshot.measured_mask & snapshot.unavailable_mask) ||
		    (snapshot.measured_mask & snapshot.unsupported_mask) ||
		    (snapshot.unavailable_mask & snapshot.unsupported_mask)) {
			close(fd);
			return -1;
		}
		(*samples)++;
	}
	close(fd);
	return 0;
}

int m80_test_cancellation(uint32_t *passes)
{
	uint32_t i;
	uint32_t count = 0;
	struct m76_request request;
	struct m76_report report;
	char prefix[256];
	if (!passes)
		return -1;
	memset(&request, 0, sizeof(request));
	strncpy(request.goal, "m80-cancellation-loop", sizeof(request.goal) - 1);
	strncpy(request.skill, "bounded-cancel", sizeof(request.skill) - 1);
	fill_model_digest(request.model_digest);
	request.supervisor_approved = 1;
	request.operator_approved = 1;
	request.supervisor_nonce = 0x81000001ULL;
	request.operator_nonce = 0x81000002ULL;
	for (i = 0; i < M80_CANCEL_CASES; i++) {
		snprintf(prefix, sizeof(prefix), "/tmp/faisal-m80-cancel-%u", i);
		memset(&report, 0, sizeof(report));
		if (m76_run(&request, &report, prefix) != 0 ||
		    report.ipc_cancelled_message_id == 0)
			return -1;
		count++;
	}
	*passes = count;
	return 0;
}

int m80_test_rollback(const char *journal_path)
{
	struct m78_service service;
	struct m78_candidate candidate;
	int rc;
	if (!journal_path)
		return -1;
	fill_candidate(&candidate);
	memset(&service, 0, sizeof(service));
	rc = m78_open(&service, journal_path);
	if (rc != 0)
		return -1;
	rc = m78_admit(&service, &candidate);
	if (rc == 0)
		rc = m78_checkpoint(&service);
	if (rc == 0 && m78_canary(&service, 0) != 1)
		rc = -1;
	if (rc == 0)
		rc = m78_rollback(&service, 80030);
	if (rc == 0 && service.deployment.state != M78_STATE_ROLLED_BACK)
		rc = -1;
	m78_close(&service);
	return rc;
}

int m80_run(const char *journal_prefix, struct m80_report *report)
{
	struct m76_request request;
	struct m76_report composed;
	struct m79_provider_evidence provider;
	struct m79_service accelerator;
	uint32_t accepted = 0;
	uint32_t samples = 0;
	uint32_t cancels = 0;
	uint32_t i;
	char prefix[256];
	if (!journal_prefix || !report)
		return -1;
	memset(report, 0, sizeof(*report));
	if (m80_test_malformed_uapi(&accepted) != 0 || accepted != 0)
		return stress_fail("malformed");
	report->malformed_rejections = M80_MALFORMED_CASES;
	if (m80_test_resource_pressure(&samples) != 0)
		return stress_fail("resource");
	report->resource_samples = samples;
	memset(&request, 0, sizeof(request));
	strncpy(request.goal, "m80-long-horizon-composition", sizeof(request.goal) - 1);
	strncpy(request.skill, "stress-recovery", sizeof(request.skill) - 1);
	fill_model_digest(request.model_digest);
	request.supervisor_approved = 1;
	request.operator_approved = 1;
	request.supervisor_nonce = 0x82000001ULL;
	request.operator_nonce = 0x82000002ULL;
	for (i = 0; i < M80_COMPOSITION_RUNS; i++) {
		int composition_rc;
		snprintf(prefix, sizeof(prefix), "%s-compose-%u", journal_prefix, i);
		memset(&composed, 0, sizeof(composed));
		composition_rc = m76_run(&request, &composed, prefix);
		if (composition_rc != 0 || composed.state != M76_COMPLETED ||
		    composed.ipc_cancelled_message_id == 0 ||
		    composed.reflection_action_id == 0 ||
		    composed.reflection_authority_capability == 0) {
			fprintf(stderr, "M80_COMPOSITION_FAIL rc=%d state=%u stages=%u failure=%u errno=%d\n",
				composition_rc, composed.state, composed.completed_stages,
				composed.failure_stage, errno);
			return stress_fail("composition");
		}
		report->composition_runs++;
		report->last_world_sequence = composed.world_event_sequence;
		report->last_observability_sequence = composed.observability_last_sequence;
	}
	if (m80_test_cancellation(&cancels) != 0 || cancels != M80_CANCEL_CASES)
		return stress_fail("cancellation");
	report->cancellation_passes = cancels;
	if (m80_test_rollback("/tmp/faisal-m80-rollback") != 0)
		return stress_fail("rollback");
	report->rollback_passes = 2;
	if (m79_discover_provider(&provider) != 0 ||
	    m79_validate_provider_evidence(&provider) != 0)
		return stress_fail("provider");
	if (provider.provider_state == M79_PROVIDER_UNSUPPORTED)
		report->provider_unsupported = 1;
	if (m79_open(&accelerator) != 0 || m79_run(&accelerator, &provider) != 0) {
		m79_close(&accelerator);
		return stress_fail("accelerator");
	}
	m79_close(&accelerator);
	report->audit_records = report->composition_runs + report->rollback_passes;
	return 0;
}
