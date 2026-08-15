#define _GNU_SOURCE
#include "../../faisal-coordinator/faisal_coordinator_service.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M76_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void remove_journals(const char *prefix)
{
	char path[256];
	const char *suffixes[] = { "experience", "model", "world", "browser", "control" };
	unsigned int i;
	for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
		snprintf(path, sizeof(path), "%s-%s", prefix, suffixes[i]);
		unlink(path);
		snprintf(path, sizeof(path), "%s-%s.ckpt", prefix, suffixes[i]);
		unlink(path);
	}
}

int main(void)
{
	const char *success_prefix = "/tmp/faisal-m76-success";
	const char *failure_prefix = "/tmp/faisal-m76-failure";
	struct m76_request request;
	struct m76_request denied;
	struct m76_report report;
	int rc = 0;

	memset(&request, 0, sizeof(request));
	strncpy(request.goal, "coordinate a verified browser observation", sizeof(request.goal) - 1);
	strncpy(request.skill, "retain and verify the observed result", sizeof(request.skill) - 1);
	request.model_digest[0] = 0x76;
	request.model_digest[1] = 0x01;
	request.supervisor_approved = 1;
	request.operator_approved = 1;
	request.supervisor_nonce = 0x76000001ULL;
	request.operator_nonce = 0x76000002ULL;
	request.failure_stage = M76_FAILURE_NONE;
	if (m76_test_malformed_inputs(&request) != 0)
		return fail("malformed input fixture", rc);
	{
		unsigned int i;
		for (i = 0; i < 64; i++) {
			struct m76_request malformed = request;
			struct m76_report rejected;
			malformed.reserved = i + 1;
			if (m76_run(&malformed, &rejected, "/tmp/faisal-m76-malformed") == 0)
				return fail("malformed task accepted", (int)i);
		}
	}
	printf("M76_TASK_INPUT_FUZZ_OK iterations=64\n");
	printf("M76_TASK_INPUT_BOUNDARY_OK\n");
	denied = request;
	denied.operator_approved = 0;
	memset(&report, 0, sizeof(report));
	if (m76_run(&denied, &report, "/tmp/faisal-m76-denied") == 0 ||
	    report.state != M76_DENIED || report.deployment_gate_open)
		return fail("approval denial", rc);
	printf("M76_INDEPENDENT_APPROVAL_DENIAL_OK\n");
	remove_journals(success_prefix);
	memset(&report, 0, sizeof(report));
	rc = m76_run(&request, &report, success_prefix);
	if (rc != 0 || report.state != M76_COMPLETED ||
	    !report.deployment_gate_open || !report.canary_passed ||
	    !report.security_passed || !report.regression_passed ||
	    report.completed_stages != 5 || !report.experience_sequence ||
	    !report.model_checkpoint_id || !report.world_event_sequence ||
	    !report.browser_session_id || !report.browser_action_id ||
	    !report.coordinator_agent_id || !report.planner_agent_id ||
	    !report.verifier_agent_id || !report.ipc_channel_id ||
	    !report.ipc_message_id || !report.ipc_cancelled_message_id ||
	    !report.reflection_action_id || !report.reflection_authority_capability ||
	    !report.recovery_sequence ||
	    m76_deployment_gate(&request, &report) != 1)
		return fail("end-to-end completion", rc);
	printf("M76_LONG_HORIZON_GRAPH_OK stages=%u experience=%llu world=%llu browser=%llu\n",
	       report.completed_stages,
	       (unsigned long long)report.experience_sequence,
	       (unsigned long long)report.world_event_sequence,
	       (unsigned long long)report.browser_action_id);
	printf("M76_MULTI_AGENT_IPC_OK coordinator=%llu planner=%llu verifier=%llu channel=%llu\n",
	       (unsigned long long)report.coordinator_agent_id,
	       (unsigned long long)report.planner_agent_id,
	       (unsigned long long)report.verifier_agent_id,
	       (unsigned long long)report.ipc_channel_id);
	printf("M76_MONITORING_REFLECTION_OK action=%llu sequence=%llu\n",
	       (unsigned long long)report.reflection_action_id,
	       (unsigned long long)report.reflection_event_sequence);
	printf("M76_DEPLOYMENT_GATE_APPROVED_OK\n");
	remove_journals(failure_prefix);
	request.failure_stage = M76_FAILURE_BROWSER;
	memset(&report, 0, sizeof(report));
	rc = m76_run(&request, &report, failure_prefix);
	if (rc == 0 || report.state != M76_RECOVERED ||
	    report.recovery_state != 1 || report.deployment_gate_open ||
	    report.failure_stage != M76_FAILURE_BROWSER ||
	    !report.model_checkpoint_id)
		return fail("browser failure recovery", rc);
	printf("M76_FAILURE_RECOVERY_OK stage=%u recovery=%llu\n",
	       report.failure_stage,
	       (unsigned long long)report.recovery_sequence);
	printf("M76_SELFTEST_EXIT=0\n");
	return 0;
}
