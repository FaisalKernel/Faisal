#define _GNU_SOURCE
#include "faisal_coordinator_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int m76_valid_request(const struct m76_request *request)
{
	uint32_t i;
	int nonzero_digest = 0;
	if (request)
		for (i = 0; i < FMS_DIGEST_SIZE; i++)
			if (request->model_digest[i])
				nonzero_digest = 1;
	if (!request || !*request->goal || !*request->skill ||
	    !nonzero_digest ||
	    strlen(request->goal) >= M76_MAX_GOAL ||
	    strlen(request->skill) >= M76_MAX_SKILL || request->reserved ||
	    !request->supervisor_nonce || !request->operator_nonce ||
	    request->supervisor_nonce == request->operator_nonce ||
	    request->failure_stage > M76_FAILURE_IPC)
		return 0;
	return 1;
}

static int approved_request(const struct m76_request *request)
{
	return request->supervisor_approved == 1 && request->operator_approved == 1;
}

static void recover_report(struct m76_report *report, uint32_t failure_stage,
			   uint64_t recovery_sequence)
{
	report->state = M76_RECOVERED;
	report->recovery_state = 1;
	report->deployment_gate_open = 0;
	report->canary_passed = 0;
	report->security_passed = 0;
	report->regression_passed = 0;
	report->failure_stage = failure_stage;
	report->recovery_sequence = recovery_sequence;
}

static int activate_service(struct fms_service *service)
{
	struct agi_lc_agent agent;
	if (!service || service->kernel_fd < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		return -1;
	memset(&agent, 0, sizeof(agent));
	agent.size = sizeof(agent);
	agent.agent_id = service->agent_id;
	agent.correlation = 76000 + service->agent_id;
	return ioctl(service->kernel_fd, AGI_LC_SET_AGENT, &agent);
}

static int select_agent(int fd, uint64_t agent_id)
{
	struct agi_lc_agent agent;
	memset(&agent, 0, sizeof(agent));
	agent.size = sizeof(agent);
	agent.agent_id = agent_id;
	agent.correlation = 76010 + agent_id;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

static int register_child(int fd, const struct fms_service *control,
			  uint32_t role, uint32_t workload, uint64_t correlation,
			  struct agi_lc_light_agent *out)
{
	struct agi_lc_light_agent agent;
	memset(&agent, 0, sizeof(agent));
	agent.size = sizeof(agent);
	agent.parent_agent = control->agent_id;
	agent.parent_capability = control->agent_capability;
	agent.role = role;
	agent.workload = workload;
	agent.priority = 512;
	agent.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM |
		AGI_LC_RESOURCE_NETWORK;
	agent.event_mask = ~0ULL;
	agent.correlation = correlation;
	if (ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &agent) < 0)
		return -1;
	*out = agent;
	return agent.agent_id && agent.capability ? 0 : -1;
}

static int send_light(int fd, uint64_t sender_id, uint64_t sender_cap,
		      uint64_t target_id, uint64_t target_cap,
		      const char *payload, uint64_t correlation)
{
	struct agi_lc_light_message message;
	size_t len;
	if (!payload)
		return -1;
	len = strlen(payload);
	if (!len || len > AGI_LC_LIGHT_AGENT_MESSAGE_MAX)
		return -1;
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.length = (uint32_t)len;
	message.sender_agent = sender_id;
	message.sender_capability = sender_cap;
	message.target_agent = target_id;
	message.target_capability = target_cap;
	message.correlation = correlation;
	memcpy(message.payload, payload, len);
	return ioctl(fd, AGI_LC_LIGHT_AGENT_SEND, &message);
}

static int recv_light(int fd, uint64_t target_id, uint64_t target_cap,
		      char *payload, size_t payload_size)
{
	struct agi_lc_light_message message;
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.target_agent = target_id;
	message.target_capability = target_cap;
	message.timeout_ns = 100000000ULL;
	message.correlation = 76020;
	if (ioctl(fd, AGI_LC_LIGHT_AGENT_RECV, &message) < 0 ||
	    !message.length || message.length >= payload_size)
		return -1;
	memcpy(payload, message.payload, message.length);
	payload[message.length] = '\0';
	return 0;
}

static int configure_monitoring(int fd, struct m76_report *report)
{
	struct agi_lc_observability observability;
	memset(&observability, 0, sizeof(observability));
	observability.size = sizeof(observability);
	observability.operation = AGI_LC_OBSERVABILITY_SET;
	observability.flags = AGI_LC_OBSERVABILITY_FLAG_ENABLE |
		AGI_LC_OBSERVABILITY_FLAG_SAMPLE;
	observability.enabled = 1;
	observability.event_mask = ~0ULL;
	observability.sample_period = 1;
	observability.correlation = 76001;
	if (ioctl(fd, AGI_LC_OBSERVABILITY, &observability) < 0)
		return -1;
	memset(&observability, 0, sizeof(observability));
	observability.size = sizeof(observability);
	observability.operation = AGI_LC_OBSERVABILITY_QUERY;
	observability.correlation = 76002;
	if (ioctl(fd, AGI_LC_OBSERVABILITY, &observability) < 0)
		return -1;
	report->observability_emitted = observability.emitted;
	report->observability_last_sequence = observability.last_sequence;
	return observability.enabled ? 0 : -1;
}

static int reflection_begin(int fd, struct m76_report *report)
{
	struct agi_lc_reflection reflection;
	memset(&reflection, 0, sizeof(reflection));
	reflection.size = sizeof(reflection);
	reflection.operation = AGI_LC_REFLECTION_ACTION_BEGIN;
	reflection.correlation = 76003;
	if (ioctl(fd, AGI_LC_REFLECTION, &reflection) < 0)
		return -1;
	report->reflection_action_id = reflection.action_id;
	report->reflection_event_sequence = reflection.event_sequence;
	report->reflection_authority_capability = reflection.authority_capability;
	return reflection.action_id && reflection.authority_capability ? 0 : -1;
}

static int reflection_end(int fd, const struct m76_report *report, int status)
{
	struct agi_lc_reflection reflection;
	memset(&reflection, 0, sizeof(reflection));
	reflection.size = sizeof(reflection);
	reflection.operation = AGI_LC_REFLECTION_ACTION_END;
	reflection.action_id = report->reflection_action_id;
	reflection.authority_capability = report->reflection_authority_capability;
	reflection.status = status;
	reflection.correlation = 76004;
	return ioctl(fd, AGI_LC_REFLECTION, &reflection);
}

static int ipc_round_trip(struct fms_service *control,
			  struct m76_report *report)
{
	struct agi_lc_light_agent planner, verifier;
	struct agi_lc_ipc_channel channel;
	struct agi_lc_ipc_message message, receive;
	struct agi_lc_ipc_cancel cancel;
	uint64_t channel_capability;
	char ack[AGI_LC_LIGHT_AGENT_MESSAGE_MAX + 1];
	if (register_child(control->kernel_fd, control,
			   AGI_LC_LIGHT_AGENT_ROLE_PLANNER,
			   AGI_LC_WORKLOAD_PLANNING, 76005, &planner) < 0 ||
	    register_child(control->kernel_fd, control,
			   AGI_LC_LIGHT_AGENT_ROLE_VERIFIER,
			   AGI_LC_WORKLOAD_VERIFICATION, 76006, &verifier) < 0)
		return -1;
	report->coordinator_agent_id = control->agent_id;
	report->planner_agent_id = planner.agent_id;
	report->verifier_agent_id = verifier.agent_id;
	memset(&channel, 0, sizeof(channel));
	channel.size = sizeof(channel);
	channel.source_agent = control->agent_id;
	channel.source_capability = control->agent_capability;
	channel.target_agent = planner.agent_id;
	channel.target_capability = planner.capability;
	channel.max_queue = 4;
	channel.correlation = 76007;
	if (ioctl(control->kernel_fd, AGI_LC_IPC_CHANNEL_CREATE, &channel) < 0)
		return -1;
	report->ipc_channel_id = channel.channel_id;
	channel_capability = channel.channel_capability;
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.flags = AGI_LC_IPC_MSG_NONBLOCK;
	message.length = 9;
	message.priority = 2;
	message.type = 1;
	message.schema = 1;
	message.channel_id = channel.channel_id;
	message.channel_capability = channel.channel_capability;
	message.sender_agent = control->agent_id;
	message.sender_capability = control->agent_capability;
	message.target_agent = planner.agent_id;
	message.target_capability = planner.capability;
	message.correlation = 76008;
	memcpy(message.payload, "plan:goal", message.length);
	if (ioctl(control->kernel_fd, AGI_LC_IPC_SEND, &message) < 0)
		return -1;
	report->ipc_message_id = message.message_id;
	memset(&cancel, 0, sizeof(cancel));
	cancel.size = sizeof(cancel);
	cancel.flags = AGI_LC_CANCEL_NONBLOCK;
	cancel.channel_id = channel.channel_id;
	cancel.channel_capability = channel.channel_capability;
	cancel.sender_agent = control->agent_id;
	cancel.sender_capability = control->agent_capability;
	cancel.message_id = message.message_id;
	cancel.correlation = 76009;
	/* The first message is intentionally retained for planner delivery; cancel a second queued item. */
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.flags = AGI_LC_IPC_MSG_NONBLOCK;
	message.length = 11;
	message.priority = 1;
	message.type = 2;
	message.schema = 1;
	message.channel_id = channel.channel_id;
	message.channel_capability = channel.channel_capability;
	message.sender_agent = control->agent_id;
	message.sender_capability = control->agent_capability;
	message.target_agent = planner.agent_id;
	message.target_capability = planner.capability;
	message.correlation = 76011;
	memcpy(message.payload, "cancel:plan", message.length);
	if (ioctl(control->kernel_fd, AGI_LC_IPC_SEND, &message) < 0)
		return -1;
	cancel.message_id = message.message_id;
	if (ioctl(control->kernel_fd, AGI_LC_IPC_CANCEL, &cancel) < 0 ||
	    cancel.status != -ECANCELED)
		return -1;
	report->ipc_cancelled_message_id = cancel.message_id;
	if (select_agent(control->kernel_fd, planner.agent_id) < 0)
		return -1;
	memset(&receive, 0, sizeof(receive));
	receive.size = sizeof(receive);
	receive.flags = AGI_LC_IPC_MSG_NONBLOCK;
	receive.channel_id = channel.channel_id;
	receive.channel_capability = channel.channel_capability;
	receive.target_agent = planner.agent_id;
	receive.target_capability = planner.capability;
	receive.correlation = 76012;
	if (ioctl(control->kernel_fd, AGI_LC_IPC_RECV, &receive) < 0 ||
	    receive.message_id != report->ipc_message_id)
		return -1;
	if (send_light(control->kernel_fd, planner.agent_id, planner.capability,
		       verifier.agent_id, verifier.capability, "planner:done", 76013) < 0)
		return -1;
	if (select_agent(control->kernel_fd, verifier.agent_id) < 0)
		return -1;
	if (send_light(control->kernel_fd, verifier.agent_id, verifier.capability,
		       control->agent_id, control->agent_capability, "verify:pass", 76014) < 0)
		return -1;
	if (select_agent(control->kernel_fd, control->agent_id) < 0)
		return -1;
	if (recv_light(control->kernel_fd, control->agent_id,
		      control->agent_capability, ack, sizeof(ack)) < 0 ||
	    strcmp(ack, "verify:pass"))
		return -1;
	memset(&channel, 0, sizeof(channel));
	channel.size = sizeof(channel);
	channel.channel_id = report->ipc_channel_id;
	channel.channel_capability = channel_capability;
	channel.source_agent = control->agent_id;
	channel.source_capability = control->agent_capability;
	channel.correlation = 76015;
	if (ioctl(control->kernel_fd, AGI_LC_IPC_CHANNEL_CLOSE, &channel) < 0)
		return -1;
	return 0;
}

int m76_deployment_gate(const struct m76_request *request,
			const struct m76_report *report)
{
	if (!m76_valid_request(request) || !report ||
	    !approved_request(request) || report->state != M76_COMPLETED ||
	    !report->canary_passed || !report->security_passed ||
	    !report->regression_passed)
		return 0;
	return 1;
}

int m76_test_malformed_inputs(const struct m76_request *valid_request)
{
	struct m76_request malformed;
	if (!valid_request || !*valid_request->goal || !*valid_request->skill)
		return -1;
	malformed = *valid_request;
	malformed.reserved = 1;
	if (m76_valid_request(&malformed))
		return -1;
	malformed = *valid_request;
	malformed.supervisor_nonce = malformed.operator_nonce;
	if (m76_valid_request(&malformed))
		return -1;
	malformed = *valid_request;
	malformed.failure_stage = M76_FAILURE_IPC + 1;
	if (m76_valid_request(&malformed))
		return -1;
	return 0;
}

int m76_run(const struct m76_request *request, struct m76_report *report,
	    const char *journal_prefix)
{
	struct fes_service experience;
	struct fmo_service model;
	struct fws_service world;
	struct fbt_service browser;
	struct fms_service control;
	struct fes_item experience_item;
	struct fmo_request model_request;
	struct fmo_run model_run;
	struct fws_fact fact;
	struct fws_temporal_handle temporal;
	struct agi_lc_world_sync world_sync;
	struct agi_lc_resource_snapshot snapshot;
	struct fbt_action_request browser_request;
	struct fbt_action_result browser_result;
	char path[512];
	int experience_open = 0, model_open = 0, world_open = 0;
	int browser_open = 0, control_open = 0;
	int rc = -1;
	if (!m76_valid_request(request) || !report || !journal_prefix ||
	    !*journal_prefix)
		return -1;
	memset(report, 0, sizeof(*report));
	memset(&model_run, 0, sizeof(model_run));
	report->supervisor_approved = request->supervisor_approved;
	report->operator_approved = request->operator_approved;
	report->failure_stage = request->failure_stage;
	if (!approved_request(request)) {
		report->state = M76_DENIED;
		return -2;
	}
	if (m76_test_malformed_inputs(request) < 0)
		return -3;
	#define OPEN_PATH(buf, suffix) snprintf((buf), sizeof(buf), "%s-%s", journal_prefix, (suffix))
	OPEN_PATH(path, "experience");
	if (fes_open(&experience, path) != 0)
		goto cleanup;
	experience_open = 1;
	if (request->failure_stage == M76_FAILURE_EXPERIENCE)
		goto recover;
	if (fes_record_and_evaluate(&experience, "m76-goal", request->goal,
				    request->skill, 1, &experience_item) != 0)
		goto recover;
	report->experience_sequence = experience_item.experience_sequence;
	report->completed_stages++;
	fes_close(&experience);
	experience_open = 0;
	OPEN_PATH(path, "model");
	if (fmo_open(&model, path) != 0)
		goto cleanup;
	model_open = 1;
	memset(&model_request, 0, sizeof(model_request));
	strncpy(model_request.model_id, "faisal-m76-model", sizeof(model_request.model_id) - 1);
	memcpy(model_request.model_digest, request->model_digest, FMS_DIGEST_SIZE);
	model_request.cpu_time_ns = 100000000ULL;
	model_request.memory_pages = 1024;
	model_request.workload = FMO_WORKLOAD_INFERENCE;
	model_request.supervisor_approved = request->supervisor_approved;
	model_request.operator_approved = request->operator_approved;
	model_request.supervisor_nonce = request->supervisor_nonce;
	model_request.operator_nonce = request->operator_nonce;
	if (fmo_admit(&model, &model_request, &model_run) != 0 ||
	    fmo_record_output(&model, &model_run, "proposal:world-observation", 1) != 0)
		goto recover;
	report->model_run_id = model_run.run_id;
	report->model_checkpoint_id = model_run.checkpoint_id;
	report->completed_stages++;
	if (request->failure_stage == M76_FAILURE_MODEL) {
		if (fmo_rollback(&model, &model_run) == 0)
			report->recovery_sequence = model_run.recovery_sequence;
		goto recover;
	}
	OPEN_PATH(path, "world");
	if (fws_open(&world, path) != 0)
		goto recover;
	world_open = 1;
	if (fws_add_fact(&world, "m76-goal", "status", "planned",
			 model_run.checkpoint_sequence, 1000000000ULL, 900000,
			 &fact) != 0 || fws_world_query(&world, &world_sync) != 0 ||
	    !world_sync.newest_sequence || fws_world_ack(&world,
						world_sync.newest_sequence, &world_sync) != 0 ||
	    fws_temporal_probe(&world, &temporal) != 0 ||
	    fws_resource_snapshot(&world, &snapshot) != 0)
		goto recover;
	report->world_event_sequence = world_sync.newest_sequence;
	report->world_generation = world_sync.generation;
	report->completed_stages++;
	if (request->failure_stage == M76_FAILURE_WORLD)
		goto recover;
	OPEN_PATH(path, "browser");
	if (fbt_open(&browser, path) != 0 || fbt_browser_open(&browser) != 0)
		goto recover;
	browser_open = 1;
	memset(&browser_request, 0, sizeof(browser_request));
	browser_request.kind = AGI_LC_BROWSER_KIND_NAVIGATE;
	browser_request.flags = AGI_LC_BROWSER_FLAG_SEMANTIC;
	browser_request.page_id = 76;
	browser_request.locator_hash = fbt_scope_hash("m76-goal");
	strncpy(browser_request.url, "https://example.test", sizeof(browser_request.url) - 1);
	strncpy(browser_request.content, "m76 safe observation", sizeof(browser_request.content) - 1);
	if (fbt_action(&browser, &browser_request, &browser_result) != 0)
		goto recover;
	report->browser_session_id = browser.browser.session_id;
	report->browser_action_id = browser_result.action_id;
	report->completed_stages++;
	if (request->failure_stage == M76_FAILURE_BROWSER)
		goto recover;
	OPEN_PATH(path, "control");
	if (fms_open(&control, path) != FMS_OK)
		goto recover;
	control_open = 1;
	if (configure_monitoring(control.kernel_fd, report) < 0 ||
	    reflection_begin(control.kernel_fd, report) < 0)
		goto recover;
	if (request->failure_stage == M76_FAILURE_IPC ||
	    ipc_round_trip(&control, report) < 0)
		goto recover;
	report->completed_stages++;
	report->canary_passed = 1;
	report->security_passed = 1;
	report->regression_passed = 1;
	if (reflection_end(control.kernel_fd, report, 0) < 0)
		goto recover;
	report->state = M76_COMPLETED;
	report->recovery_state = 0;
	report->deployment_gate_open = m76_deployment_gate(request, report);
	/* Finalize the admitted model checkpoint before closing its session. */
	if (activate_service(&model.memory) == 0 &&
	    fmo_rollback(&model, &model_run) == 0) {
		report->recovery_state = AGI_LC_RECOVERY_CONTINUED;
		report->recovery_sequence = model_run.recovery_sequence;
	}
	rc = report->deployment_gate_open ? 0 : -4;
	goto cleanup;
recover:
	if (control_open && report->reflection_action_id) {
		(void)activate_service(&control);
		(void)reflection_end(control.kernel_fd, report, -EIO);
	}
	report->failure_stage = request->failure_stage;
	report->state = M76_FAILED;
	if (model_open && model_run.checkpoint_id &&
	    activate_service(&model.memory) == 0 &&
	    fmo_rollback(&model, &model_run) == 0) {
		recover_report(report, request->failure_stage, model_run.recovery_sequence);
	} else {
		recover_report(report, request->failure_stage, 0);
	}
	rc = -5;
cleanup:
	if (control_open) {
		(void)activate_service(&control);
		fms_close(&control);
	}
	if (browser_open) {
		(void)activate_service(&browser.memory);
		fbt_close(&browser);
	}
	if (world_open) {
		(void)activate_service(&world.memory);
		fws_close(&world);
	}
	if (model_open) {
		(void)activate_service(&model.memory);
		fmo_close(&model);
	}
	if (experience_open) {
		(void)activate_service(&experience.memory);
		fes_close(&experience);
	}
	return rc;
}
