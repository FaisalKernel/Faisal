#include "../../faisal-agent-runtime/faisal_agent_runtime.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int cases_run;
static unsigned int mutation_rejections;

static void expect_code(const char *name, int actual, int expected)
{
	++cases_run;
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual, expected);
		exit(1);
	}
}

static void expect_true(const char *name, int condition)
{
	++cases_run;
	if (!condition) {
		fprintf(stderr, "FAIL %s\n", name);
		exit(1);
	}
}

static void fill_digest(uint8_t digest[FAR_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FAR_DIGEST_SIZE);
}

static struct far_policy policy(void)
{
	struct far_policy result;

	memset(&result, 0, sizeof(result));
	result.budget_policy.current_time_ns = 1000U;
	result.budget_policy.max_deadline_horizon_ns = 1000000U;
	result.budget_policy.minimum_priority = 1U;
	result.budget_policy.require_authority = 1U;
	result.budget_policy.require_verified_input = 1U;
	result.budget_policy.maximum.cpu_ns = 1000000U;
	result.budget_policy.maximum.memory_bytes = 1000000U;
	result.budget_policy.maximum.gpu_ns = 1000000U;
	result.budget_policy.maximum.npu_ns = 1000000U;
	result.budget_policy.maximum.network_bytes = 1000000U;
	result.budget_policy.maximum.storage_bytes = 1000000U;
	result.budget_policy.maximum.cost_micro = 1000000U;
	result.budget_policy.maximum.energy_uj = 1000000U;
	result.require_tool_authority = 1U;
	result.require_message_authority = 1U;
	result.require_verified_input = 1U;
	return result;
}

static struct far_objective objective_request(void)
{
	struct far_objective request;

	memset(&request, 0, sizeof(request));
	request.tenant_id = 7U;
	request.trace_id = 9001U;
	request.task_generation = 3U;
	request.session_generation = 4U;
	request.world_generation = 5U;
	request.model_generation = 6U;
	request.request_sequence = 1U;
	request.created_at_ns = 100U;
	request.deadline_ns = 100000U;
	request.required_capability_mask = 0x4U;
	request.priority = 50U;
	request.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
	request.budget.cpu_ns = 1000U;
	request.budget.memory_bytes = 2000U;
	request.budget.gpu_ns = 3000U;
	request.budget.npu_ns = 4000U;
	request.budget.network_bytes = 5000U;
	request.budget.storage_bytes = 6000U;
	request.budget.cost_micro = 7000U;
	request.budget.energy_uj = 8000U;
	fill_digest(request.objective_digest, 0x21U);
	fill_digest(request.provenance_digest, 0x22U);
	strcpy(request.name, "research-objective");
	return request;
}

int main(void)
{
	char path[128];
	struct far_service service;
	struct far_service recovered;
	struct far_agent agent;
	struct far_objective request = objective_request();
	struct far_objective admitted;
	struct far_objective running;
	struct far_objective queued;
	struct far_objective completed;
	struct far_objective replayed;
	struct far_checkpoint checkpoint;
	struct far_checkpoint tampered_checkpoint;
	struct far_tool_request tool;
	struct far_message message;
	struct far_journal_attestation attestation;
	struct far_policy service_policy = policy();
	uint8_t identity[FAR_DIGEST_SIZE];
	uint8_t digest[FAR_DIGEST_SIZE];
	snprintf(path, sizeof(path), "/tmp/faisal-agent-runtime-%ld.journal", (long)getpid());
	unlink(path);
	fill_digest(identity, 0x11U);
	fill_digest(digest, 0x31U);
	expect_code("open", far_open(&service, path, &service_policy), FAR_OK);
	expect_code("register-agent", far_register_agent(&service, 7U, 0x7U, 900000U,
						 identity, "planner", &agent), FAR_OK);
	expect_true("agent-ready", agent.state == FAR_AGENT_READY && agent.generation == 1U);

	request.agent_id = agent.agent_id;
	expect_code("admit", far_admit_objective(&service, &request, &admitted), FAR_OK);
	expect_true("admitted-queued", admitted.objective_id != 0U &&
			 admitted.state == FAR_OBJECTIVE_QUEUED);
	expect_code("dispatch", far_dispatch(&service, admitted.objective_id, 110U, &running), FAR_OK);
	expect_true("running", running.state == FAR_OBJECTIVE_RUNNING);

	memset(&tool, 0, sizeof(tool));
	tool.request_id = 1U;
	tool.objective_id = running.objective_id;
	tool.agent_id = agent.agent_id;
	tool.agent_generation = agent.generation;
	tool.capability = 0x4U;
	tool.authority_lease_id = 44U;
	tool.sequence = 1U;
	tool.issued_at_ns = 120U;
	tool.deadline_ns = 1000U;
	tool.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
	fill_digest(tool.input_digest, 0x41U);
	fill_digest(tool.provenance_digest, 0x42U);
	strcpy(tool.tool_name, "filesystem.read");
	expect_code("tool-authorized", far_request_tool(&service, &tool), FAR_OK);
	tool.flags = FAR_FLAG_VERIFIED_INPUT;
	expect_code("tool-authority-rejected", far_request_tool(&service, &tool), FAR_ERR_AUTHORITY);
	++mutation_rejections;
	tool.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
	tool.capability = 0x80U;
	expect_code("tool-capability-rejected", far_request_tool(&service, &tool), FAR_ERR_CAPABILITY);
	++mutation_rejections;
	tool.capability = 0x4U;

	memset(&message, 0, sizeof(message));
	message.message_id = 1U;
	message.objective_id = running.objective_id;
	message.from_agent_id = agent.agent_id;
	message.to_agent_id = agent.agent_id;
	message.from_generation = agent.generation;
	message.sequence = 1U;
	message.observed_at_ns = 121U;
	message.flags = FAR_FLAG_AUTHORITY_GRANTED;
	fill_digest(message.payload_digest, 0x51U);
	expect_code("message-authorized", far_send_message(&service, &message), FAR_OK);
	message.flags = 0U;
	expect_code("message-authority-rejected", far_send_message(&service, &message), FAR_ERR_AUTHORITY);
	++mutation_rejections;

	fill_digest(digest, 0x61U);
	expect_code("checkpoint", far_checkpoint(&service, running.objective_id, 130U,
					 digest, digest, digest, &checkpoint), FAR_OK);
	expect_true("checkpoint-verified", checkpoint.verified == 1U && checkpoint.sequence == 1U);
	tampered_checkpoint = checkpoint;
	tampered_checkpoint.checkpoint_digest[0] ^= 0xffU;
	expect_code("tampered-checkpoint-rejected", far_recover(&service, running.objective_id,
							 140U, &tampered_checkpoint, &queued), FAR_ERR_CHECKPOINT);
	++mutation_rejections;
	expect_code("recover", far_recover(&service, running.objective_id, 140U,
					 &checkpoint, &queued), FAR_OK);
	expect_true("recovery-queued", queued.state == FAR_OBJECTIVE_QUEUED &&
			 (queued.flags & FAR_FLAG_RECOVERY) != 0U);
	expect_code("redispatch", far_dispatch(&service, running.objective_id, 150U, &running), FAR_OK);
	expect_code("complete", far_complete(&service, running.objective_id, 160U, digest, &completed), FAR_OK);
	expect_true("completed", completed.state == FAR_OBJECTIVE_SUCCEEDED);
	expect_code("duplicate-completion-rejected", far_complete(&service, running.objective_id,
							 170U, digest, &completed), FAR_ERR_STATE);
	++mutation_rejections;
	request = objective_request();
	request.agent_id = agent.agent_id;
	request.flags = FAR_FLAG_MODEL_PROPOSAL | FAR_FLAG_VERIFIED_INPUT;
	expect_code("model-proposal-without-authority-rejected",
			far_admit_objective(&service, &request, &admitted), FAR_ERR_AUTHORITY);
	++mutation_rejections;
	request = objective_request();
	request.agent_id = agent.agent_id;
	request.budget.cpu_ns = UINT64_MAX;
	expect_code("budget-overflow-limit-rejected",
			far_admit_objective(&service, &request, &admitted), FAR_ERR_BUDGET);
	++mutation_rejections;
	fill_digest(digest, 0x71U);
	expect_code("record-anomaly", far_record_anomaly(&service, agent.agent_id,
						 completed.objective_id, 175U, 9U, 0x1U,
						 digest, &agent, &completed), FAR_OK);
	expect_true("agent-quarantined", agent.state == FAR_AGENT_QUARANTINED &&
			 agent.generation == 2U);
	expect_true("objective-quarantined", completed.state == FAR_OBJECTIVE_QUARANTINED &&
			 completed.anomaly_count == 1U);
	tool.agent_generation = 1U;
	tool.flags = FAR_FLAG_AUTHORITY_GRANTED | FAR_FLAG_VERIFIED_INPUT;
	tool.capability = 0x4U;
	expect_code("stale-tool-after-quarantine", far_request_tool(&service, &tool),
			FAR_ERR_GENERATION);
	++mutation_rejections;

	expect_code("journal-query", far_query_journal(&service, &attestation), FAR_OK);
	expect_true("journal-events", attestation.last_sequence >= 7U &&
			 attestation.record_count == attestation.last_sequence);
	far_close(&service);

	expect_code("reopen-replay", far_open(&recovered, path, &service_policy), FAR_OK);
	expect_code("replay-objective", far_query_objective(&recovered, completed.objective_id,
							 &replayed), FAR_OK);
	expect_true("replayed-final-quarantine", replayed.state == FAR_OBJECTIVE_QUARANTINED);
	expect_code("replay-agent", far_query_agent(&recovered, agent.agent_id, &agent), FAR_OK);
	expect_true("replayed-agent", agent.agent_id != 0U &&
			 agent.state == FAR_AGENT_QUARANTINED && agent.generation == 2U);
	expect_code("replay-objective-quarantine", far_query_objective(&recovered,
							 completed.objective_id, &replayed), FAR_OK);
	expect_true("replayed-objective-quarantined", replayed.state == FAR_OBJECTIVE_QUARANTINED);
	expect_code("replay-journal", far_query_journal(&recovered, &attestation), FAR_OK);
	expect_true("replay-chain", attestation.last_sequence >= 8U && attestation.anomaly_count == 1U);
	far_close(&recovered);
	unlink(path);
	printf("M241_AGENT_RUNTIME_SELFTEST_EXIT=0 cases=%u mutation_rejections=%u\n",
	       cases_run, mutation_rejections);
	return 0;
}
