#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../faisal-tool/faisal_tool_service.h"

static int fail(const char *what, int result)
{
	fprintf(stderr, "M99_FAIL:%s result=%d errno=%s\n", what, result,
		strerror(errno));
	return 1;
}

static void fill_digest(uint8_t digest[M99_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, M99_DIGEST_SIZE);
}

static int acquire_kernel_authority(struct m99_service *service,
					struct fts_authority_ref *authority,
					uint64_t correlation)
{
	struct agi_lc_capability_grant grant = {
		.size = sizeof(grant),
		.rights = AGI_LC_CAP_PRIVILEGED_API,
		.correlation = correlation,
	};
	struct agi_lc_intent_lease lease = {
		.size = sizeof(lease),
		.operation = AGI_LC_INTENT_LEASE_ACQUIRE,
		.flags = AGI_LC_INTENT_LEASE_FLAG_SINGLE_USE |
			AGI_LC_INTENT_LEASE_FLAG_REVOKE_ON_CLOSE,
		.operation_class = AGI_LC_INTENT_OP_TOOL,
		.resource_mask = AGI_LC_RESOURCE_CPU,
		.expires_ns = AGI_LC_INTENT_MAX_TTL_NS,
		.max_uses = 1,
		.correlation = correlation + 1,
	};

	grant.agent_id = service->mission.tasks.agent_id;
	grant.agent_capability = service->mission.tasks.agent_capability;
	if (ioctl(service->mission.tasks.kernel_fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0 ||
	    !grant.grant_id || !grant.capability)
		return FTS_ERR_KERNEL;
	lease.grant_id = grant.grant_id;
	lease.grant_capability = grant.capability;
	lease.agent_id = service->mission.tasks.agent_id;
	lease.agent_capability = service->mission.tasks.agent_capability;
	lease.intent_digest[0] = 0x99;
	lease.intent_digest[1] = (uint8_t)correlation;
	if (ioctl(service->mission.tasks.kernel_fd, AGI_LC_INTENT_LEASE, &lease) < 0 ||
	    !lease.lease_id || lease.status != AGI_LC_INTENT_STATUS_ACTIVE)
		return FTS_ERR_KERNEL;
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = lease.lease_id;
	authority->grant_id = lease.grant_id;
	authority->grant_capability = lease.grant_capability;
	authority->agent_id = lease.agent_id;
	authority->agent_capability = lease.agent_capability;
	authority->lineage_id = lease.lineage_id;
	authority->scope_id = lease.scope_id;
	authority->generation = lease.generation;
	authority->flags = lease.flags;
	authority->operation_class = lease.operation_class;
	authority->resource_mask = lease.resource_mask;
	memcpy(authority->intent_digest, lease.intent_digest,
	       sizeof(authority->intent_digest));
	return FTS_OK;
}

static void fill_host_authority(struct m99_service *service,
				struct fts_authority_ref *authority,
				uint64_t lease_id)
{
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = lease_id;
	authority->grant_id = lease_id + 1;
	authority->grant_capability = lease_id + 2;
	authority->agent_id = service->mission.tasks.agent_id ?
		service->mission.tasks.agent_id : 4;
	authority->agent_capability = service->mission.tasks.agent_capability ?
		service->mission.tasks.agent_capability : 5;
	authority->lineage_id = lease_id + 3;
	authority->generation = 1;
	authority->operation_class = AGI_LC_INTENT_OP_TOOL;
	authority->resource_mask = AGI_LC_RESOURCE_CPU;
	authority->intent_digest[0] = 0x99;
	authority->intent_digest[1] = (uint8_t)lease_id;
}

static int get_authority(struct m99_service *service,
			 struct fts_authority_ref *authority, uint64_t correlation,
			 uint64_t host_lease_id)
{
	if (service->mission.tasks.kernel_fd >= 0)
		return acquire_kernel_authority(service, authority, correlation);
	fill_host_authority(service, authority, host_lease_id);
	return FTS_OK;
}

static int prepare_mission(struct m99_service *service, uint64_t now_ns,
				   uint64_t objective_id,
				   const struct fts_authority_ref *authority,
				   struct m98_mission *out)
{
	struct m98_policy policy = {
		.deadline_ns = 1000000000ULL,
		.cpu_budget_ns = 1000000,
		.money_budget_micro = 1000,
		.max_steps = 4,
		.max_retries = 2,
		.risk_ceiling = 20,
		.supervisor_approved = 1,
		.operator_approved = 1,
		.supervisor_nonce = 9911,
		.operator_nonce = 9912,
	};
	struct m98_mission mission;
	uint8_t plan[M99_DIGEST_SIZE];
	uint8_t model[M99_DIGEST_SIZE];
	uint8_t action[M99_DIGEST_SIZE];
	int result;

	fill_digest(plan, 0x41);
	fill_digest(model, 0x42);
	fill_digest(action, 0x43);
	result = m98_create(&service->mission, "execute registered verified tool", &policy,
			now_ns, &mission);
	if (result != M98_OK)
		return result;
	result = m98_observe(&service->mission, mission.mission_id, now_ns + 1, 1,
			M98_TRIGGER_MANUAL, plan, model, action,
			"tool execution observation", &mission);
	if (result != M98_OK)
		return result;
	result = m98_propose(&service->mission, mission.mission_id, now_ns + 2,
			authority, plan, model, action, 10, AGI_LC_RESOURCE_CPU, 100,
			"registered tool proposal", "invoke registered safe fixture", &mission);
	if (result != M98_OK)
		return result;
	*out = mission;
	(void)objective_id;
	return M99_OK;
}

struct invocation_worker {
	const struct m99_service *service;
	uint64_t invocation_id;
	int failed;
};

static void *invocation_query_worker(void *opaque)
{
	struct invocation_worker *worker = opaque;
	unsigned int index;

	for (index = 0; index < 128; index++) {
		struct m99_invocation invocation;

		if (m99_invocation_query(worker->service, worker->invocation_id,
					 &invocation) != M99_OK) {
			worker->failed = 1;
			break;
		}
	}
	return NULL;
}

int main(int argc, char **argv)
{
	char path[] = "/tmp/faisal-m99-tools-XXXXXX";
	struct m99_service service;
	struct m99_tool_spec revocable_tool;
	struct m99_tool_spec verified_tool;
	struct m99_tool_spec high_risk_tool;
	struct m99_tool_spec query_tool;
	struct m99_invocation invocation;
	struct m99_invocation query_invocation;
	struct m98_mission revocation_mission;
	struct m98_mission happy_mission;
	struct fts_authority_ref authority;
	struct fts_authority_ref second_authority;
	struct fts_authority_ref third_authority;
	struct fts_authority_ref invalid_authority;
	uint8_t implementation_digest[M99_DIGEST_SIZE];
	uint8_t input_digest[M99_DIGEST_SIZE];
	uint8_t result_digest[M99_DIGEST_SIZE];
	int fd;
	int require_kernel = argc > 1 && strcmp(argv[1], "--require-kernel") == 0;
	int result;

	fd = mkstemp(path);
	if (fd < 0)
		return fail("mkstemp", M99_ERR_IO);
	close(fd);
	unlink(path);
	result = m99_open(&service, path, require_kernel);
	if (result != M99_OK)
		return fail("service-open", result);
	printf("M99_TOOL_SERVICE_OPEN_OK kernel=%d\n",
	       service.mission.tasks.kernel_fd >= 0);
	result = get_authority(&service, &authority, 99001, 99001);
	if (result != FTS_OK)
		return fail("authority-acquire", result);
	printf("M99_AUTHORITY_REFERENCE_OK lease=%llu\n",
	       (unsigned long long)authority.lease_id);
	fill_digest(implementation_digest, 0xa1);
	fill_digest(input_digest, 0xb2);
	fill_digest(result_digest, 0xc3);
	result = m99_register(&service, "revocable-safe-fixture",
			"non-privileged deterministic test fixture", AGI_LC_INTENT_OP_TOOL,
			AGI_LC_RESOURCE_CPU, 10,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION, 100, 10,
			implementation_digest, &revocable_tool);
	if (result != M99_OK)
		return fail("register-revocable", result);
	printf("M99_TOOL_REGISTER_OK id=%llu generation=%llu\n",
	       (unsigned long long)revocable_tool.tool_id,
	       (unsigned long long)revocable_tool.registry_generation);
	result = m99_register(&service, "revocable-safe-fixture",
			"duplicate must be rejected", AGI_LC_INTENT_OP_TOOL,
			AGI_LC_RESOURCE_CPU, 10, 0, 100, 10,
			implementation_digest, &query_tool);
	if (result != M99_ERR_CONFLICT)
		return fail("duplicate-tool-rejection", result);
	printf("M99_DUPLICATE_TOOL_REJECTED_OK\n");
	result = prepare_mission(&service, 100, 1, &authority, &revocation_mission);
	if (result != M99_OK)
		return fail("prepare-revocation-mission", result);
	memset(&invalid_authority, 0, sizeof(invalid_authority));
	result = m99_admit(&service, revocation_mission.mission_id, 110,
			&invalid_authority, revocable_tool.tool_id, input_digest, &invocation);
	if (result != M99_ERR_AUTHORITY)
		return fail("model-authority-separation", result);
	printf("M99_MODEL_OUTPUT_NOT_AUTHORITY_OK\n");
	result = m99_admit(&service, revocation_mission.mission_id, 111,
			&authority, revocable_tool.tool_id, input_digest, &invocation);
	if (result != M99_OK || invocation.state != M99_INVOCATION_ADMITTED)
		return fail("admit-revocable", result);
	printf("M99_INVOCATION_ADMITTED_OK id=%llu\n",
	       (unsigned long long)invocation.invocation_id);
	result = m99_revoke(&service, revocable_tool.tool_id, 112,
			"fixture revoked before execution", &revocable_tool);
	if (result != M99_OK || revocable_tool.state != M99_TOOL_REVOKED)
		return fail("tool-revoke", result);
	printf("M99_TOOL_REVOCATION_OK generation=%llu\n",
	       (unsigned long long)revocable_tool.revocation_generation);
	result = m99_execute(&service, invocation.invocation_id, 113, &query_invocation);
	if (result != M99_ERR_REVOKED || query_invocation.state != M99_INVOCATION_REVOKED)
		return fail("revoked-execution-denial", result);
	printf("M99_REVOKED_EXECUTION_DENIED_OK\n");

	result = get_authority(&service, &second_authority, 99002, 99002);
	if (result != FTS_OK)
		return fail("second-authority-acquire", result);
	result = m99_register(&service, "verified-safe-fixture",
			"deterministic verified test fixture", AGI_LC_INTENT_OP_TOOL,
			AGI_LC_RESOURCE_CPU, 10,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION |
			M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL,
			100, 10, implementation_digest, &verified_tool);
	if (result != M99_OK)
		return fail("register-verified", result);
	result = m99_register(&service, "high-risk-fixture",
			"policy denial fixture", AGI_LC_INTENT_OP_TOOL,
			AGI_LC_RESOURCE_CPU, 90, M99_TOOL_FLAG_REQUIRES_OBSERVATION,
			100, 10, implementation_digest, &high_risk_tool);
	if (result != M99_OK)
		return fail("register-high-risk", result);
	result = prepare_mission(&service, 200, 2, &second_authority, &happy_mission);
	if (result != M99_OK)
		return fail("prepare-happy-mission", result);
	result = m99_admit(&service, happy_mission.mission_id, 205,
			&second_authority, high_risk_tool.tool_id, input_digest, &query_invocation);
	if (result != M99_ERR_POLICY)
		return fail("high-risk-policy-denial", result);
	printf("M99_HIGH_RISK_POLICY_DENIAL_OK\n");
	result = m99_admit(&service, happy_mission.mission_id, 210,
			&second_authority, verified_tool.tool_id, input_digest, &invocation);
	if (result != M99_OK)
		return fail("admit-verified", result);
	printf("M99_RISK_COST_APPROVAL_ADMITTED_OK\n");
	result = m99_execute(&service, invocation.invocation_id, 211, &invocation);
	if (result != M99_OK || invocation.state != M99_INVOCATION_EXECUTING)
		return fail("execute-verified", result);
	printf("M99_BROKER_EXECUTION_STARTED_OK\n");
	result = m99_complete(&service, invocation.invocation_id, 212, 0, 1,
			result_digest, "verified fixture result", &invocation);
	if (result != M99_OK || invocation.state != M99_INVOCATION_COMPLETED)
		return fail("complete-verified", result);
	printf("M99_VERIFIED_COMPLETION_COMMITTED_OK mission=%llu\n",
	       (unsigned long long)invocation.mission_id);
	result = m99_invocation_query(&service, invocation.invocation_id,
			&query_invocation);
	if (result != M99_OK || query_invocation.state != M99_INVOCATION_COMPLETED)
		return fail("completed-query", result);
	printf("M99_INVOCATION_QUERY_OK\n");
	{
		pthread_t workers[4];
		struct invocation_worker queries[4];
		unsigned int index;

		memset(queries, 0, sizeof(queries));
		for (index = 0; index < 4; index++) {
			queries[index].service = &service;
			queries[index].invocation_id = invocation.invocation_id;
			if (pthread_create(&workers[index], NULL, invocation_query_worker,
					   &queries[index]) != 0)
				return fail("concurrent-query-create", M99_ERR_STATE);
		}
		for (index = 0; index < 4; index++)
			if (pthread_join(workers[index], NULL) != 0 || queries[index].failed)
				return fail("concurrent-query", M99_ERR_STATE);
	}
	printf("M99_CONCURRENT_QUERY_LOCKING_OK workers=4\n");
	result = get_authority(&service, &third_authority, 99003, 99003);
	if (result != FTS_OK)
		return fail("third-authority-acquire", result);
	{
		struct m98_mission failed_mission;
		struct m99_invocation failed_invocation;

		result = prepare_mission(&service, 300, 3, &third_authority,
				&failed_mission);
		if (result != M99_OK)
			return fail("prepare-failure-mission", result);
		result = m99_admit(&service, failed_mission.mission_id, 310,
				&third_authority, verified_tool.tool_id, input_digest,
				&failed_invocation);
		if (result != M99_OK)
			return fail("admit-failure-tool", result);
		result = m99_execute(&service, failed_invocation.invocation_id, 311,
				&failed_invocation);
		if (result != M99_OK)
			return fail("execute-failure-tool", result);
		result = m99_complete(&service, failed_invocation.invocation_id, 312,
				0, 0, result_digest, "unverified fixture result",
				&failed_invocation);
		if (result != M99_ERR_VERIFICATION ||
		    failed_invocation.state != M99_INVOCATION_FAILED)
			return fail("unverified-result-denial", result);
	}
	printf("M99_UNVERIFIED_RESULT_DENIED_OK\n");
	m99_close(&service);
	result = m99_open(&service, path, 0);
	if (result != M99_OK)
		return fail("reopen", result);
	result = m99_tool_query(&service, verified_tool.tool_id, &query_tool);
	if (result != M99_OK || query_tool.state != M99_TOOL_REGISTERED)
		return fail("tool-replay", result);
	result = m99_invocation_query(&service, invocation.invocation_id,
			&query_invocation);
	if (result != M99_OK || query_invocation.state != M99_INVOCATION_COMPLETED)
		return fail("invocation-replay", result);
	printf("M99_REGISTRY_REPLAY_OK\n");
	if (m99_test_corrupt_tail(&service) != M99_OK)
		return fail("corrupt-tail", M99_ERR_IO);
	m99_close(&service);
	result = m99_open(&service, path, 0);
	if (result != M99_ERR_CORRUPT)
		return fail("corruption-fail-closed", result);
	printf("M99_CORRUPTION_FAIL_CLOSED_OK\n");
	unlink(path);
	{
		char suffix[sizeof(path) + 32];
		snprintf(suffix, sizeof(suffix), "%s.task", path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.causal", path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.continuity", path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.mission", path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.tools", path);
		unlink(suffix);
	}
	printf("M99_SELFTEST_EXIT=0\n");
	return 0;
}
