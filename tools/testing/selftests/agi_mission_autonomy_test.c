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

#include "../../faisal-mission/faisal_mission_service.h"

static int fail(const char *what, int result)
{
	fprintf(stderr, "M98_FAIL:%s result=%d errno=%s\n", what, result,
		strerror(errno));
	return 1;
}

static void fill_digest(uint8_t digest[M98_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, M98_DIGEST_SIZE);
}

static int acquire_kernel_authority(struct m98_service *service,
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

	grant.agent_id = service->tasks.agent_id;
	grant.agent_capability = service->tasks.agent_capability;
	if (ioctl(service->tasks.kernel_fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0 ||
	    !grant.grant_id || !grant.capability)
		return FTS_ERR_KERNEL;
	lease.grant_id = grant.grant_id;
	lease.grant_capability = grant.capability;
	lease.agent_id = service->tasks.agent_id;
	lease.agent_capability = service->tasks.agent_capability;
	lease.intent_digest[0] = 0x98;
	lease.intent_digest[1] = (uint8_t)correlation;
	if (ioctl(service->tasks.kernel_fd, AGI_LC_INTENT_LEASE, &lease) < 0 ||
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

static void fill_host_authority(struct m98_service *service,
				struct fts_authority_ref *authority)
{
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = 98001;
	authority->grant_id = 98002;
	authority->grant_capability = 98003;
	authority->agent_id = service->tasks.agent_id ? service->tasks.agent_id : 4;
	authority->agent_capability = service->tasks.agent_capability ?
		service->tasks.agent_capability : 5;
	authority->lineage_id = 98004;
	authority->generation = 1;
	authority->operation_class = AGI_LC_INTENT_OP_TOOL;
	authority->resource_mask = AGI_LC_RESOURCE_CPU;
	authority->intent_digest[0] = 0x98;
	authority->intent_digest[1] = 0xa1;
}

static int get_authority(struct m98_service *service,
			 struct fts_authority_ref *authority, uint64_t correlation)
{
	if (service->tasks.kernel_fd >= 0)
		return acquire_kernel_authority(service, authority, correlation);
	fill_host_authority(service, authority);
	return FTS_OK;
}

struct query_worker {
	const struct m98_service *service;
	uint64_t mission_id;
	int failed;
};

static void *query_worker_main(void *opaque)
{
	struct query_worker *worker = opaque;
	unsigned int index;

	for (index = 0; index < 128; index++) {
		struct m98_mission mission;

		if (m98_query(worker->service, worker->mission_id, &mission) != M98_OK) {
			worker->failed = 1;
			break;
		}
	}
	return NULL;
}

static int make_policy(struct m98_policy *policy, uint64_t deadline)
{
	memset(policy, 0, sizeof(*policy));
	policy->deadline_ns = deadline;
	policy->cpu_budget_ns = 1000000;
	policy->money_budget_micro = 1000;
	policy->max_steps = 4;
	policy->max_retries = 2;
	policy->risk_ceiling = 100;
	policy->supervisor_approved = 1;
	policy->operator_approved = 1;
	policy->supervisor_nonce = 98011;
	policy->operator_nonce = 98012;
	return 0;
}

int main(int argc, char **argv)
{
	char path[] = "/tmp/faisal-m98-mission-XXXXXX";
	struct m98_service service;
	struct m98_policy policy;
	struct m98_mission mission;
	struct m98_mission query;
	struct fts_authority_ref authority;
	struct fts_authority_ref invalid_authority;
	uint8_t working[M98_DIGEST_SIZE];
	uint8_t world[M98_DIGEST_SIZE];
	uint8_t resource[M98_DIGEST_SIZE];
	uint8_t plan[M98_DIGEST_SIZE];
	uint8_t model[M98_DIGEST_SIZE];
	uint8_t action[M98_DIGEST_SIZE];
	int fd;
	int require_kernel = argc > 1 && strcmp(argv[1], "--require-kernel") == 0;
	int result;

	fd = mkstemp(path);
	if (fd < 0)
		return fail("mkstemp", M98_ERR_IO);
	close(fd);
	unlink(path);
	result = m98_open(&service, path, require_kernel);
	if (result != M98_OK)
		return fail("service-open", result);
	printf("M98_MISSION_SERVICE_OPEN_OK kernel=%d\n", service.tasks.kernel_fd >= 0);
	result = get_authority(&service, &authority, 98020);
	if (result != FTS_OK)
		return fail("authority-acquire", result);
	printf("M98_AUTHORITY_REFERENCE_OK lease=%llu\n",
	       (unsigned long long)authority.lease_id);
	memset(&invalid_authority, 0, sizeof(invalid_authority));

	fill_digest(working, 0x11);
	fill_digest(world, 0x22);
	fill_digest(resource, 0x33);
	fill_digest(plan, 0x44);
	fill_digest(model, 0x55);
	fill_digest(action, 0x66);
	make_policy(&policy, 1000000000ULL);
	result = m98_create(&service, "maintain verified autonomous mission", &policy,
			10, &mission);
	if (result != M98_OK)
		return fail("mission-create", result);
	printf("M98_MISSION_CREATE_OK id=%llu task=%llu\n",
	       (unsigned long long)mission.mission_id,
	       (unsigned long long)mission.task_id);
	result = m98_observe(&service, mission.mission_id, 20, 1,
			M98_TRIGGER_MANUAL, working, world, resource,
			"initial world observation", &mission);
	if (result != M98_OK || mission.state != M98_MISSION_PROPOSAL_REQUIRED)
		return fail("mission-observe", result);
	printf("M98_OBSERVATION_ADMITTED_OK event=%llu\n",
	       (unsigned long long)mission.event_sequence);
	result = m98_propose(&service, mission.mission_id, 30,
			&invalid_authority, plan, model, action, 10,
			AGI_LC_RESOURCE_CPU, 10, "proposal without authority", "tool action",
			&query);
	if (result == M98_OK)
		return fail("model-proposal-authority-separation", result);
	printf("M98_MODEL_PROPOSAL_NOT_AUTHORITY_OK\n");
	result = m98_propose(&service, mission.mission_id, 40, &authority,
			plan, model, action, 10, AGI_LC_RESOURCE_CPU, 10,
			"bounded verified plan", "bounded tool action", &mission);
	if (result != M98_OK || mission.state != M98_MISSION_EXECUTION_PENDING)
		return fail("mission-propose", result);
	printf("M98_PROPOSAL_PREPARED_OK branch=%llu\n",
	       (unsigned long long)mission.branch_id);
	result = m98_execute_result(&service, mission.mission_id, 50, 100, 10,
			M98_DECISION_CONTINUE, 1, "verified execution result", &mission);
	if (result != M98_OK || mission.state != M98_MISSION_OBSERVE_REQUIRED ||
	    !mission.capsule_id)
		return fail("mission-commit", result);
	printf("M98_EVIDENCE_COMMIT_CONTINUE_OK capsule=%llu step=%llu\n",
	       (unsigned long long)mission.capsule_id,
	       (unsigned long long)mission.step);
	result = m98_observe(&service, mission.mission_id, 60, 2,
			M98_TRIGGER_EVENT, working, world, resource,
			"stable post-commit observation", &mission);
	if (result != M98_OK || mission.state != M98_MISSION_PROPOSAL_REQUIRED)
		return fail("mission-continuation-observe", result);
	printf("M98_CONTINUATION_OBSERVE_OK\n");
	fill_digest(world, 0x77);
	result = m98_observe(&service, mission.mission_id, 70, 3,
			M98_TRIGGER_EVENT, working, world, resource,
			"world drift observation", &mission);
	if (result != M98_ERR_STALE || mission.state != M98_MISSION_REPLAN_REQUIRED)
		return fail("world-drift-replan", result);
	printf("M98_WORLD_DRIFT_REPLAN_REQUIRED_OK\n");
	fill_digest(world, 0x22);

	m98_close(&service);
	result = m98_open(&service, path, require_kernel);
	if (result != M98_OK)
		return fail("mission-reopen", result);
	result = m98_query(&service, 1, &query);
	if (result != M98_OK || query.state != M98_MISSION_REPLAN_REQUIRED)
		return fail("mission-replay", result);
	printf("M98_MISSION_REPLAY_OK state=%u\n", query.state);
	{
		pthread_t workers[4];
		struct query_worker queries[4];
		unsigned int index;

		memset(queries, 0, sizeof(queries));
		for (index = 0; index < 4; index++) {
			queries[index].service = &service;
			queries[index].mission_id = 1;
			if (pthread_create(&workers[index], NULL, query_worker_main,
					   &queries[index]) != 0)
				return fail("concurrent-query-create", M98_ERR_STATE);
		}
		for (index = 0; index < 4; index++)
			if (pthread_join(workers[index], NULL) != 0 || queries[index].failed)
				return fail("concurrent-query", M98_ERR_STATE);
	}
	printf("M98_CONCURRENT_QUERY_LOCKING_OK workers=4\n");

	make_policy(&policy, 2000000000ULL);
	result = m98_create(&service, "recover interrupted autonomous mission", &policy,
			100, &mission);
	if (result != M98_OK)
		return fail("recovery-create", result);
	result = m98_observe(&service, mission.mission_id, 110, 1,
			M98_TRIGGER_MANUAL, working, world, resource,
			"recovery observation", &mission);
	if (result != M98_OK)
		return fail("recovery-observe", result);
	result = get_authority(&service, &authority, 98030);
	if (result != FTS_OK)
		return fail("recovery-authority", result);
	result = m98_propose(&service, mission.mission_id, 120, &authority,
			plan, model, action, 10, AGI_LC_RESOURCE_CPU, 10,
			"interrupted plan", "interrupted tool action", &mission);
	if (result != M98_OK || mission.state != M98_MISSION_EXECUTION_PENDING)
		return fail("recovery-propose", result);
	m98_close(&service);
	result = m98_open(&service, path, require_kernel);
	if (result != M98_OK)
		return fail("recovery-reopen", result);
	result = m98_query(&service, mission.mission_id, &query);
	if (result != M98_OK || query.state != M98_MISSION_ESCALATED)
		return fail("recovery-escalation", result);
	printf("M98_INFLIGHT_RECOVERY_ESCALATED_OK\n");

	make_policy(&policy, 1000);
	result = m98_create(&service, "deadline bounded mission", &policy, 200,
			&mission);
	if (result != M98_OK)
		return fail("deadline-create", result);
	result = m98_tick(&service, mission.mission_id, 1001, &query);
	if (result != M98_ERR_DEADLINE || query.state != M98_MISSION_STOPPED)
		return fail("deadline-stop", result);
	printf("M98_DEADLINE_STOP_OK\n");

	if (m98_test_corrupt_tail(&service) != M98_OK)
		return fail("corrupt-tail", M98_ERR_IO);
	m98_close(&service);
	result = m98_open(&service, path, 0);
	if (result != M98_ERR_CORRUPT)
		return fail("corruption-fail-closed", result);
	printf("M98_CORRUPTION_FAIL_CLOSED_OK\n");
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
	}
	printf("M98_SELFTEST_EXIT=0\n");
	return 0;
}
