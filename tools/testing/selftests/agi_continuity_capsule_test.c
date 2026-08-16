#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../faisal-task/faisal_task_service.h"

static int fail(const char *what, int result)
{
	fprintf(stderr, "M97_FAIL:%s result=%d errno=%s\n", what, result,
		strerror(errno));
	return 1;
}

static void fill_digest(uint8_t digest[FTS_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FTS_DIGEST_SIZE);
}

static int acquire_kernel_authority(struct fts_service *service,
					struct fts_authority_ref *authority)
{
	struct agi_lc_capability_grant grant = {
		.size = sizeof(grant),
		.rights = AGI_LC_CAP_BROWSER_CONTROL,
		.correlation = 97001,
	};
	struct agi_lc_intent_lease lease = {
		.size = sizeof(lease),
		.operation = AGI_LC_INTENT_LEASE_ACQUIRE,
		.flags = AGI_LC_INTENT_LEASE_FLAG_SINGLE_USE |
			AGI_LC_INTENT_LEASE_FLAG_REVOKE_ON_CLOSE,
		.operation_class = AGI_LC_INTENT_OP_BROWSER,
		.resource_mask = AGI_LC_RESOURCE_NETWORK,
		.expires_ns = AGI_LC_INTENT_MAX_TTL_NS,
		.max_uses = 1,
		.correlation = 97002,
	};

	grant.agent_id = service->agent_id;
	grant.agent_capability = service->agent_capability;
	if (ioctl(service->kernel_fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0 ||
	    !grant.grant_id || !grant.capability)
		return FTS_ERR_KERNEL;
	lease.grant_id = grant.grant_id;
	lease.grant_capability = grant.capability;
	lease.agent_id = service->agent_id;
	lease.agent_capability = service->agent_capability;
	lease.intent_digest[0] = 0x97;
	lease.intent_digest[1] = 0xa1;
	if (ioctl(service->kernel_fd, AGI_LC_INTENT_LEASE, &lease) < 0 ||
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

static void fill_host_authority(struct fts_service *service,
				struct fts_authority_ref *authority)
{
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = 1;
	authority->grant_id = 2;
	authority->grant_capability = 3;
	authority->agent_id = service->agent_id ? service->agent_id : 4;
	authority->agent_capability = service->agent_capability ?
		service->agent_capability : 5;
	authority->lineage_id = 6;
	authority->generation = 1;
	authority->operation_class = AGI_LC_INTENT_OP_BROWSER;
	authority->resource_mask = AGI_LC_RESOURCE_NETWORK;
	authority->intent_digest[0] = 0x97;
	authority->intent_digest[1] = 0xa1;
}

static int add_complete_evidence(struct fts_service *service,
					uint64_t branch_id, struct fts_branch *branch)
{
	uint8_t digest[FTS_DIGEST_SIZE];
	int result;

	fill_digest(digest, 0x51);
	result = fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_OBSERVATION, digest, 1,
			"continuity observation verified", branch);
	if (result != FTS_OK)
		return result;
	fill_digest(digest, 0x52);
	result = fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_RESULT, digest, 1,
			"continuity result recorded", branch);
	if (result != FTS_OK)
		return result;
	fill_digest(digest, 0x53);
	return fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_VERIFICATION, digest, 1,
			"continuity independently verified", branch);
}

int main(int argc, char **argv)
{
	char path[] = "/tmp/faisal-m97-continuity-XXXXXX";
	struct fts_service service;
	struct fts_authority_ref authority;
	struct fts_task task;
	struct fts_branch branch;
	struct fts_continuity capsule;
	struct fts_continuity query;
	uint8_t action_digest[FTS_DIGEST_SIZE];
	uint8_t observation_digest[FTS_DIGEST_SIZE];
	uint8_t working_digest[FTS_DIGEST_SIZE];
	uint8_t world_digest[FTS_DIGEST_SIZE];
	uint8_t resource_digest[FTS_DIGEST_SIZE];
	uint8_t changed_digest[FTS_DIGEST_SIZE];
	int fd;
	int require_kernel = argc > 1 && strcmp(argv[1], "--require-kernel") == 0;
	int result;

	fd = mkstemp(path);
	if (fd < 0)
		return fail("mkstemp", FTS_ERR_IO);
	close(fd);
	unlink(path);
	result = fts_open(&service, path, require_kernel);
	if (result != FTS_OK)
		return fail("service-open", result);
	printf("M97_CONTINUITY_SERVICE_OPEN_OK kernel=%d\n",
	       service.kernel_fd >= 0);

	if (service.kernel_fd >= 0)
		result = acquire_kernel_authority(&service, &authority);
	else
		fill_host_authority(&service, &authority);
	if (result != FTS_OK)
		return fail("authority-acquire", result);
	printf("M97_CONTINUITY_AUTHORITY_REFERENCE_OK lease=%llu\n",
	       (unsigned long long)authority.lease_id);

	result = fts_submit(&service, 9701, "continuity-primary",
			"commit state-vector continuity", 999999999ULL,
			1000000000ULL, 100, 100, 10, 1, NULL, 0, &task);
	if (result != FTS_OK)
		return fail("submit", result);
	result = fts_claim(&service, task.task_id, 2, 1000000000ULL, &task);
	if (result != FTS_OK)
		return fail("claim", result);
	fill_digest(action_digest, 0xa7);
	fill_digest(observation_digest, 0xb7);
	result = fts_branch_propose(&service, task.task_id, &authority,
			AGI_LC_INTENT_OP_BROWSER, AGI_LC_RESOURCE_NETWORK, 97001,
			action_digest, observation_digest,
			"resume only if state vector remains identical", &branch);
	if (result != FTS_OK)
		return fail("branch-propose", result);
	result = add_complete_evidence(&service, branch.branch_id, &branch);
	if (result != FTS_OK)
		return fail("evidence", result);
	result = fts_branch_prepare(&service, branch.branch_id, 3, &branch);
	if (result != FTS_OK)
		return fail("branch-prepare", result);
	result = fts_branch_commit(&service, branch.branch_id, 4, &branch);
	if (result != FTS_OK || branch.state != FTS_BRANCH_COMMITTED)
		return fail("branch-commit", result);
	printf("M97_COMMITTED_BRANCH_PRECONDITION_OK branch=%llu\n",
	       (unsigned long long)branch.branch_id);

	fill_digest(working_digest, 0x41);
	fill_digest(world_digest, 0x42);
	fill_digest(resource_digest, 0x43);
	result = fts_continuity_seal(&service, branch.branch_id, 5,
			working_digest, world_digest, resource_digest, &capsule);
	if (result != FTS_OK || capsule.state != FTS_CONTINUITY_SEALED)
		return fail("continuity-seal", result);
	printf("M97_CONTINUITY_CAPSULE_SEALED_OK id=%llu\n",
	       (unsigned long long)capsule.capsule_id);

	result = fts_continuity_check(&service, capsule.capsule_id,
			working_digest, world_digest, resource_digest, &query);
	if (result != FTS_OK || query.capsule_id != capsule.capsule_id)
		return fail("continuity-exact-resume", result);
	printf("M97_CONTINUITY_RESUME_EXACT_OK\n");

	fill_digest(changed_digest, 0x44);
	result = fts_continuity_check(&service, capsule.capsule_id,
			changed_digest, world_digest, resource_digest, &query);
	if (result != FTS_ERR_STALE)
		return fail("working-state-drift", result);
	printf("M97_WORKING_STATE_DRIFT_REJECTED_OK\n");
	fill_digest(changed_digest, 0x45);
	result = fts_continuity_check(&service, capsule.capsule_id,
			working_digest, changed_digest, resource_digest, &query);
	if (result != FTS_ERR_STALE)
		return fail("world-state-drift", result);
	printf("M97_WORLD_STATE_DRIFT_REJECTED_OK\n");
	fill_digest(changed_digest, 0x46);
	result = fts_continuity_check(&service, capsule.capsule_id,
			working_digest, world_digest, changed_digest, &query);
	if (result != FTS_ERR_STALE)
		return fail("resource-state-drift", result);
	printf("M97_RESOURCE_STATE_DRIFT_REJECTED_OK\n");

	fts_close(&service);
	result = fts_open(&service, path, 0);
	if (result != FTS_OK)
		return fail("reopen", result);
	result = fts_continuity_check(&service, capsule.capsule_id,
			working_digest, world_digest, resource_digest, &query);
	if (result != FTS_OK || query.state != FTS_CONTINUITY_SEALED)
		return fail("continuity-replay", result);
	printf("M97_CONTINUITY_REPLAY_OK id=%llu\n",
	       (unsigned long long)query.capsule_id);

	result = fts_continuity_invalidate(&service, capsule.capsule_id, 6,
			FTS_STOP_POLICY, &query);
	if (result != FTS_OK || query.state != FTS_CONTINUITY_INVALIDATED)
		return fail("continuity-invalidate", result);
	result = fts_continuity_check(&service, capsule.capsule_id,
			working_digest, world_digest, resource_digest, &query);
	if (result != FTS_ERR_REVOKED)
		return fail("invalidated-resume", result);
	printf("M97_CONTINUITY_INVALIDATION_REVOKED_OK\n");

	if (fts_test_continuity_corrupt_tail(&service) != FTS_OK)
		return fail("continuity-corrupt-inject", FTS_ERR_IO);
	fts_close(&service);
	result = fts_open(&service, path, 0);
	if (result != FTS_ERR_CORRUPT)
		return fail("continuity-corruption-detection", result);
	printf("M97_CONTINUITY_CORRUPTION_FAIL_CLOSED_OK\n");

	unlink(path);
	{
		char suffix[sizeof(path) + 16];
		snprintf(suffix, sizeof(suffix), "%s.causal", path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.continuity", path);
		unlink(suffix);
	}
	printf("M97_SELFTEST_EXIT=0\n");
	return 0;
}
