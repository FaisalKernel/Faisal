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
	fprintf(stderr, "M96_FAIL:%s result=%d errno=%s\n", what, result,
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
		.correlation = 96001,
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
		.correlation = 96002,
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
	lease.intent_digest[0] = 0x96;
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
	authority->intent_digest[0] = 0x96;
	authority->intent_digest[1] = 0xa1;
}

static int add_complete_evidence(struct fts_service *service,
					uint64_t branch_id, struct fts_branch *branch)
{
	uint8_t digest[FTS_DIGEST_SIZE];
	int result;

	fill_digest(digest, 0x11);
	result = fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_OBSERVATION, digest, 1, "observation verified", branch);
	if (result != FTS_OK)
		return result;
	fill_digest(digest, 0x22);
	result = fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_RESULT, digest, 1, "result recorded", branch);
	if (result != FTS_OK)
		return result;
	fill_digest(digest, 0x33);
	return fts_branch_add_evidence(service, branch_id,
			FTS_EVIDENCE_VERIFICATION, digest, 1,
			"independent verification", branch);
}

int main(int argc, char **argv)
{
	char path[] = "/tmp/faisal-m96-causal-XXXXXX";
	struct fts_service service;
	struct fts_authority_ref authority;
	struct fts_task task;
	struct fts_task second;
	struct fts_branch branch;
	struct fts_branch query;
	uint8_t action_digest[FTS_DIGEST_SIZE];
	uint8_t observation_digest[FTS_DIGEST_SIZE];
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
	printf("M96_CAUSAL_SERVICE_OPEN_OK kernel=%d\n", service.kernel_fd >= 0);

	if (service.kernel_fd >= 0)
		result = acquire_kernel_authority(&service, &authority);
	else
		fill_host_authority(&service, &authority);
	if (result != FTS_OK)
		return fail("authority-acquire", result);
	printf("M96_AUTHORITY_REFERENCE_OK lease=%llu\n",
	       (unsigned long long)authority.lease_id);

	result = fts_submit(&service, 9601, "causal-primary", "commit verified browser action",
			999999999ULL, 1000000000ULL, 100, 100, 10, 1, NULL, 0, &task);
	if (result != FTS_OK)
		return fail("submit-primary", result);
	result = fts_claim(&service, task.task_id, 2, 1000000000ULL, &task);
	if (result != FTS_OK)
		return fail("claim-primary", result);
	fill_digest(action_digest, 0xa1);
	fill_digest(observation_digest, 0xb2);
	result = fts_branch_propose(&service, task.task_id, &authority,
			AGI_LC_INTENT_OP_BROWSER, AGI_LC_RESOURCE_NETWORK, 96001,
			action_digest, observation_digest, "verified browser mutation", &branch);
	if (result != FTS_OK)
		return fail("branch-propose", result);
	printf("M96_CAUSAL_BRANCH_PROPOSE_OK id=%llu generation=%llu\n",
	       (unsigned long long)branch.branch_id,
	       (unsigned long long)branch.objective_generation);
	result = fts_branch_prepare(&service, branch.branch_id, 3, &branch);
	if (result != FTS_OK || branch.state != FTS_BRANCH_PREPARED)
		return fail("branch-prepare", result);
	printf("M96_CAUSAL_PREPARE_AUTHORIZED_OK\n");
	result = fts_branch_commit(&service, branch.branch_id, 4, &branch);
	if (result != FTS_ERR_INCOMPLETE)
		return fail("incomplete-commit-rejection", result);
	if (fts_branch_query(&service, branch.branch_id, &query) != FTS_OK ||
	    query.state != FTS_BRANCH_REJECTED)
		return fail("incomplete-rejection-state", FTS_ERR_STATE);
	printf("M96_INCOMPLETE_COMMIT_REJECTED_OK\n");

	result = fts_submit(&service, 9602, "causal-commit", "commit evidence complete action",
			999999999ULL, 1000000000ULL, 100, 100, 10, 1, NULL, 0, &second);
	if (result != FTS_OK)
		return fail("submit-commit", result);
	result = fts_claim(&service, second.task_id, 2, 1000000000ULL, &second);
	if (result != FTS_OK)
		return fail("claim-commit", result);
	result = fts_branch_propose(&service, second.task_id, &authority,
			AGI_LC_INTENT_OP_BROWSER, AGI_LC_RESOURCE_NETWORK, 96002,
			action_digest, observation_digest, "evidence complete mutation", &branch);
	if (result != FTS_OK)
		return fail("branch-propose-commit", result);
	result = add_complete_evidence(&service, branch.branch_id, &branch);
	if (result != FTS_OK)
		return fail("evidence-add", result);
	result = fts_branch_prepare(&service, branch.branch_id, 3, &branch);
	if (result != FTS_OK)
		return fail("branch-prepare-commit", result);
	result = fts_branch_commit(&service, branch.branch_id, 4, &branch);
	if (result != FTS_OK || branch.state != FTS_BRANCH_COMMITTED)
		return fail("branch-commit", result);
	printf("M96_EVIDENCE_COMPLETE_COMMIT_OK id=%llu\n",
	       (unsigned long long)branch.branch_id);

	result = fts_submit(&service, 9603, "causal-invalidate", "invalidate stale branch",
			999999999ULL, 1000000000ULL, 100, 100, 10, 1, NULL, 0, &second);
	if (result != FTS_OK)
		return fail("submit-invalidate", result);
	result = fts_branch_propose(&service, second.task_id, &authority,
			AGI_LC_INTENT_OP_BROWSER, AGI_LC_RESOURCE_NETWORK, 96003,
			action_digest, observation_digest, "stale candidate", &branch);
	if (result != FTS_OK)
		return fail("branch-propose-invalidate", result);
	result = fts_branch_invalidate(&service, branch.branch_id, FTS_STOP_POLICY, &branch);
	if (result != FTS_OK || branch.state != FTS_BRANCH_INVALIDATED)
		return fail("branch-invalidate", result);
	printf("M96_BRANCH_INVALIDATION_OK\n");

	fts_close(&service);
	result = fts_open(&service, path, 0);
	if (result != FTS_OK)
		return fail("reopen", result);
	if (fts_branch_query(&service, 2, &query) != FTS_OK ||
	    query.state != FTS_BRANCH_COMMITTED)
		return fail("causal-replay", FTS_ERR_CORRUPT);
	printf("M96_CAUSAL_REPLAY_OK committed=1\n");
	if (fts_test_causal_corrupt_tail(&service) != FTS_OK)
		return fail("causal-corrupt-inject", FTS_ERR_IO);
	fts_close(&service);
	result = fts_open(&service, path, 0);
	if (result != FTS_ERR_CORRUPT)
		return fail("causal-corruption-detection", result);
	printf("M96_CAUSAL_CORRUPTION_FAIL_CLOSED_OK\n");
	unlink(path);
	{
		char causal_path[sizeof(path) + 8];
		snprintf(causal_path, sizeof(causal_path), "%s.causal", path);
		unlink(causal_path);
	}
	printf("M96_SELFTEST_EXIT=0\n");
	return 0;
}
