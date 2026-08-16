#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/agi_lifecycle.h>

#include "../../faisal-adapter/faisal_adapter_service.h"

static int fail(const char *what, int result)
{
	fprintf(stderr, "M100_FAIL:%s result=%d errno=%s\n", what, result,
		strerror(errno));
	return 1;
}

static void fill_digest(uint8_t digest[M100_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, M100_DIGEST_SIZE);
}

static int acquire_kernel_authority(struct m100_service *service,
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

	grant.agent_id = service->tools.mission.tasks.agent_id;
	grant.agent_capability = service->tools.mission.tasks.agent_capability;
	if (ioctl(service->tools.mission.tasks.kernel_fd,
			AGI_LC_CAPABILITY_GRANT, &grant) < 0 ||
	    !grant.grant_id || !grant.capability)
		return FTS_ERR_KERNEL;
	lease.grant_id = grant.grant_id;
	lease.grant_capability = grant.capability;
	lease.agent_id = service->tools.mission.tasks.agent_id;
	lease.agent_capability = service->tools.mission.tasks.agent_capability;
	lease.intent_digest[0] = 0x99;
	lease.intent_digest[1] = (uint8_t)correlation;
	if (ioctl(service->tools.mission.tasks.kernel_fd,
			AGI_LC_INTENT_LEASE, &lease) < 0 ||
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

static void fill_host_authority(struct m100_service *service,
				struct fts_authority_ref *authority, uint64_t lease_id)
{
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = lease_id;
	authority->grant_id = lease_id + 1;
	authority->grant_capability = lease_id + 2;
	authority->agent_id = service->tools.mission.tasks.agent_id ?
		service->tools.mission.tasks.agent_id : 4;
	authority->agent_capability = service->tools.mission.tasks.agent_capability ?
		service->tools.mission.tasks.agent_capability : 5;
	authority->lineage_id = lease_id + 3;
	authority->generation = 1;
	authority->operation_class = AGI_LC_INTENT_OP_TOOL;
	authority->resource_mask = AGI_LC_RESOURCE_CPU;
	authority->intent_digest[0] = 0x99;
	authority->intent_digest[1] = (uint8_t)lease_id;
}

static int get_authority(struct m100_service *service,
				 struct fts_authority_ref *authority,
				 uint64_t correlation, uint64_t host_lease_id)
{
	if (service->tools.mission.tasks.kernel_fd >= 0)
		return acquire_kernel_authority(service, authority, correlation);
	fill_host_authority(service, authority, host_lease_id);
	return FTS_OK;
}

static int prepare_mission(struct m100_service *service, uint64_t now_ns,
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
		.supervisor_nonce = 10011,
		.operator_nonce = 10012,
	};
	struct m98_mission mission;
	uint8_t plan[M100_DIGEST_SIZE];
	uint8_t model[M100_DIGEST_SIZE];
	uint8_t action[M100_DIGEST_SIZE];
	int result;

	fill_digest(plan, 0x41);
	fill_digest(model, 0x42);
	fill_digest(action, 0x43);
	result = m98_create(&service->tools.mission,
			"execute verified adapter effect", &policy, now_ns, &mission);
	if (result != M98_OK)
		return result;
	result = m98_observe(&service->tools.mission, mission.mission_id,
			now_ns + 1, 1, M98_TRIGGER_MANUAL, plan, model, action,
			"adapter sandbox observation", &mission);
	if (result != M98_OK)
		return result;
	result = m98_propose(&service->tools.mission, mission.mission_id,
			now_ns + 2, authority, plan, model, action, 10,
			AGI_LC_RESOURCE_CPU, 100, "verified adapter proposal",
			"run deterministic effect capsule", &mission);
	if (result != M98_OK)
		return result;
	*out = mission;
	return M100_OK;
}

static int admit_execute(struct m100_service *service, uint64_t mission_id,
				 uint64_t now_ns, const struct fts_authority_ref *authority,
				 const uint8_t input_digest[M100_DIGEST_SIZE],
				 uint64_t tool_id, struct m99_invocation *out)
{
	int result;

	result = m99_admit(&service->tools, mission_id, now_ns, authority,
			tool_id, input_digest, out);
	if (result != M99_OK)
		return result;
	return m99_execute(&service->tools, out->invocation_id, now_ns + 1, out);
}

static int make_invocation(struct m100_service *service, uint64_t now_ns,
				   uint64_t tool_id, uint8_t input_value,
				   uint64_t correlation, uint64_t host_lease_id,
				   struct m99_invocation *out)
{
	struct fts_authority_ref authority;
	struct m98_mission mission;
	uint8_t input_digest[M100_DIGEST_SIZE];
	int result;

	result = get_authority(service, &authority, correlation, host_lease_id);
	if (result != FTS_OK)
		return result;
	result = prepare_mission(service, now_ns, &authority, &mission);
	if (result != M98_OK)
		return result;
	fill_digest(input_digest, input_value);
	return admit_execute(service, mission.mission_id, now_ns + 3,
			     &authority, input_digest, tool_id, out);
}

static void cleanup_files(const char *prefix, const char *scratch)
{
	char path[FTS_MAX_JOURNAL_PATH];
	const char *suffixes[] = {
		"", ".task", ".causal", ".continuity", ".mission", ".tools",
		".effects"
	};
	size_t index;

	for (index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++) {
		if (snprintf(path, sizeof(path), "%s%s", prefix,
			     suffixes[index]) < (int)sizeof(path))
			(void)unlink(path);
	}
	if (scratch) {
		if (snprintf(path, sizeof(path), "%s/%s", scratch,
			     M100_EFFECT_FILE) < (int)sizeof(path))
			(void)unlink(path);
		(void)rmdir(scratch);
	}
}

int main(int argc, char **argv)
{
	char journal[] = "/tmp/faisal-m100-adapter-XXXXXX";
	char scratch[] = "/tmp/faisal-m100-scratch-XXXXXX";
	struct m100_service service;
	struct m100_service replayed;
	struct m99_tool_spec safe_tool;
	struct m99_tool_spec revoked_tool;
	struct m99_tool_spec queried_tool;
	struct m99_invocation first_invocation;
	struct m99_invocation conflict_invocation;
	struct m99_invocation ambiguous_invocation;
	struct m99_invocation revoked_invocation;
	struct m100_effect committed;
	struct m100_effect duplicate;
	struct m100_effect conflict;
	struct m100_effect ambiguous;
	struct m100_effect ambiguous_retry;
	struct m100_effect revoked;
	struct m100_effect query;
	uint8_t implementation_digest[M100_DIGEST_SIZE];
	int fd;
	int require_kernel = argc > 1 && !strcmp(argv[1], "--require-kernel");
	int result;

	fd = mkstemp(journal);
	if (fd < 0)
		return fail("journal-create", M100_ERR_IO);
	close(fd);
	unlink(journal);
	if (!mkdtemp(scratch))
		return fail("scratch-create", M100_ERR_IO);

	result = m100_open(&service, journal, require_kernel);
	if (result != M100_OK) {
		cleanup_files(journal, scratch);
		return fail("service-open", result);
	}
	printf("M100_SERVICE_OPEN_OK kernel=%d\n",
	       service.tools.mission.tasks.kernel_fd >= 0);

	fill_digest(implementation_digest, 0xa1);
	result = m99_register(&service.tools, "m100-deterministic-effect",
			"writes one approved payload inside a scoped sandbox",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 10,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION, 100, 0,
			implementation_digest, &safe_tool);
	if (result != M99_OK)
		goto fail_open;
	printf("M100_TOOL_REGISTER_OK id=%llu\n",
	       (unsigned long long)safe_tool.tool_id);

	result = make_invocation(&service, 1000, safe_tool.tool_id, 0x11,
				10001, 10001, &first_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m100_run_effect(&service, first_invocation.invocation_id, 1010,
				scratch, "effect-committed", "payload-alpha", &committed);
	if (result != M100_OK || committed.state != M100_EFFECT_COMMITTED ||
	    !committed.verification_ok || strcmp(committed.output, "payload-alpha"))
		goto fail_open;
	printf("M100_VERIFIED_EFFECT_COMMITTED_OK effect=%llu\n",
	       (unsigned long long)committed.effect_id);

	result = m100_run_effect(&service, first_invocation.invocation_id, 1011,
				scratch, "effect-committed", "payload-alpha", &duplicate);
	if (result != M100_ERR_DUPLICATE || duplicate.effect_id != committed.effect_id)
		goto fail_open;
	printf("M100_IDEMPOTENT_DUPLICATE_OK\n");

	result = make_invocation(&service, 1020, safe_tool.tool_id, 0x22,
				10002, 10002, &conflict_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m100_run_effect(&service, conflict_invocation.invocation_id, 1030,
				scratch, "effect-committed", "payload-beta", &conflict);
	if (result != M100_ERR_CONFLICT)
		goto fail_open;
	printf("M100_IDEMPOTENCY_CONFLICT_OK\n");

	result = make_invocation(&service, 1040, safe_tool.tool_id, 0x33,
				10003, 10003, &ambiguous_invocation);
	if (result != M99_OK ||
	    m100_test_inject_fail_after_effect(&service) != M100_OK)
		goto fail_open;
	result = m100_run_effect(&service, ambiguous_invocation.invocation_id, 1050,
				scratch, "effect-ambiguous", "payload-gamma", &ambiguous);
	if (result != M100_ERR_AMBIGUOUS ||
	    ambiguous.state != M100_EFFECT_EFFECTED)
		goto fail_open;
	result = m100_run_effect(&service, ambiguous_invocation.invocation_id, 1051,
				scratch, "effect-ambiguous", "payload-gamma", &ambiguous_retry);
	if (result != M100_ERR_AMBIGUOUS ||
	    ambiguous_retry.state != M100_EFFECT_EFFECTED)
		goto fail_open;
	printf("M100_CRASH_AMBIGUITY_NO_RETRY_OK\n");

	result = m99_register(&service.tools, "m100-revocable-effect",
			"fixture revoked after admission and before effect execution",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 10,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION, 100, 0,
			implementation_digest, &revoked_tool);
	if (result != M99_OK)
		goto fail_open;
	result = make_invocation(&service, 1060, revoked_tool.tool_id, 0x44,
				10004, 10004, &revoked_invocation);
	if (result != M99_OK ||
	    m99_revoke(&service.tools, revoked_tool.tool_id, 1070,
		       "M100 revocation fixture", &queried_tool) != M99_OK)
		goto fail_open;
	result = m100_run_effect(&service, revoked_invocation.invocation_id, 1071,
				scratch, "effect-revoked", "payload-delta", &revoked);
	if (result != M100_ERR_REVOKED)
		goto fail_open;
	printf("M100_REVOCATION_BEFORE_EFFECT_DENIED_OK\n");

	result = m100_run_effect(&service, first_invocation.invocation_id, 1080,
				"/tmp/../tmp", "effect-scope", "payload-epsilon", &query);
	if (result != M100_ERR_SCOPE)
		goto fail_open;
	printf("M100_SCOPE_TRAVERSAL_REJECTED_OK\n");

	m100_close(&service);
	result = m100_open(&replayed, journal, 0);
	if (result != M100_OK)
		return fail("replay-open", result);
	if (m100_query(&replayed, committed.effect_id, &query) != M100_OK ||
	    query.state != M100_EFFECT_COMMITTED ||
	    m100_query(&replayed, ambiguous.effect_id, &query) != M100_OK ||
	    query.state != M100_EFFECT_EFFECTED ||
	    m99_tool_query(&replayed.tools, revoked_tool.tool_id, &queried_tool) != M99_OK ||
	    queried_tool.state != M99_TOOL_REVOKED) {
		m100_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("replay-state", M100_ERR_CORRUPT);
	}
	printf("M100_RESTART_REPLAY_STATES_OK\n");
	if (m100_test_corrupt_tail(&replayed) != M100_OK) {
		m100_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("corrupt-tail-injection", M100_ERR_IO);
	}
	m100_close(&replayed);
	result = m100_open(&replayed, journal, 0);
	if (result != M100_ERR_CORRUPT) {
		if (result == M100_OK)
			m100_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("corruption-fail-closed", result);
	}
	printf("M100_CORRUPTION_FAIL_CLOSED_OK\n");
	cleanup_files(journal, scratch);
	printf("M100_SELFTEST_EXIT=0\n");
	return 0;

fail_open:
	m100_close(&service);
	cleanup_files(journal, scratch);
	return fail("selftest", result);
}
