#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../faisal-adapter/faisal_nondeterministic_adapter_service.h"

static int fail(const char *what, int result)
{
	fprintf(stderr, "M102_FAIL:%s result=%d errno=%s\n", what, result,
		strerror(errno));
	return 1;
}

static void fill_digest(uint8_t digest[M102_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, M102_DIGEST_SIZE);
}

static int acquire_kernel_authority(struct m102_service *service,
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
	lease.intent_digest[0] = 0xa2;
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

static void fill_host_authority(struct m102_service *service,
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
	authority->intent_digest[0] = 0xa2;
	authority->intent_digest[1] = (uint8_t)lease_id;
}

static int get_authority(struct m102_service *service,
				 struct fts_authority_ref *authority,
				 uint64_t correlation, uint64_t host_lease_id)
{
	if (service->tools.mission.tasks.kernel_fd >= 0)
		return acquire_kernel_authority(service, authority, correlation);
	fill_host_authority(service, authority, host_lease_id);
	return FTS_OK;
}

static int prepare_mission(struct m102_service *service, uint64_t now_ns,
				   const struct fts_authority_ref *authority,
				   struct m98_mission *out)
{
	struct m98_policy policy = {
		.deadline_ns = 1000000000ULL,
		.cpu_budget_ns = 1000000,
		.money_budget_micro = 1000,
		.max_steps = 8,
		.max_retries = 2,
		.risk_ceiling = 20,
		.supervisor_approved = 1,
		.operator_approved = 1,
		.supervisor_nonce = 10211,
		.operator_nonce = 10212,
	};
	struct m98_mission mission;
	uint8_t plan[M102_DIGEST_SIZE];
	uint8_t model[M102_DIGEST_SIZE];
	uint8_t action[M102_DIGEST_SIZE];
	int result;

	fill_digest(plan, 0x51);
	fill_digest(model, 0x52);
	fill_digest(action, 0x53);
	result = m98_create(&service->tools.mission,
			"execute network-deny nondeterministic adapter", &policy,
			now_ns, &mission);
	if (result != M98_OK)
		return result;
	result = m98_observe(&service->tools.mission, mission.mission_id,
			now_ns + 1, 1, M98_TRIGGER_MANUAL, plan, model, action,
			"network-deny adapter observation", &mission);
	if (result != M98_OK)
		return result;
	result = m98_propose(&service->tools.mission, mission.mission_id,
			now_ns + 2, authority, plan, model, action, 10,
			AGI_LC_RESOURCE_CPU, 100, "network-deny adapter proposal",
			"run fixed program with network denied", &mission);
	if (result != M98_OK)
		return result;
	*out = mission;
	return M102_OK;
}

static int make_invocation(struct m102_service *service, uint64_t now_ns,
				   uint64_t tool_id, uint8_t input_value,
				   uint64_t correlation, uint64_t host_lease_id,
				   struct m99_invocation *out)
{
	struct fts_authority_ref authority;
	struct m98_mission mission;
	uint8_t input_digest[M102_DIGEST_SIZE];
	int result;

	result = get_authority(service, &authority, correlation, host_lease_id);
	if (result != FTS_OK)
		return result;
	result = prepare_mission(service, now_ns, &authority, &mission);
	if (result != M98_OK)
		return result;
	fill_digest(input_digest, input_value);
	result = m99_admit(&service->tools, mission.mission_id, now_ns + 3,
			   &authority, tool_id, input_digest, out);
	if (result != M99_OK)
		return result;
	return m99_execute(&service->tools, out->invocation_id, now_ns + 4, out);
}

static void cleanup_files(const char *prefix, const char *scratch)
{
	char path[FTS_MAX_JOURNAL_PATH];
	const char *suffixes[] = {
		"", ".task", ".causal", ".continuity", ".mission", ".tools",
		".effects", ".network-effects"
	};
	size_t index;

	for (index = 0; index < sizeof(suffixes) / sizeof(suffixes[0]); index++)
		if (snprintf(path, sizeof(path), "%s%s", prefix, suffixes[index]) <
		    (int)sizeof(path))
			(void)unlink(path);
	if (scratch)
		(void)rmdir(scratch);
}

static int network_probe_main(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd >= 0) {
		close(fd);
		return 2;
	}
	return 0;
}

static int write_probe_main(void)
{
	int fd = open("/tmp/m102-write-probe", O_WRONLY | O_CREAT | O_TRUNC,
			      0600);

	if (fd >= 0) {
		close(fd);
		(void)unlink("/tmp/m102-write-probe");
		return 2;
	}
	return 0;
}

int main(int argc, char **argv)
{
	char journal[] = "/tmp/faisal-m102-adapter-XXXXXX";
	char scratch[] = "/tmp/faisal-m102-scratch-XXXXXX";
	char selfpath[FTS_MAX_JOURNAL_PATH];
	const char *echo_argv[3];
	const char *probe_argv[3];
	const char *write_argv[3];
	struct m102_service service;
	struct m102_service replayed;
	struct m99_tool_spec echo_tool;
	struct m99_tool_spec probe_tool;
	struct m99_tool_spec write_tool;
	struct m99_tool_spec revoked_tool;
	struct m99_tool_spec queried_tool;
	struct m99_invocation echo_invocation;
	struct m99_invocation conflict_invocation;
	struct m99_invocation probe_invocation;
	struct m99_invocation write_invocation;
	struct m99_invocation revoked_invocation;
	struct m102_effect committed;
	struct m102_effect duplicate;
	struct m102_effect conflict;
	struct m102_effect network_denied;
	struct m102_effect write_denied;
	struct m102_effect revoked;
	struct m102_effect query;
	uint8_t command_digest[M102_DIGEST_SIZE];
	int fd;
	int require_kernel = argc > 1 && !strcmp(argv[1], "--require-kernel");
	int result;

	if (argc > 1 && !strcmp(argv[1], "--network-probe"))
		return network_probe_main();
	if (argc > 1 && !strcmp(argv[1], "--write-probe"))
		return write_probe_main();
	if (argc > 1 && !strcmp(argv[1], "--fixed-output")) {
		printf("m102-network-deny-ok\n");
		return 0;
	}
	if (!realpath(argv[0], selfpath))
		return fail("selfpath", M102_ERR_IO);
	echo_argv[0] = selfpath;
	echo_argv[1] = "--fixed-output";
	echo_argv[2] = NULL;
	probe_argv[0] = selfpath;
	probe_argv[1] = "--network-probe";
	probe_argv[2] = NULL;
	write_argv[0] = selfpath;
	write_argv[1] = "--write-probe";
	write_argv[2] = NULL;
	fd = mkstemp(journal);
	if (fd < 0)
		return fail("journal-create", M102_ERR_IO);
	close(fd);
	unlink(journal);
	if (!mkdtemp(scratch))
		return fail("scratch-create", M102_ERR_IO);
	result = m102_open(&service, journal, require_kernel);
	if (result != M102_OK) {
		cleanup_files(journal, scratch);
		return fail("service-open", result);
	}
	printf("M102_SERVICE_OPEN_OK kernel=%d\n",
	       service.tools.mission.tasks.kernel_fd >= 0);
	if (m102_command_digest(echo_argv[0], echo_argv, 2,
				command_digest) != M102_OK)
		goto fail_open;
	result = m99_register(&service.tools, "m102-fixed-echo",
			"fixed program with network-deny sandbox and verified output",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 12,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION |
			M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL,
			200, 0, command_digest, &echo_tool);
	if (result != M99_OK)
		goto fail_open;
	if (m102_command_digest(probe_argv[0], probe_argv, 2,
				command_digest) != M102_OK)
		goto fail_open;
	result = m99_register(&service.tools, "m102-network-probe",
			"probe that must be killed when it attempts socket creation",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 15,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION |
			M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL,
			200, 0, command_digest, &probe_tool);
	if (result != M99_OK)
		goto fail_open;
	if (m102_command_digest(write_argv[0], write_argv, 2,
				command_digest) != M102_OK)
		goto fail_open;
	result = m99_register(&service.tools, "m102-write-probe",
			"probe that must be denied when it attempts a writable open",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 15,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION |
			M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL,
			200, 0, command_digest, &write_tool);
	if (result != M99_OK)
		goto fail_open;
	printf("M102_TOOL_REGISTRATION_PROVENANCE_OK\n");
	result = make_invocation(&service, 2000, echo_tool.tool_id, 0x61,
				20001, 20001, &echo_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m102_run_program(&service, echo_invocation.invocation_id, 2010,
				  scratch, echo_argv[0], echo_argv, 2,
				  "network-effect-committed", &committed);
	if (result != M102_OK || committed.state != M102_EFFECT_COMMITTED ||
	    !committed.verification_ok ||
	    strcmp(committed.output, "m102-network-deny-ok\n"))
		goto fail_open;
	printf("M102_VERIFIED_NETWORK_DENY_EFFECT_COMMITTED_OK\n");
	result = m102_run_program(&service, echo_invocation.invocation_id, 2011,
				  scratch, echo_argv[0], echo_argv, 2,
				  "network-effect-committed", &duplicate);
	if (result != M102_ERR_DUPLICATE ||
	    duplicate.effect_id != committed.effect_id)
		goto fail_open;
	printf("M102_IDEMPOTENT_DUPLICATE_OK\n");
	result = make_invocation(&service, 2020, echo_tool.tool_id, 0x62,
				20002, 20002, &conflict_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m102_run_program(&service, conflict_invocation.invocation_id,
				  2030, scratch, echo_argv[0], echo_argv, 2,
				  "network-effect-committed", &conflict);
	if (result != M102_ERR_CONFLICT)
		goto fail_open;
	printf("M102_IDEMPOTENCY_CONFLICT_OK\n");
	result = make_invocation(&service, 2040, probe_tool.tool_id, 0x63,
				20003, 20003, &probe_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m102_run_program(&service, probe_invocation.invocation_id, 2050,
				  scratch, probe_argv[0], probe_argv, 2,
				  "network-effect-probe", &network_denied);
	if (result != M102_ERR_SANDBOX ||
	    network_denied.state != M102_EFFECT_FAILED)
		goto fail_open;
	printf("M102_NETWORK_SYSCALL_DENIED_OK\n");
	result = make_invocation(&service, 2055, write_tool.tool_id, 0x65,
				20005, 20005, &write_invocation);
	if (result != M99_OK)
		goto fail_open;
	result = m102_run_program(&service, write_invocation.invocation_id, 2056,
				  scratch, write_argv[0], write_argv, 2,
				  "network-effect-write", &write_denied);
	if (result != M102_ERR_SANDBOX ||
	    write_denied.state != M102_EFFECT_FAILED)
		goto fail_open;
	printf("M102_FILESYSTEM_WRITE_DENIED_OK\n");
	result = m99_register(&service.tools, "m102-revocable",
			"revocation before nondeterministic effect",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 12,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION |
			M99_TOOL_FLAG_REQUIRES_VERIFICATION,
			200, 0, command_digest, &revoked_tool);
	if (result != M99_OK)
		goto fail_open;
	result = make_invocation(&service, 2060, revoked_tool.tool_id, 0x64,
				20004, 20004, &revoked_invocation);
	if (result != M99_OK ||
	    m99_revoke(&service.tools, revoked_tool.tool_id, 2070,
			"M102 revocation fixture", &queried_tool) != M99_OK)
		goto fail_open;
	result = m102_run_program(&service, revoked_invocation.invocation_id, 2071,
				  scratch, echo_argv[0], echo_argv, 2,
				  "network-effect-revoked", &revoked);
	if (result != M102_ERR_REVOKED)
		goto fail_open;
	printf("M102_REVOCATION_BEFORE_EFFECT_DENIED_OK\n");
	result = m102_run_program(&service, echo_invocation.invocation_id, 2080,
				  "/tmp/../tmp", echo_argv[0], echo_argv, 2,
				  "network-effect-scope", &query);
	if (result != M102_ERR_SCOPE)
		goto fail_open;
	printf("M102_SCOPE_TRAVERSAL_REJECTED_OK\n");
	m102_close(&service);
	result = m102_open(&replayed, journal, 0);
	if (result != M102_OK)
		return fail("replay-open", result);
	if (m102_query(&replayed, committed.effect_id, &query) != M102_OK ||
	    query.state != M102_EFFECT_COMMITTED ||
	    m102_query(&replayed, network_denied.effect_id, &query) != M102_OK ||
	    query.state != M102_EFFECT_FAILED ||
	    m102_query(&replayed, write_denied.effect_id, &query) != M102_OK ||
	    query.state != M102_EFFECT_FAILED ||
	    m99_tool_query(&replayed.tools, revoked_tool.tool_id,
			   &queried_tool) != M99_OK ||
	    queried_tool.state != M99_TOOL_REVOKED) {
		m102_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("replay-state", M102_ERR_CORRUPT);
	}
	printf("M102_RESTART_REPLAY_STATES_OK\n");
	if (m102_test_corrupt_tail(&replayed) != M102_OK) {
		m102_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("corrupt-tail-injection", M102_ERR_IO);
	}
	m102_close(&replayed);
	result = m102_open(&replayed, journal, 0);
	if (result != M102_ERR_CORRUPT) {
		if (result == M102_OK)
			m102_close(&replayed);
		cleanup_files(journal, scratch);
		return fail("corruption-fail-closed", result);
	}
	printf("M102_CORRUPTION_FAIL_CLOSED_OK\n");
	cleanup_files(journal, scratch);
	printf("M102_SELFTEST_EXIT=0\n");
	return 0;

fail_open:
	m102_close(&service);
	cleanup_files(journal, scratch);
	return fail("selftest", result);
}
