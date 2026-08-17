#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M115_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int drain_records(int fd)
{
	struct agi_lc_record record;
	int original_flags = fcntl(fd, F_GETFL, 0);
	ssize_t n;

	if (original_flags < 0 || fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
		return -1;
	for (;;) {
		n = read(fd, &record, sizeof(record));
		if (n == (ssize_t)sizeof(record))
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
			if (errno == EINTR)
				continue;
			break;
		}
		(void)fcntl(fd, F_SETFL, original_flags);
		return -1;
	}
	return fcntl(fd, F_SETFL, original_flags);
}

int main(void)
{
	int fd;
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_sandbox_binding sandbox = {
		.size = sizeof(sandbox),
		.operation = AGI_LC_SANDBOX_BIND,
	};
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_INFRASTRUCTURE,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 11501,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent), .correlation = 11502 };
	struct agi_lc_resource_demand demand = {
		.size = sizeof(demand),
		.workload = AGI_LC_WORKLOAD_CODE_EXECUTION,
		.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM,
		.cpu_util_max = 100,
		.memory_max_bytes = 16ULL * 1024 * 1024,
		.correlation = 11503,
	};
	struct agi_lc_tenant_snapshot snapshot = {
		.size = sizeof(snapshot),
		.flags = AGI_LC_TENANT_FLAG_REQUIRE_SANDBOX |
			 AGI_LC_TENANT_FLAG_INCLUDE_LIGHT_AGENTS,
	};
	struct agi_lc_tenant_snapshot malformed = snapshot;
	const char *cgroup_root = "/sys/fs/cgroup";
	const char *tenant_path = "/sys/fs/cgroup/faisal-tenant-115";
	int cgroup_fd = -1;
	int cgroup_procs_fd;
	pid_t throttle_pid;
	struct agi_lc_tenant_cgroup tenant_cgroup = {
		.size = sizeof(tenant_cgroup),
		.flags = AGI_LC_TENANT_CGROUP_FLAG_REQUIRE_SANDBOX,
		.operation = AGI_LC_TENANT_CGROUP_BIND,
		.cgroup_fd = -1,
		.correlation = 11504,
	};
	struct agi_lc_tenant_cgroup tenant_query = {
		.size = sizeof(tenant_query),
		.operation = AGI_LC_TENANT_CGROUP_QUERY,
		.cgroup_fd = -1,
	};
	struct agi_lc_tenant_cgroup tenant_release = {
		.size = sizeof(tenant_release),
		.operation = AGI_LC_TENANT_CGROUP_RELEASE,
		.cgroup_fd = -1,
	};
	struct agi_lc_accel_device accel = {
		.size = sizeof(accel),
		.type = AGI_LC_ACCEL_TYPE_GPU,
		.capabilities = AGI_LC_ACCEL_CAP_DEVICE_MEMORY,
		.accounting_flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
		.isolation_flags = AGI_LC_ACCEL_ISOLATION_TENANT_MEMORY,
		.total_memory_bytes = 16ULL * 1024 * 1024,
		.available_memory_bytes = 16ULL * 1024 * 1024,
		.name = "qemu-tenant-gpu",
		.driver = "faisal-test",
		.correlation = 11507,
	};
	struct agi_lc_accel_device_account accel_account = {
		.size = sizeof(accel_account),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
		.memory_bytes = 8ULL * 1024 * 1024,
		.correlation = 11508,
	};
	struct agi_lc_accel_device_account accel_over = {
		.size = sizeof(accel_over),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
		.memory_bytes = 9ULL * 1024 * 1024,
		.correlation = 11509,
	};
	struct agi_lc_accel_device_account accel_release_over = {
		.size = sizeof(accel_release_over),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY |
			AGI_LC_ACCEL_ACCOUNT_RELEASE,
		.memory_bytes = 9ULL * 1024 * 1024,
		.correlation = 11512,
	};
	struct agi_lc_accel_device_account accel_release = {
		.size = sizeof(accel_release),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY |
			AGI_LC_ACCEL_ACCOUNT_RELEASE,
		.memory_bytes = 8ULL * 1024 * 1024,
		.correlation = 11513,
	};
	struct agi_lc_accel_device_account accel_event_fill = {
		.size = sizeof(accel_event_fill),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
	};
	struct agi_lc_subscribe accel_subscribe = {
		.size = sizeof(accel_subscribe),
		.event_mask = 1ULL << (AGI_LC_EVENT_ACCEL - 1),
		.correlation = 11514,
	};
	struct agi_lc_subscribe accel_unsubscribe = {
		.size = sizeof(accel_unsubscribe),
		.correlation = 11515,
	};
	struct agi_lc_accel_device accel_remove = {
		.size = sizeof(accel_remove),
		.correlation = 11510,
	};
	struct agi_lc_tenant_cpu_policy cpu_policy = {
		.size = sizeof(cpu_policy),
		.flags = AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP,
		.operation = AGI_LC_TENANT_CPU_OP_SET,
		.mode = AGI_LC_TENANT_CPU_MODE_HARD_THROTTLE,
		.period_us = 100000,
		.quota_us = 50000,
		.expected_generation = 0,
		.correlation = 11506,
	};
	struct agi_lc_tenant_cpu_policy cpu_stale = {
		.size = sizeof(cpu_stale),
		.flags = AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP,
		.operation = AGI_LC_TENANT_CPU_OP_SET,
		.mode = AGI_LC_TENANT_CPU_MODE_HARD_THROTTLE,
		.period_us = 100000,
		.quota_us = 25000,
		.expected_generation = 0,
		.correlation = 11511,
	};
	struct agi_lc_tenant_cpu_policy cpu_query = {
		.size = sizeof(cpu_query),
		.flags = AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP,
		.operation = AGI_LC_TENANT_CPU_OP_QUERY,
	};
	struct agi_lc_tenant_cpu_policy cpu_clear = {
		.size = sizeof(cpu_clear),
		.flags = AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP,
		.operation = AGI_LC_TENANT_CPU_OP_CLEAR,
		.expected_generation = 1,
	};
	struct agi_lc_tenant_budget budget = {
		.size = sizeof(budget),
		.flags = AGI_LC_TENANT_BUDGET_FLAG_REQUIRE_SANDBOX |
			 AGI_LC_TENANT_BUDGET_FLAG_REQUIRE_CGROUP,
		.operation = AGI_LC_TENANT_BUDGET_OP_SET,
		.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM,
		.cpu_budget_ns = 60ULL * 1000 * 1000 * 1000,
		.memory_limit_bytes = 32ULL * 1024 * 1024,
		.correlation = 11505,
	};
	struct agi_lc_resource_demand over_limit = demand;
	struct agi_lc_tenant_budget query = {
		.size = sizeof(query),
		.operation = AGI_LC_TENANT_BUDGET_OP_QUERY,
	};
	struct agi_lc_tenant_budget clear = {
		.size = sizeof(clear),
		.operation = AGI_LC_TENANT_BUDGET_OP_CLEAR,
	};

	fd = open("/dev/agi_lifecycle", O_RDWR);
	if (fd < 0)
		return fail("open");
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0)
		return fail("session");
	if (ioctl(fd, AGI_LC_SANDBOX, &sandbox) < 0 ||
	    sandbox.state != AGI_LC_SANDBOX_STATE_BOUND || !sandbox.binding_id)
		return fail("sandbox bind");
	if (ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return fail("agent register");
	agent.agent_id = light.agent_id;
	if (ioctl(fd, AGI_LC_SET_AGENT, &agent) < 0)
		return fail("set agent");
	if (mount("none", cgroup_root, "cgroup2", 0, NULL) < 0 && errno != EBUSY)
		return fail("cgroup2 mount");
	if (mkdir(tenant_path, 0755) < 0 && errno != EEXIST)
		return fail("tenant cgroup mkdir");
	cgroup_fd = open(tenant_path, O_RDONLY | O_DIRECTORY);
	if (cgroup_fd < 0)
		return fail("tenant cgroup open");
	tenant_cgroup.cgroup_fd = cgroup_fd;
	if (ioctl(fd, AGI_LC_TENANT_CGROUP, &tenant_cgroup) < 0 ||
	    tenant_cgroup.status != AGI_LC_TENANT_CGROUP_STATUS_BOUND ||
	    !tenant_cgroup.cgroup_id || !tenant_cgroup.parent_cgroup_id ||
	    tenant_cgroup.hierarchy_owner_id != create.session_id)
		return fail("tenant cgroup bind");
	printf("M151_TENANT_CGROUP_OWNER_OK cgroup=%llu parent=%llu\n",
	       (unsigned long long)tenant_cgroup.cgroup_id,
	       (unsigned long long)tenant_cgroup.parent_cgroup_id);
	if (ioctl(fd, AGI_LC_TENANT_CGROUP, &tenant_query) < 0 ||
	    tenant_query.status != AGI_LC_TENANT_CGROUP_STATUS_BOUND ||
	    tenant_query.cgroup_id != tenant_cgroup.cgroup_id)
		return fail("tenant cgroup query");
	printf("M151_TENANT_CGROUP_QUERY_OK\n");
	cgroup_procs_fd = open("/sys/fs/cgroup/faisal-tenant-115/cgroup.procs",
				       O_WRONLY);
	if (cgroup_procs_fd < 0)
		return fail("tenant cgroup procs open");
	{
		char pid_buf[32];
		int pid_len = snprintf(pid_buf, sizeof(pid_buf), "%ld\n",
				       (long)getpid());
		if (write(cgroup_procs_fd, pid_buf, pid_len) != pid_len) {
			close(cgroup_procs_fd);
			return fail("tenant cgroup procs move");
		}
	}
	close(cgroup_procs_fd);
	printf("M153_TENANT_CGROUP_TASK_MOVE_OK\n");
	if (ioctl(fd, AGI_LC_ACCEL_REGISTER, &accel) < 0 ||
	    !accel.device_id || accel.owner_session_id != create.session_id ||
	    accel.owner_cgroup_id != tenant_cgroup.cgroup_id)
		return fail("tenant accelerator register");
	printf("M152_TENANT_ACCELERATOR_CLAIM_OK device=%llu memory=%llu\n",
	       (unsigned long long)accel.device_id,
	       (unsigned long long)accel.total_memory_bytes);
	accel_account.device_id = accel.device_id;
	if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT, &accel_account) < 0 ||
	    accel_account.status != AGI_LC_ACCEL_ACCOUNT_STATUS_ACCEPTED ||
	    accel_account.tenant_cgroup_id != tenant_cgroup.cgroup_id ||
	    accel_account.device_memory_limit_bytes != accel.total_memory_bytes)
		return fail("tenant accelerator account");
	printf("M152_TENANT_ACCELERATOR_MEMORY_ACCOUNT_OK\n");
	accel_over.device_id = accel.device_id;
	if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT, &accel_over) >= 0 ||
	    errno != EDQUOT ||
	    accel_over.status != AGI_LC_ACCEL_ACCOUNT_STATUS_MEMORY_DENIED)
		return fail("tenant accelerator memory isolation");
	printf("M152_TENANT_ACCELERATOR_MEMORY_DENY_OK\\n");
	accel_release_over.device_id = accel.device_id;
	if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT, &accel_release_over) >= 0 ||
	    errno != ERANGE ||
	    accel_release_over.status !=
		AGI_LC_ACCEL_ACCOUNT_STATUS_RELEASE_DENIED)
		return fail("tenant accelerator release underflow");
	printf("M153_TENANT_ACCELERATOR_RELEASE_UNDERFLOW_DENY_OK\\n");
	accel_release.device_id = accel.device_id;
	if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT, &accel_release) < 0 ||
	    accel_release.status != AGI_LC_ACCEL_ACCOUNT_STATUS_ACCEPTED ||
	    accel_release.tenant_cgroup_id != tenant_cgroup.cgroup_id)
		return fail("tenant accelerator release");
	printf("M153_TENANT_ACCELERATOR_MEMORY_RELEASE_OK\n");
	if (ioctl(fd, AGI_LC_SUBSCRIBE, &accel_subscribe) < 0)
		return fail("accelerator event subscribe");
	if (drain_records(fd) < 0)
		return fail("accelerator event drain");
	accel_event_fill.device_id = accel.device_id;
	for (int i = 0; i < 65; i++) {
		accel_event_fill.correlation = 11516 + (uint64_t)i;
		accel_event_fill.agent_id = 0;
		accel_event_fill.tenant_cgroup_id = 0;
		accel_event_fill.tenant_cgroup_generation = 0;
		accel_event_fill.device_memory_limit_bytes = 0;
		accel_event_fill.status = 0;
		if (i < 64) {
			if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT,
				  &accel_event_fill) < 0 ||
			    accel_event_fill.status !=
				AGI_LC_ACCEL_ACCOUNT_STATUS_ACCEPTED)
				return fail("accelerator event fill");
		} else if (ioctl(fd, AGI_LC_ACCEL_DEVICE_ACCOUNT,
					&accel_event_fill) >= 0 ||
				   errno != EAGAIN ||
				   accel_event_fill.status !=
					AGI_LC_ACCEL_ACCOUNT_STATUS_TELEMETRY_LOST) {
				return fail("accelerator telemetry loss");
		}
	}
	printf("M154_TENANT_ACCELERATOR_TELEMETRY_LOSS_OK\n");
	if (ioctl(fd, AGI_LC_SUBSCRIBE, &accel_unsubscribe) < 0)
		return fail("accelerator event unsubscribe");
	accel_remove.device_id = accel.device_id;

	if (ioctl(fd, AGI_LC_ACCEL_UNREGISTER, &accel_remove) < 0)
		return fail("tenant accelerator unregister");
	printf("M152_TENANT_ACCELERATOR_RELEASE_OK\n");
	if (ioctl(fd, AGI_LC_TENANT_CPU_POLICY, &cpu_policy) < 0 ||
	    cpu_policy.status != AGI_LC_TENANT_CPU_STATUS_ACTIVE ||
	    cpu_policy.generation != 1 || cpu_policy.quota_us != 50000)
		return fail("tenant cpu policy set");
	printf("M152_TENANT_CPU_THROTTLE_SET_OK generation=%llu quota=%lld\n",
	       (unsigned long long)cpu_policy.generation,
	       (long long)cpu_policy.quota_us);
	throttle_pid = fork();
	if (throttle_pid < 0)
		return fail("tenant cpu throttle worker fork");
	if (throttle_pid == 0) {
		struct timespec start, now;
		volatile uint64_t sink = 0;

		clock_gettime(CLOCK_MONOTONIC, &start);
		do {
			sink += 1;
			clock_gettime(CLOCK_MONOTONIC, &now);
		} while ((now.tv_sec - start.tv_sec) * 1000000000LL +
			 (now.tv_nsec - start.tv_nsec) < 600000000LL);
		(void)sink;
		_exit(0);
	}
	usleep(700000);
	errno = 0;
	if (ioctl(fd, AGI_LC_TENANT_CPU_POLICY, &cpu_query) < 0 ||
	    cpu_query.status != AGI_LC_TENANT_CPU_STATUS_ACTIVE ||
	    cpu_query.throttled_usec == 0) {
		kill(throttle_pid, SIGKILL);
		waitpid(throttle_pid, NULL, 0);
		return fail("tenant cpu throttle observation");
	}
	if (waitpid(throttle_pid, NULL, 0) != throttle_pid)
		return fail("tenant cpu throttle worker wait");
	printf("M153_TENANT_CPU_THROTTLE_OBSERVED_OK throttled=%llu\n",
	       (unsigned long long)cpu_query.throttled_usec);
	memset(&cpu_query, 0, sizeof(cpu_query));
	cpu_query.size = sizeof(cpu_query);
	cpu_query.flags = AGI_LC_TENANT_CPU_FLAG_REQUIRE_CGROUP;
	cpu_query.operation = AGI_LC_TENANT_CPU_OP_QUERY;
	errno = 0;
	if (ioctl(fd, AGI_LC_TENANT_CPU_POLICY, &cpu_stale) >= 0 ||
	    errno != EAGAIN)
		return fail("tenant cpu stale generation");
	printf("M152_TENANT_CPU_STALE_GENERATION_DENY_OK\n");
	if (ioctl(fd, AGI_LC_TENANT_CPU_POLICY, &cpu_query) < 0 ||
	    cpu_query.status != AGI_LC_TENANT_CPU_STATUS_ACTIVE ||
	    cpu_query.quota_us != 50000 || cpu_query.period_us != 100000)
		return fail("tenant cpu policy query");
	printf("M152_TENANT_CPU_THROTTLE_QUERY_OK throttled=%llu\n",
	       (unsigned long long)cpu_query.throttled_usec);
	cpu_clear.expected_generation = cpu_policy.generation;
	if (ioctl(fd, AGI_LC_TENANT_CPU_POLICY, &cpu_clear) < 0 ||
	    cpu_clear.status != AGI_LC_TENANT_CPU_STATUS_CLEARED ||
	    cpu_clear.generation != 2)
		return fail("tenant cpu policy clear");
	printf("M152_TENANT_CPU_THROTTLE_CLEAR_OK\n");
	if (ioctl(fd, AGI_LC_SET_RESOURCE_DEMAND, &demand) < 0)
		return fail("resource demand ioctl");
	printf("M115_DEMAND status=%u enforced=0x%x unsupported=0x%x agent=%llu\\n",
	       demand.status, demand.enforced_mask, demand.unsupported_mask,
	       (unsigned long long)demand.agent_id);
	if (demand.status != AGI_LC_RESOURCE_STATUS_ENFORCED ||
	    (demand.enforced_mask & (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM)) !=
		    (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM))
		return fail("resource demand");
	if (ioctl(fd, AGI_LC_TENANT_BUDGET, &budget) < 0 ||
	    budget.status != AGI_LC_TENANT_BUDGET_STATUS_ACTIVE ||
	    budget.enforced_mask != (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM))
		return fail("tenant budget set");
	printf("M115_TENANT_BUDGET_SET_OK generation=%llu memory_limit=%llu\n",
	       (unsigned long long)budget.generation,
	       (unsigned long long)budget.memory_limit_bytes);
	over_limit.memory_max_bytes = 64ULL * 1024 * 1024;
	errno = 0;
	if (ioctl(fd, AGI_LC_SET_RESOURCE_DEMAND, &over_limit) >= 0 ||
	    errno != EDQUOT)
		return fail("tenant over-limit demand accepted");
	printf("M115_TENANT_BUDGET_ADMISSION_DENY_OK\n");
	if (ioctl(fd, AGI_LC_TENANT_BUDGET, &query) < 0 ||
	    query.status != AGI_LC_TENANT_BUDGET_STATUS_ACTIVE ||
	    query.memory_limit_bytes != budget.memory_limit_bytes)
		return fail("tenant budget query");
	printf("M115_TENANT_BUDGET_QUERY_OK\n");
	if (ioctl(fd, AGI_LC_GET_TENANT_SNAPSHOT, &snapshot) < 0)
		return fail("tenant snapshot");
	if (snapshot.session_id != create.session_id ||
	    snapshot.sandbox_binding_id != sandbox.binding_id ||
	    snapshot.agent_count < 1 || snapshot.active_agent_count < 1 ||
	    snapshot.light_agent_count < 1 ||
	    (snapshot.resource_mask & (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM)) !=
		    (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM) ||
	    (snapshot.measured_mask & (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM)) !=
		    (AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM) ||
		    snapshot.memory_limit_bytes != budget.memory_limit_bytes ||
		    snapshot.cpu_budget_ns != budget.cpu_budget_ns)
		return fail("tenant values");
	printf("M115_TENANT_AGGREGATE_OK agents=%u active=%u light=%u memory_limit=%llu\n",
	       snapshot.agent_count, snapshot.active_agent_count,
	       snapshot.light_agent_count,
	       (unsigned long long)snapshot.memory_limit_bytes);
	malformed.session_id = 1;
	errno = 0;
	if (ioctl(fd, AGI_LC_GET_TENANT_SNAPSHOT, &malformed) >= 0 ||
	    errno != EINVAL)
		return fail("malformed tenant request accepted");
	printf("M115_TENANT_MALFORMED_REJECT_OK\\n");
	if (ioctl(fd, AGI_LC_TENANT_BUDGET, &clear) < 0 ||
	    clear.status != AGI_LC_TENANT_BUDGET_STATUS_CLEARED)
		return fail("tenant budget clear");
	printf("M115_TENANT_BUDGET_CLEAR_OK\n");
	cgroup_procs_fd = open("/sys/fs/cgroup/cgroup.procs", O_WRONLY);
	if (cgroup_procs_fd < 0)
		return fail("tenant parent cgroup procs open");
	{
		char pid_buf[32];
		int pid_len = snprintf(pid_buf, sizeof(pid_buf), "%ld\n",
				       (long)getpid());
		if (write(cgroup_procs_fd, pid_buf, pid_len) != pid_len) {
			close(cgroup_procs_fd);
			return fail("tenant parent cgroup procs move");
		}
	}
	close(cgroup_procs_fd);
	printf("M153_TENANT_PARENT_TASK_RESTORE_OK\n");
	if (ioctl(fd, AGI_LC_TENANT_CGROUP, &tenant_release) < 0 ||
	    tenant_release.status != AGI_LC_TENANT_CGROUP_STATUS_REVOKED)
		return fail("tenant cgroup release");
	printf("M151_TENANT_CGROUP_RELEASE_OK\n");
	close(cgroup_fd);
	if (rmdir(tenant_path) < 0)
		return fail("tenant cgroup rmdir");
	printf("M115_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
