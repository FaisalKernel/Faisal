#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M115_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
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
	struct agi_lc_tenant_budget budget = {
		.size = sizeof(budget),
		.flags = AGI_LC_TENANT_BUDGET_FLAG_REQUIRE_SANDBOX,
		.operation = AGI_LC_TENANT_BUDGET_OP_SET,
		.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM,
		.cpu_budget_ns = 60ULL * 1000 * 1000 * 1000,
		.memory_limit_bytes = 32ULL * 1024 * 1024,
		.correlation = 11504,
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
	printf("M115_TENANT_BUDGET_CLEAR_OK\nM115_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
