// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "DOMAIN_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

int main(void)
{
	int fd;
	long cpus;
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 67001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };
	struct agi_lc_execution_domain domain = {
		.size = sizeof(domain),
		.operation = AGI_LC_EXEC_DOMAIN_CREATE,
		.requested_features = AGI_LC_EXEC_DOMAIN_REQUEST_NOHZ_FULL |
			AGI_LC_EXEC_DOMAIN_REQUEST_IRQ_ISOLATION,
		.correlation = 67002,
	};
	struct agi_lc_execution_domain query, bad, required, release;

	cpus = sysconf(_SC_NPROCESSORS_ONLN);
	if (cpus < 2) {
		printf("M67_SKIP_NEEDS_TWO_CPUS\nM67_SELFTEST_EXIT=4\n");
		return 4;
	}
	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return fail("session");
	agent.agent_id = light.agent_id;
	agent.correlation = 67003;
	if (ioctl(fd, AGI_LC_SET_AGENT, &agent) < 0)
		return fail("set agent");
	domain.requested_cpus[0] = 1ULL << 1;
	if (ioctl(fd, AGI_LC_EXECUTION_DOMAIN, &domain) < 0 ||
	    domain.state != AGI_LC_EXEC_DOMAIN_STATE_ACTIVE ||
	    !domain.domain_id || !domain.capability ||
	    !(domain.applied_cpus[0] & (1ULL << 1)) ||
	    !(domain.housekeeping_cpus[0] & 1ULL) ||
	    !(domain.available_features & AGI_LC_EXEC_DOMAIN_FEATURE_AFFINITY) ||
	    !(domain.available_features & AGI_LC_EXEC_DOMAIN_FEATURE_HOUSEKEEPING) ||
	    !(domain.unsupported_features & AGI_LC_EXEC_DOMAIN_FEATURE_NOHZ_FULL) ||
	    !(domain.unsupported_features & AGI_LC_EXEC_DOMAIN_FEATURE_IRQ_ISOLATION))
		return fail("domain create");
	printf("M67_DOMAIN_CREATE_OK id=%llu\n",
	       (unsigned long long)domain.domain_id);
	query = domain;
	query.operation = AGI_LC_EXEC_DOMAIN_QUERY;
	query.correlation = 67004;
	if (ioctl(fd, AGI_LC_EXECUTION_DOMAIN, &query) < 0 ||
	    query.state != AGI_LC_EXEC_DOMAIN_STATE_ACTIVE ||
	    query.domain_id != domain.domain_id)
		return fail("domain query");
	printf("M67_DOMAIN_QUERY_OK\n");
	bad = query;
	bad.capability ^= 1;
	bad.correlation = 67005;
	if (ioctl(fd, AGI_LC_EXECUTION_DOMAIN, &bad) >= 0 || errno != EACCES)
		return fail("stale domain capability rejection");
	printf("M67_STALE_DOMAIN_CAPABILITY_REJECT_OK\n");
	required = domain;
	required.operation = AGI_LC_EXEC_DOMAIN_CREATE;
	required.flags = 0;
	required.domain_id = 0;
	required.capability = 0;
	required.generation = 0;
	required.state = 0;
	required.status = 0;
	required.owner_agent = 0;
	required.owner_tgid = 0;
	required.available_features = 0;
	required.unsupported_features = 0;
	required.jitter_sequence = 0;
	required.requested_features = AGI_LC_EXEC_DOMAIN_REQUIRE_NOHZ_FULL;
	required.correlation = 67006;
	if (ioctl(fd, AGI_LC_EXECUTION_DOMAIN, &required) >= 0 ||
	    errno != EOPNOTSUPP)
		return fail("required nohz boundary");
	printf("M67_NOHZ_BOUNDARY_OK\n");
	release = domain;
	release.operation = AGI_LC_EXEC_DOMAIN_RELEASE;
	release.correlation = 67007;
	if (ioctl(fd, AGI_LC_EXECUTION_DOMAIN, &release) < 0 ||
	    release.state != AGI_LC_EXEC_DOMAIN_STATE_RELEASED)
		return fail("domain release");
	printf("M67_DOMAIN_RELEASE_OK\nM67_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
