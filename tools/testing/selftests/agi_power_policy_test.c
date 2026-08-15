#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M70_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.correlation = 70001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	agent.agent_id = light.agent_id;
	agent.correlation = 70002;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

int main(void)
{
	int fd, flags, i, found_event = 0;
	struct agi_lc_power_policy policy = {
		.size = sizeof(policy),
		.operation = AGI_LC_POWER_POLICY_SET,
		.flags = AGI_LC_POWER_POLICY_FLAG_CPU_LATENCY_QOS,
		.profile = AGI_LC_POWER_PROFILE_INFERENCE,
		.requested_features = AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS |
			AGI_LC_POWER_POLICY_FEATURE_DEVICE_WAKE_LATENCY |
			AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET,
		.min_cpu_util = 128,
		.max_cpu_util = 900,
		.cpu_latency_us = 1000,
		.power_budget_uw = 1000000,
		.power_window_us = 10000,
		.correlation = 70003,
	};
	struct agi_lc_power_policy query, stale, required, release;
	struct agi_lc_record record;
	ssize_t n;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (setup_session(fd) < 0)
		return fail("session");

	if (ioctl(fd, AGI_LC_POWER_POLICY, &policy) < 0 ||
	    !policy.policy_id || !policy.capability ||
	    policy.state != AGI_LC_POWER_POLICY_STATE_ACTIVE ||
	    policy.agent_id == 0 || policy.task_id == 0 ||
	    !(policy.available_features &
	      AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS) ||
	    !(policy.applied_features &
	      AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS) ||
	    !(policy.unsupported_features &
	      AGI_LC_POWER_POLICY_FEATURE_DEVICE_WAKE_LATENCY) ||
	    !(policy.unsupported_features &
	      AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET) ||
	    policy.status != -EOPNOTSUPP)
		return fail("policy set");
	printf("M70_POWER_POLICY_SET_OK id=%llu applied=0x%llx unsupported=0x%llx\n",
	       (unsigned long long)policy.policy_id,
	       (unsigned long long)policy.applied_features,
	       (unsigned long long)policy.unsupported_features);

	memset(&query, 0, sizeof(query));
	query.size = sizeof(query);
	query.operation = AGI_LC_POWER_POLICY_QUERY;
	query.policy_id = policy.policy_id;
	query.capability = policy.capability;
	query.correlation = 70004;
	if (ioctl(fd, AGI_LC_POWER_POLICY, &query) < 0 ||
	    query.state != AGI_LC_POWER_POLICY_STATE_ACTIVE ||
	    query.applied_features != policy.applied_features ||
	    query.unsupported_features != policy.unsupported_features)
		return fail("policy query");
	printf("M70_POWER_POLICY_QUERY_OK generation=%llu\n",
	       (unsigned long long)query.generation);

	memset(&stale, 0, sizeof(stale));
	stale.size = sizeof(stale);
	stale.operation = AGI_LC_POWER_POLICY_QUERY;
	stale.policy_id = policy.policy_id;
	stale.capability = policy.capability + 1;
	stale.correlation = 70005;
	if (ioctl(fd, AGI_LC_POWER_POLICY, &stale) == 0 || errno != EACCES)
		return fail("stale policy capability accepted");
	printf("M70_STALE_POLICY_CAPABILITY_REJECT_OK\n");

	memset(&required, 0, sizeof(required));
	required.size = sizeof(required);
	required.operation = AGI_LC_POWER_POLICY_SET;
	required.flags = AGI_LC_POWER_POLICY_FLAG_REQUIRE_ALL;
	required.profile = AGI_LC_POWER_PROFILE_INFERENCE;
	required.requested_features = AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS |
		AGI_LC_POWER_POLICY_FEATURE_DEVICE_WAKE_LATENCY;
	required.cpu_latency_us = 1000;
	required.correlation = 70006;
	if (ioctl(fd, AGI_LC_POWER_POLICY, &required) == 0 || errno != EOPNOTSUPP)
		return fail("required unsupported policy accepted");
	printf("M70_REQUIRED_FEATURE_REFUSAL_OK\n");

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	for (i = 0; i < 64; i++) {
		n = read(fd, &record, sizeof(record));
		if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n != (ssize_t)sizeof(record))
			break;
		if (record.type == AGI_LC_EVENT_POWER_POLICY &&
		    record.metadata == policy.policy_id) {
			found_event = 1;
			break;
		}
	}
	if (!found_event)
		return fail("power policy event delivery");
	printf("M70_POWER_POLICY_EVENT_OK\n");

	memset(&release, 0, sizeof(release));
	release.size = sizeof(release);
	release.operation = AGI_LC_POWER_POLICY_RELEASE;
	release.policy_id = policy.policy_id;
	release.capability = policy.capability;
	release.correlation = 70007;
	if (ioctl(fd, AGI_LC_POWER_POLICY, &release) < 0 ||
	    release.state != AGI_LC_POWER_POLICY_STATE_RELEASED ||
	    release.applied_features != 0)
		return fail("policy release");
	printf("M70_POWER_POLICY_RELEASE_OK generation=%llu\n",
	       (unsigned long long)release.generation);

	close(fd);
	printf("M70_SELFTEST_EXIT=0\n");
	return 0;
}
