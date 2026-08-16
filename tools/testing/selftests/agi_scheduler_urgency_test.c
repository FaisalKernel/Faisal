// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <linux/sched/types.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef SCHED_FLAG_UTIL_CLAMP_MIN
#define SCHED_FLAG_UTIL_CLAMP_MIN (1U << 5)
#endif
#ifndef SCHED_FLAG_UTIL_CLAMP_MAX
#define SCHED_FLAG_UTIL_CLAMP_MAX (1U << 6)
#endif
#ifndef SCHED_CAPACITY_SCALE
#define SCHED_CAPACITY_SCALE 1024U
#endif

#define M101_SCHED_BENCH_ITERATIONS 32U

static int fail(const char *what)
{
	fprintf(stderr, "M101_SCHED_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.correlation = 101001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	agent.agent_id = light.agent_id;
	agent.correlation = 101002;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

static int get_sched_attr(struct sched_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->size = sizeof(*attr);
	return (int)syscall(SYS_sched_getattr, 0, attr, sizeof(*attr), 0);
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void)
{
	struct agi_lc_sched_hint hint = {
		.size = sizeof(hint),
		.priority = 900,
		.state = AGI_LC_AGENT_STATE_RUNNING,
		.dependency_count = 2,
		.unblock_credit = 0,
		.deadline_ns = monotonic_ns() + 5000000ULL,
		.latency_sensitive = 1,
		.util_min = 0,
		.util_max = SCHED_CAPACITY_SCALE,
		.correlation = 101003,
	};
	struct agi_lc_sched_hint query = { .size = sizeof(query) };
	struct sched_attr attr;
	uint64_t bench_start;
	uint64_t bench_end;
	uint64_t bench_total;
	unsigned int index;
	int fd;
	int ret;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (setup_session(fd) < 0)
		return fail("session");
	ret = ioctl(fd, AGI_LC_SET_SCHED_HINT, &hint);
	if (ret < 0 && errno != EOPNOTSUPP)
		return fail("set deadline hint");
	if (ret < 0) {
		printf("M101_SCHED_UCLAMP_UNAVAILABLE_OK errno=%d\n", errno);
		printf("M101_SCHED_SELFTEST_EXIT=0\n");
		close(fd);
		return 0;
	}
	if (hint.agent_id == 0 || hint.deadline_ns == 0 || !hint.latency_sensitive)
		return fail("set response");
	if (get_sched_attr(&attr) < 0)
		return fail("sched_getattr");
#ifdef M101_BASELINE
	if (attr.sched_util_min != 0)
		return fail("baseline clamp changed");
	printf("M101_SCHED_BASELINE_NO_URGENCY_OK util_min=%u\n",
	       attr.sched_util_min);
#else
	if (attr.sched_util_min < SCHED_CAPACITY_SCALE) {
		fprintf(stderr, "M101_SCHED_ATTR flags=0x%llx min=%u max=%u policy=%u\n",
			(unsigned long long)attr.sched_flags, attr.sched_util_min,
			attr.sched_util_max, attr.sched_policy);
		return fail("deadline urgency clamp");
	}
	printf("M101_SCHED_DEADLINE_URGENCY_OK util_min=%u\n",
	       attr.sched_util_min);
#endif
	if (ioctl(fd, AGI_LC_GET_SCHED_HINT, &query) < 0)
		return fail("get hint");
	if (query.agent_id != hint.agent_id ||
	    query.deadline_ns != hint.deadline_ns ||
	    query.latency_sensitive != 1)
		return fail("hint readback");
	printf("M101_SCHED_HINT_READBACK_OK\n");
	bench_start = monotonic_ns();
	for (index = 0; index < M101_SCHED_BENCH_ITERATIONS; index++) {
		hint.agent_id = 0;
		hint.correlation++;
		hint.deadline_ns = monotonic_ns() + 5000000ULL;
		if (ioctl(fd, AGI_LC_SET_SCHED_HINT, &hint) < 0)
			return fail("benchmark set hint");
	}
	bench_end = monotonic_ns();
	bench_total = bench_end - bench_start;
	printf("M101_SCHED_BENCH_ITERATIONS=%u\n", M101_SCHED_BENCH_ITERATIONS);
	printf("M101_SCHED_BENCH_TOTAL_NS=%llu\n",
	       (unsigned long long)bench_total);
	printf("M101_SCHED_BENCH_MEAN_NS=%llu\n",
	       (unsigned long long)(bench_total / M101_SCHED_BENCH_ITERATIONS));
	printf("M101_SCHED_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
