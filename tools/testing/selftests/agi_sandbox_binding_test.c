// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *what)
{
	perror(what);
	exit(1);
}

static void expect_errno(const char *what, int expected)
{
	if (errno != expected) {
		fprintf(stderr, "%s: expected errno=%d got=%d\n", what, expected, errno);
		exit(1);
	}
}

int main(void)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_sandbox_binding bind = {
		.size = sizeof(bind),
		.operation = AGI_LC_SANDBOX_BIND,
		.flags = AGI_LC_SANDBOX_FLAGS_ALL,
	};
	struct agi_lc_sandbox_binding query = {
		.size = sizeof(query),
		.operation = AGI_LC_SANDBOX_QUERY,
	};
	struct agi_lc_sandbox_binding release = {
		.size = sizeof(release),
		.operation = AGI_LC_SANDBOX_RELEASE,
	};
	pid_t child;
	int fd, status;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fail("M114_OPEN");
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0)
		fail("M114_CREATE");
	if (ioctl(fd, AGI_LC_SANDBOX, &bind) < 0)
		fail("M114_BIND");
	if (bind.state != AGI_LC_SANDBOX_STATE_BOUND || !bind.binding_id ||
	    !bind.generation || !bind.owner_tgid || !bind.pid_namespace ||
	    !bind.mount_namespace || !bind.net_namespace ||
	    !bind.ipc_namespace || !bind.uts_namespace ||
	    !bind.user_namespace || !bind.cgroup_id) {
		fprintf(stderr, "M114_BIND_ATTESTATION_INVALID\n");
		return 1;
	}
	printf("M114_SANDBOX_BIND_ATTESTED_OK pidns=%llu cgroup=%llu\n",
	       (unsigned long long)bind.pid_namespace,
	       (unsigned long long)bind.cgroup_id);

	if (ioctl(fd, AGI_LC_SANDBOX, &query) < 0)
		fail("M114_QUERY");
	if (query.state != AGI_LC_SANDBOX_STATE_BOUND || query.status != 0)
		return 1;
	printf("M114_SANDBOX_QUERY_OK generation=%llu\n",
	       (unsigned long long)query.generation);

	child = fork();
	if (child < 0)
		fail("M114_FORK");
	if (child == 0) {
		struct agi_lc_sandbox_binding child_query = {
			.size = sizeof(child_query),
			.operation = AGI_LC_SANDBOX_QUERY,
		};
		if (ioctl(fd, AGI_LC_SANDBOX, &child_query) >= 0)
			_exit(2);
		expect_errno("M114_TGID_DRIFT", EXDEV);
		printf("M114_SANDBOX_TGID_DRIFT_DENIED_OK\n");
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return 1;

	if (ioctl(fd, AGI_LC_SANDBOX, &release) < 0)
		fail("M114_RELEASE");
	if (release.state != AGI_LC_SANDBOX_STATE_REVOKED)
		return 1;
	printf("M114_SANDBOX_RELEASE_OK\nM114_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
