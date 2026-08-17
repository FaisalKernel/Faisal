#include "../../faisal-launcher/faisal_sandbox_launcher.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static void fail(const char *name, int rc)
{
	fprintf(stderr, "M114_LAUNCHER_FAIL %s rc=%d errno=%d\n", name, rc, errno);
	exit(1);
}

int main(void)
{
	const char *const argv[] = { "/tmp/faisal_launcher_probe", NULL };
	struct fsl_config config = {
		.root = "/",
		.require_namespaces = 0,
		.require_cgroup = 0,
		.require_landlock = 1,
		.require_seccomp = 1,
	};
	struct fsl_config required_cgroup = config;
	int status;
	if (fsl_launch(&config, argv, 1, &status) != 0 || status != 0) {
		fprintf(stderr, "M114_LAUNCHER_STATUS=%d\n", status);
		fail("ENFORCED_LAUNCH", FSL_MAX_ARGS);
	}
	printf("M114_TRUSTED_LAUNCHER_LANDLOCK_SECCOMP_OK\n");
	required_cgroup.require_cgroup = 1;
	required_cgroup.cgroup_root = "/faisal-nonexistent-cgroup-root";
	if (fsl_launch(&required_cgroup, argv, 1, &status) != -EPERM)
		fail("CGROUP_FAIL_CLOSED", -EPERM);
	printf("M114_TRUSTED_LAUNCHER_CGROUP_FAIL_CLOSED_OK\n");
	printf("M114_LAUNCHER_SELFTEST_EXIT=0\n");
	return 0;
}
