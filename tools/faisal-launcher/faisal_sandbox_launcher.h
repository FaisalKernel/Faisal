#ifndef FAISAL_SANDBOX_LAUNCHER_H
#define FAISAL_SANDBOX_LAUNCHER_H
#include <stddef.h>
#include <stdint.h>
#define FSL_MAX_PATH 4096U
#define FSL_MAX_ARGS 64U
struct fsl_config {
	const char *root;
	const char *cgroup_root;
	const char *tenant;
	uint64_t memory_max;
	uint64_t cpu_quota_us;
	uint64_t cpu_period_us;
	int require_namespaces;
	int require_cgroup;
	int require_landlock;
	int require_seccomp;
};
int fsl_launch(const struct fsl_config *config, const char *const argv[], size_t argc, int *status);
#endif
