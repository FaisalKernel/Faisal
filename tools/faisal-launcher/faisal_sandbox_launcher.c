#define _GNU_SOURCE
#include "faisal_sandbox_launcher.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef FSL_SECCOMP_DEFAULT
#define FSL_SECCOMP_DEFAULT SECCOMP_RET_KILL_PROCESS
#endif
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

static int write_text(const char *path, const char *text)
{
	int fd;
	ssize_t n, len;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	len = (ssize_t)strlen(text);
	n = write(fd, text, (size_t)len);
	close(fd);
	return n == len ? 0 : -EIO;
}

static int write_u64(const char *path, uint64_t value)
{
	char text[32];
	int n = snprintf(text, sizeof(text), "%llu\n", (unsigned long long)value);
	return n > 0 && n < (int)sizeof(text) ? write_text(path, text) : -EINVAL;
}

static int mkdir_one(const char *path)
{
	if (!mkdir(path, 0755) || errno == EEXIST)
		return 0;
	return -errno;
}

static int setup_cgroup(const struct fsl_config *cfg, pid_t pid)
{
	char path[FSL_MAX_PATH], dir[FSL_MAX_PATH], pid_text[32];
	int n;
	if (!cfg->cgroup_root || !cfg->cgroup_root[0])
		return cfg->require_cgroup ? -ENOTSUP : 0;
	if (snprintf(dir, sizeof(dir), "%s/faisal-%s", cfg->cgroup_root,
		     cfg->tenant && cfg->tenant[0] ? cfg->tenant : "tenant") >= (int)sizeof(dir))
		return -ENAMETOOLONG;
	if (mkdir_one(dir) < 0 && errno != EEXIST)
		return -errno;
	if (cfg->memory_max) {
		n = snprintf(path, sizeof(path), "%s/memory.max", dir);
		if (n < 0 || n >= (int)sizeof(path) || write_u64(path, cfg->memory_max) < 0)
			return -EPERM;
	}
	if (cfg->cpu_quota_us && cfg->cpu_period_us) {
		n = snprintf(path, sizeof(path), "%s/cpu.max", dir);
		if (n < 0 || n >= (int)sizeof(path))
			return -ENAMETOOLONG;
		if (snprintf(pid_text, sizeof(pid_text), "%llu %llu\n",
			     (unsigned long long)cfg->cpu_quota_us,
			     (unsigned long long)cfg->cpu_period_us) >= (int)sizeof(pid_text) ||
		    write_text(path, pid_text) < 0)
			return -EPERM;
	}
	if (snprintf(path, sizeof(path), "%s/cgroup.procs", dir) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	if (snprintf(pid_text, sizeof(pid_text), "%ld\n", (long)pid) >= (int)sizeof(pid_text))
		return -EINVAL;
	return write_text(path, pid_text);
}

static int install_landlock(const char *root)
{
	struct landlock_ruleset_attr ruleset = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
			LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
			LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
			LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
			LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
			LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
			LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM |
			LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE,
	};
	struct landlock_path_beneath_attr path_rule;
	int ruleset_fd, root_fd;
	ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
	if (ruleset_fd < 0)
		return -errno;
	root_fd = open(root, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (root_fd < 0) {
		close(ruleset_fd);
		return -errno;
	}
	memset(&path_rule, 0, sizeof(path_rule));
	path_rule.allowed_access = ruleset.handled_access_fs;
	path_rule.parent_fd = root_fd;
	if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
			    &path_rule, 0) < 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
		int err = -errno;
		close(root_fd); close(ruleset_fd);
		return err;
	}
	close(root_fd); close(ruleset_fd);
	return 0;
}

#ifdef FSL_TRACE_OUTPUT
static void fsl_trace_write(int fd, const char *text, size_t length)
{
	if (write(fd, text, length) < 0)
		_exit(125);
}
#endif

#ifdef FSL_TRACE_SIGSYS
static void fsl_sigsys(int signal_number, siginfo_t *info, void *context)
{
	char text[96];
	int length;
	(void)signal_number;
	(void)context;
	length = snprintf(text, sizeof(text), "FSL_SIGSYS syscall=%d\n",
			  info ? info->si_syscall : -1);
		if (length > 0 && write(STDERR_FILENO, text, (size_t)length) < 0)
			_exit(125);
		_exit(125);
}
#endif

#define FSL_ALLOW(n) \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (n), 0, 1), \
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static int install_seccomp(void)
{
#ifdef FSL_TRACE_SIGSYS
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_sigaction = fsl_sigsys;
	action.sa_flags = SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGSYS, &action, NULL) < 0)
		return -errno;
#endif
	struct sock_filter filter[] = {
#ifndef FSL_SKIP_ARCH_CHECK
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
		FSL_ALLOW(__NR_read), FSL_ALLOW(__NR_write), FSL_ALLOW(__NR_close),
		FSL_ALLOW(__NR_openat), FSL_ALLOW(__NR_newfstatat), FSL_ALLOW(__NR_fstat),
		FSL_ALLOW(__NR_lseek), FSL_ALLOW(__NR_exit), FSL_ALLOW(__NR_exit_group),
		FSL_ALLOW(__NR_execve), FSL_ALLOW(__NR_execveat), FSL_ALLOW(__NR_brk),
		FSL_ALLOW(__NR_mmap), FSL_ALLOW(__NR_munmap), FSL_ALLOW(__NR_mprotect),
		FSL_ALLOW(__NR_arch_prctl), FSL_ALLOW(__NR_set_tid_address),
		FSL_ALLOW(__NR_set_robust_list), FSL_ALLOW(__NR_rseq), FSL_ALLOW(__NR_rt_sigaction),
		FSL_ALLOW(__NR_rt_sigprocmask), FSL_ALLOW(__NR_rt_sigreturn),
		FSL_ALLOW(__NR_dup2), FSL_ALLOW(__NR_ioctl), FSL_ALLOW(__NR_futex), FSL_ALLOW(__NR_getpid),
		FSL_ALLOW(__NR_getppid), FSL_ALLOW(__NR_gettid), FSL_ALLOW(__NR_getuid),
		FSL_ALLOW(__NR_geteuid), FSL_ALLOW(__NR_getgid), FSL_ALLOW(__NR_getegid),
		FSL_ALLOW(__NR_getrandom), FSL_ALLOW(__NR_uname), FSL_ALLOW(__NR_readlink),
		FSL_ALLOW(__NR_readlinkat), FSL_ALLOW(__NR_faccessat), FSL_ALLOW(__NR_faccessat2),
		FSL_ALLOW(__NR_statx), FSL_ALLOW(__NR_prlimit64), FSL_ALLOW(__NR_setrlimit),
		FSL_ALLOW(__NR_getrlimit), FSL_ALLOW(__NR_madvise), FSL_ALLOW(__NR_mremap),
		FSL_ALLOW(__NR_prctl), FSL_ALLOW(__NR_fcntl), FSL_ALLOW(__NR_dup),
		FSL_ALLOW(__NR_dup3), FSL_ALLOW(__NR_getcwd), FSL_ALLOW(__NR_pread64),
		FSL_ALLOW(__NR_getdents64), FSL_ALLOW(__NR_ftruncate),
		BPF_STMT(BPF_RET | BPF_K, FSL_SECCOMP_DEFAULT),
	};
	struct sock_fprog program = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0)
		return -errno;
	return 0;
}

static int child_setup(const struct fsl_config *cfg)
{
	int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS;
	if (unshare(flags) < 0) {
		if (cfg->require_namespaces)
			return -errno;
	} else if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0 &&
		   cfg->require_namespaces) {
		return -errno;
	}
	if (cfg->root && chdir(cfg->root) < 0)
		return -errno;
	if (cfg->require_landlock) {
		int rc = install_landlock(cfg->root ? cfg->root : "/");
		if (rc < 0 && cfg->require_landlock)
			return rc;
	}
	if (cfg->require_seccomp) {
		int rc = install_seccomp();
		if (rc < 0 && cfg->require_seccomp)
			return rc;
	}
	return 0;
}

int fsl_launch(const struct fsl_config *config, const char *const argv[],
		size_t argc, int *status)
{
	pid_t pid;
	int pipefd[2], child_rc, wait_status;
	char output[256];
	ssize_t output_n;
	if (!config || !argv || !argv[0] || argc == 0 || argc > FSL_MAX_ARGS ||
		!status || !config->root || !config->root[0])
		return -EINVAL;
	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return -errno;
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]); close(pipefd[1]);
		return -errno;
	}
	if (!pid) {
		close(pipefd[0]);
		child_rc = child_setup(config);
#ifdef FSL_TRACE_OUTPUT
		fsl_trace_write(pipefd[1], "FSL_AFTER_SETUP\n", 16);
#endif
		if (child_rc < 0) {
			char error_text[64];
			int error_length = snprintf(error_text, sizeof(error_text),
						    "FSL_CHILD_SETUP_RC=%d\n", child_rc);
			if (error_length > 0 && write(pipefd[1], error_text,
						       (size_t)error_length) < 0)
				_exit(125);
			_exit(125);
		}
		if (dup2(pipefd[1], STDOUT_FILENO) < 0)
			_exit(125);
#ifdef FSL_TRACE_OUTPUT
		fsl_trace_write(STDOUT_FILENO, "FSL_AFTER_DUP2_OUT\n", 19);
#endif
		if (dup2(pipefd[1], STDERR_FILENO) < 0)
			_exit(125);
#ifdef FSL_TRACE_OUTPUT
		fsl_trace_write(STDERR_FILENO, "FSL_AFTER_DUP2_ERR\n", 19);
#endif
		close(pipefd[1]);
#ifdef FSL_TRACE_OUTPUT
		fsl_trace_write(STDERR_FILENO, "FSL_BEFORE_EXEC\n", 16);
#endif
		execvp(argv[0], (char *const *)argv);
		_exit(126);
	}
	close(pipefd[1]);
	if (setup_cgroup(config, pid) < 0 && config->require_cgroup) {
		kill(pid, SIGKILL);
		close(pipefd[0]);
		waitpid(pid, &wait_status, 0);
		return -EPERM;
	}
	while ((output_n = read(pipefd[0], output, sizeof(output))) > 0) {
#ifdef FSL_TRACE_OUTPUT
		if (write(STDERR_FILENO, output, (size_t)output_n) < 0)
			break;
#endif
	}
	close(pipefd[0]);
	if (waitpid(pid, &wait_status, 0) < 0)
		return -errno;
	*status = wait_status;
	return 0;
}
