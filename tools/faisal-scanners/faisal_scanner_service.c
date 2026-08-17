#define _GNU_SOURCE
#include "faisal_scanner_service.h"
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void digest_init(EVP_MD_CTX **ctx)
{
	*ctx = EVP_MD_CTX_new();
	if (*ctx)
		(void)EVP_DigestInit_ex(*ctx, EVP_sha256(), NULL);
}

static void digest_finish(EVP_MD_CTX *ctx, uint8_t out[FAS_DIGEST_SIZE])
{
	unsigned int n = 0;
	if (!ctx) {
		memset(out, 0, FAS_DIGEST_SIZE);
		return;
	}
	(void)EVP_DigestFinal_ex(ctx, out, &n);
	EVP_MD_CTX_free(ctx);
}

static int set_result(struct fas_result *out, uint32_t kind, uint32_t status,
			int exit_code, const char *summary)
{
	if (!out)
		return FAS_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->kind = kind;
	out->status = status;
	out->exit_code = exit_code;
	if (summary)
		(void)snprintf(out->summary, sizeof(out->summary), "%s", summary);
	return FAS_PASS;
}

static int run_bounded(const char *root, const char *const argv[], size_t argc,
			struct fas_result *out)
{
	int pipefd[2], status, rc = FAS_IO;
	pid_t pid;
	char buffer[1024];
	ssize_t n;
	uint64_t total = 0;
	EVP_MD_CTX *digest = NULL;
	(void)argc;
	if (!root || !root[0] || !argv || !argv[0] || !out)
		return FAS_ARGUMENT;
	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return FAS_IO;
	digest_init(&digest);
	pid = fork();
	if (pid < 0) {
		close(pipefd[0]); close(pipefd[1]);
		EVP_MD_CTX_free(digest);
		return FAS_IO;
	}
	if (!pid) {
		if (chdir(root) < 0)
			_exit(126);
		if (dup2(pipefd[1], STDOUT_FILENO) < 0 ||
		    dup2(pipefd[1], STDERR_FILENO) < 0)
			_exit(126);
		close(pipefd[0]); close(pipefd[1]);
		execvp(argv[0], (char *const *)argv);
		_exit(errno == ENOENT ? 127 : 126);
	}
	close(pipefd[1]);
	while ((n = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
		uint64_t accepted = n;
		if (total + accepted > FAS_MAX_OUTPUT)
			accepted = FAS_MAX_OUTPUT - total;
		if (accepted && digest)
			(void)EVP_DigestUpdate(digest, buffer, accepted);
		total += accepted;
		if (total >= FAS_MAX_OUTPUT) {
			kill(pid, SIGKILL);
			rc = FAS_LIMIT;
			break;
		}
	}
	close(pipefd[0]);
	if (waitpid(pid, &status, 0) < 0) {
		EVP_MD_CTX_free(digest);
		return FAS_IO;
	}
	if (rc != FAS_LIMIT) {
		if (WIFEXITED(status)) {
			int code = WEXITSTATUS(status);
			set_result(out, FAS_BUILD, code == 0 ? FAS_PASS : FAS_FAIL,
				code, code == 0 ? "trusted build command passed" :
				"trusted build command failed");
			rc = FAS_PASS;
		} else {
			set_result(out, FAS_BUILD, FAS_FAIL, 128 + SIGTERM,
				"trusted build command terminated by signal");
			rc = FAS_PASS;
		}
	}
	out->observed_bytes = total;
	digest_finish(digest, out->evidence_digest);
	return rc;
}

int fas_scan_build(const char *root, const char *const argv[], size_t argc,
		struct fas_result *out)
{
	if (argc == 0 || argc > 32 || !argv || !argv[argc - 1] ||
		argv[argc] != NULL)
		return FAS_ARGUMENT;
	return run_bounded(root, argv, argc, out);
}

static int manifest_name(const char *name)
{
	static const char *const names[] = {
		"Makefile", "Kbuild", "Cargo.toml", "Cargo.lock", "go.mod",
		"go.sum", "package.json", "package-lock.json", "pnpm-lock.yaml",
		"yarn.lock", "requirements.txt", "Pipfile.lock", "poetry.lock",
	};
	size_t i;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (!strcmp(name, names[i]))
			return 1;
	return 0;
}

struct dep_context {
	EVP_MD_CTX *digest;
	uint64_t files;
	uint64_t bytes;
};

static struct dep_context *active_dependency_context;

static int dependency_walk(const char *path, const struct stat *st,
			int type, struct FTW *state)
{
	const char *base;
	int fd;
	unsigned char buffer[4096];
	ssize_t n;
	(void)state;
	if (type != FTW_F || !st || !active_dependency_context ||
		!S_ISREG(st->st_mode))
		return 0;
	base = strrchr(path, '/');
	base = base ? base + 1 : path;
	if (!manifest_name(base))
		return 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	(void)EVP_DigestUpdate(active_dependency_context->digest, path,
				       strlen(path));
	while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
		active_dependency_context->bytes += (uint64_t)n;
		if (active_dependency_context->bytes > (16U * 1024U * 1024U)) {
			close(fd);
			return 1;
		}
		(void)EVP_DigestUpdate(active_dependency_context->digest, buffer,
				       (size_t)n);
	}
	close(fd);
	active_dependency_context->files++;
	return 0;
}

int fas_scan_dependencies(const char *root, struct fas_result *out)
{
	struct dep_context context;
	int walk_rc;
	if (!root || !root[0] || !out)
		return FAS_ARGUMENT;
	memset(&context, 0, sizeof(context));
	digest_init(&context.digest);
	if (!context.digest)
		return FAS_IO;
	active_dependency_context = &context;
	walk_rc = nftw(root, dependency_walk, 16, FTW_PHYS);
	active_dependency_context = NULL;
	if (walk_rc != 0 && context.bytes > (16U * 1024U * 1024U)) {
		digest_finish(context.digest, out->evidence_digest);
		return set_result(out, FAS_DEPENDENCY, FAS_LIMIT, -1,
				  "dependency manifest byte limit exceeded");
	}
	memset(out, 0, sizeof(*out));
	out->kind = FAS_DEPENDENCY;
	out->status = walk_rc < 0 ? FAS_IO : FAS_PASS;
	out->observed_files = context.files;
	out->observed_bytes = context.bytes;
	digest_finish(context.digest, out->evidence_digest);
	(void)snprintf(out->summary, sizeof(out->summary),
		       "dependency manifests=%llu bytes=%llu",
		       (unsigned long long)out->observed_files,
		       (unsigned long long)out->observed_bytes);
	return FAS_PASS;
}

int fas_scan_vulnerabilities(const char *root, struct fas_result *out)
{
	static const char *const tools[] = { "grype", "osv-scanner", "trivy" };
	char path[256];
	size_t i;
	if (!root || !out)
		return FAS_ARGUMENT;
	for (i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) {
		const char *const argv[] = { tools[i], "dir", ".", "--quiet", NULL };
		if (!access(tools[i], X_OK) ||
		    (snprintf(path, sizeof(path), "/usr/bin/%s", tools[i]) < (int)sizeof(path) &&
		     !access(path, X_OK))) {
			int rc = run_bounded(root, argv, 4, out);
			if (rc == FAS_PASS)
				out->kind = FAS_VULNERABILITY;
			return rc;
		}
	}
	set_result(out, FAS_VULNERABILITY, FAS_UNAVAILABLE, -1,
		"no supported vulnerability scanner installed; gate must fail closed");
	return FAS_PASS;
}
