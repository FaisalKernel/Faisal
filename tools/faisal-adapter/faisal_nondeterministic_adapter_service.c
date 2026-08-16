#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "faisal_nondeterministic_adapter_service.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define M102_LANDLOCK_RULE_PATH_BENEATH 1U
#define M102_LANDLOCK_UNAVAILABLE (-100)
#define M102_LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define M102_LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define M102_LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define M102_LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define M102_LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define M102_LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define M102_LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define M102_LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define M102_LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define M102_LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define M102_LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define M102_LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define M102_SECCOMP_MODE_FILTER 2
#define M102_SECCOMP_RET_KILL_PROCESS 0x80000000U
#define M102_SECCOMP_RET_ALLOW 0x7fff0000U
#define M102_AUDIT_ARCH_X86_64 0xc000003eU
#define M102_BPF_LD 0x00U
#define M102_BPF_W 0x00U
#define M102_BPF_ABS 0x20U
#define M102_BPF_JMP 0x05U
#define M102_BPF_JEQ 0x10U
#define M102_BPF_K 0x00U
#define M102_BPF_RET 0x06U
#define M102_BPF_ALU 0x04U
#define M102_BPF_AND 0x50U
#define M102_READONLY_OPEN_FLAGS (O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND | O_TMPFILE)
#define M102_RECORD_EFFECT 1U
#define M102_MAX_IMPLEMENTATION_BYTES (64U * 1024U * 1024U)

struct m102_landlock_ruleset_attr {
	uint64_t handled_access_fs;
};

struct m102_landlock_path_beneath_attr {
	uint64_t allowed_access;
	int32_t parent_fd;
};

struct m102_seccomp_data {
	int32_t nr;
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t args[6];
};

struct m102_sock_filter {
	uint16_t code;
	uint8_t jt;
	uint8_t jf;
	uint32_t k;
};

struct m102_sock_fprog {
	unsigned short len;
	struct m102_sock_filter *filter;
};

#define M102_BPF_STMT(opcode, value) ((struct m102_sock_filter){ \
	.code = (uint16_t)(opcode), .jt = 0, .jf = 0, .k = (uint32_t)(value) })
#define M102_BPF_JUMP(opcode, value, true_jump, false_jump) \
	((struct m102_sock_filter){ .code = (uint16_t)(opcode), \
	 .jt = (uint8_t)(true_jump), .jf = (uint8_t)(false_jump), \
	 .k = (uint32_t)(value) })

struct m102_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t record_size;
	uint64_t sequence;
	uint8_t digest[M102_DIGEST_SIZE];
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return M102_ERR_IO;
		}
		if (!written)
			return M102_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return M102_OK;
}

static int read_exact_or_eof(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t total = 0;

	while (total < length) {
		ssize_t received = read(fd, cursor + total, length - total);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			return M102_ERR_IO;
		}
		if (!received)
			return total ? M102_ERR_CORRUPT : 1;
		total += (size_t)received;
	}
	return M102_OK;
}

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[M102_DIGEST_SIZE])
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = M102_ERR_IO;

	if (!context || (!data && length) || !digest)
		goto out;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, data, length) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M102_DIGEST_SIZE)
		result = M102_OK;
out:
	EVP_MD_CTX_free(context);
	return result;
}

static int digest_file_contents(const char *path,
				uint8_t digest[M102_DIGEST_SIZE])
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	struct stat stat_buffer;
	unsigned char buffer[8192];
	int fd = -1;
	int result = M102_ERR_IO;

	if (!context || !path || !digest)
		goto out;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0 || fstat(fd, &stat_buffer) < 0 ||
	    !S_ISREG(stat_buffer.st_mode) || stat_buffer.st_size < 0 ||
	    (uint64_t)stat_buffer.st_size > M102_MAX_IMPLEMENTATION_BYTES)
		goto out;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
		goto out;
	for (;;) {
		ssize_t received = read(fd, buffer, sizeof(buffer));

		if (received < 0) {
			if (errno == EINTR)
				continue;
			goto out;
		}
		if (!received)
			break;
		if (EVP_DigestUpdate(context, buffer, (size_t)received) != 1)
			goto out;
	}
	if (EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M102_DIGEST_SIZE)
		result = M102_OK;
out:
	if (fd >= 0)
		close(fd);
	EVP_MD_CTX_free(context);
	return result;
}

static int nonzero_digest(const uint8_t digest[M102_DIGEST_SIZE])
{
	unsigned int index;

	if (!digest)
		return 0;
	for (index = 0; index < M102_DIGEST_SIZE; index++)
		if (digest[index])
			return 1;
	return 0;
}

static int copy_text(char *destination, size_t destination_size,
			     const char *source, int allow_empty)
{
	size_t length;

	if (!destination || !destination_size || !source)
		return M102_ERR_ARGUMENT;
	length = strnlen(source, destination_size);
	if ((!allow_empty && !length) || length >= destination_size)
		return M102_ERR_ARGUMENT;
	memcpy(destination, source, length + 1);
	return M102_OK;
}

static int lock_service(struct m102_service *service)
{
	if (!service || !service->lock_initialized)
		return M102_ERR_ARGUMENT;
	return pthread_mutex_lock(&service->lock) == 0 ? M102_OK : M102_ERR_STATE;
}

static void unlock_service(struct m102_service *service)
{
	(void)pthread_mutex_unlock(&service->lock);
}

static struct m102_effect *find_effect(struct m102_service *service,
					       uint64_t effect_id)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (service->effects[index].effect_id == effect_id)
			return &service->effects[index];
	return NULL;
}

static const struct m102_effect *find_effect_const(
		const struct m102_service *service, uint64_t effect_id)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (service->effects[index].effect_id == effect_id)
			return &service->effects[index];
	return NULL;
}

static struct m102_effect *find_key(struct m102_service *service,
					    const char *key)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (!strcmp(service->effects[index].idempotency_key, key))
			return &service->effects[index];
	return NULL;
}

static int digest_effect(const struct m102_effect *effect,
			 uint8_t digest[M102_DIGEST_SIZE])
{
	struct m102_effect canonical;

	if (!effect)
		return M102_ERR_ARGUMENT;
	canonical = *effect;
	memset(canonical.post_state_digest, 0,
	       sizeof(canonical.post_state_digest));
	return digest_bytes(&canonical, sizeof(canonical), digest);
}

static int append_effect(struct m102_service *service,
			 const struct m102_effect *effect)
{
	struct m102_disk_header header;
	uint8_t digest[M102_DIGEST_SIZE];
	int result;

	if (!service || service->effect_fd < 0 || !effect)
		return M102_ERR_ARGUMENT;
	result = digest_effect(effect, digest);
	if (result != M102_OK)
		return result;
	memset(&header, 0, sizeof(header));
	header.magic = M102_EFFECT_JOURNAL_MAGIC;
	header.version = M102_EFFECT_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.record_size = sizeof(header) + sizeof(*effect);
	header.sequence = service->effect_sequence + 1;
	memcpy(header.digest, digest, sizeof(header.digest));
	result = write_all(service->effect_fd, &header, sizeof(header));
	if (result == M102_OK)
		result = write_all(service->effect_fd, effect, sizeof(*effect));
	if (result == M102_OK && fdatasync(service->effect_fd) < 0)
		result = M102_ERR_IO;
	if (result == M102_OK)
		service->effect_sequence = header.sequence;
	return result;
}

static int apply_effect(struct m102_service *service,
			const struct m102_effect *effect)
{
	struct m102_effect *existing = find_effect(service, effect->effect_id);

	if (existing) {
		*existing = *effect;
		return M102_OK;
	}
	if (service->effect_count >= M102_MAX_EFFECTS)
		return M102_ERR_FULL;
	service->effects[service->effect_count++] = *effect;
	return M102_OK;
}

static int validate_effect(const struct m102_effect *effect)
{
	if (!effect || !effect->effect_id || !effect->invocation_id ||
	    !effect->mission_id || !effect->tool_id || !effect->agent_id ||
	    !effect->authority_lease_id || effect->state < M102_EFFECT_PENDING ||
	    effect->state > M102_EFFECT_AMBIGUOUS ||
	    !nonzero_digest(effect->idempotency_digest) ||
	    !nonzero_digest(effect->input_digest) ||
	    !nonzero_digest(effect->policy_digest) ||
	    !nonzero_digest(effect->pre_state_digest) ||
	    !effect->idempotency_key[0] || !effect->scope[0] ||
	    !effect->program[0] ||
	    effect->sandbox_kind != M102_SANDBOX_KIND_LANDLOCK_SECCOMP_NETWORK_DENY)
		return M102_ERR_CORRUPT;
	return M102_OK;
}

static int replay_unlocked(struct m102_service *service)
{
	struct m102_disk_header header;
	uint64_t last_sequence = 0;
	int result;

	if (lseek(service->effect_fd, 0, SEEK_SET) < 0)
		return M102_ERR_IO;
	service->effect_count = 0;
	service->effect_sequence = 0;
	service->next_effect_id = 1;
	for (;;) {
		struct m102_effect effect;
		uint8_t digest[M102_DIGEST_SIZE];

		result = read_exact_or_eof(service->effect_fd, &header,
					   sizeof(header));
		if (result == 1)
			break;
		if (result != M102_OK || header.magic != M102_EFFECT_JOURNAL_MAGIC ||
		    header.version != M102_EFFECT_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    header.record_size != sizeof(header) + sizeof(effect) ||
		    header.sequence <= last_sequence)
			return M102_ERR_CORRUPT;
		result = read_exact_or_eof(service->effect_fd, &effect, sizeof(effect));
		if (result != M102_OK || validate_effect(&effect) != M102_OK ||
		    digest_effect(&effect, digest) != M102_OK ||
		    memcmp(digest, header.digest, sizeof(digest)))
			return M102_ERR_CORRUPT;
		result = apply_effect(service, &effect);
		if (result != M102_OK)
			return result;
		last_sequence = header.sequence;
		service->effect_sequence = last_sequence;
		if (effect.effect_id >= service->next_effect_id)
			service->next_effect_id = effect.effect_id + 1;
	}
	if (lseek(service->effect_fd, 0, SEEK_END) < 0)
		return M102_ERR_IO;
	return M102_OK;
}

int m102_replay(struct m102_service *service)
{
	int result;

	result = lock_service(service);
	if (result != M102_OK)
		return result;
	result = replay_unlocked(service);
	unlock_service(service);
	return result;
}

static int validate_scope(const char *scratch_dir)
{
	struct stat stat_buffer;

	if (!scratch_dir || !scratch_dir[0] || scratch_dir[0] != '/' ||
	    strstr(scratch_dir, "..") ||
	    strnlen(scratch_dir, M102_MAX_SCOPE) >= M102_MAX_SCOPE ||
	    stat(scratch_dir, &stat_buffer) < 0 || !S_ISDIR(stat_buffer.st_mode))
		return M102_ERR_SCOPE;
	return M102_OK;
}

static int digest_scope(const char *scratch_dir,
			uint8_t digest[M102_DIGEST_SIZE])
{
	struct stat stat_buffer;
	char metadata[M102_MAX_SCOPE + 96];
	int length;

	if (stat(scratch_dir, &stat_buffer) < 0)
		return M102_ERR_SCOPE;
	length = snprintf(metadata, sizeof(metadata), "%s:%llu:%llu:%llu",
			  scratch_dir, (unsigned long long)stat_buffer.st_dev,
			  (unsigned long long)stat_buffer.st_ino,
			  (unsigned long long)stat_buffer.st_mtime);
	if (length < 0 || (size_t)length >= sizeof(metadata))
		return M102_ERR_SCOPE;
	return digest_bytes(metadata, (size_t)length, digest);
}

int m102_command_digest(const char *program, const char *const argv[],
			 size_t argc, uint8_t digest[M102_DIGEST_SIZE])
{
	unsigned char canonical[M102_MAX_PROGRAM + M102_MAX_ARGS * M102_MAX_PROGRAM +
				 M102_DIGEST_SIZE + 64];
	uint8_t implementation_digest[M102_DIGEST_SIZE];
	size_t offset = 0;
	size_t index;
	int length;

	if (!program || !argv || !digest || !argc || argc > M102_MAX_ARGS ||
	    program[0] != '/' || strstr(program, "..") ||
	    strnlen(program, M102_MAX_PROGRAM) >= M102_MAX_PROGRAM)
		return M102_ERR_ARGUMENT;
	length = snprintf((char *)canonical, sizeof(canonical), "M102-CMD-V1:%s",
			  program);
	if (length < 0 || (size_t)length >= sizeof(canonical))
		return M102_ERR_ARGUMENT;
	offset = (size_t)length;
	for (index = 0; index < argc; index++) {
		size_t argument_length;

		if (!argv[index] || strstr(argv[index], ".."))
			return M102_ERR_ARGUMENT;
		argument_length = strnlen(argv[index], M102_MAX_PROGRAM);
		if (argument_length >= M102_MAX_PROGRAM ||
		    offset + argument_length + 1 >= sizeof(canonical))
			return M102_ERR_ARGUMENT;
		canonical[offset++] = '\0';
		memcpy(canonical + offset, argv[index], argument_length);
		offset += argument_length;
	}
		if (digest_file_contents(program, implementation_digest) != M102_OK ||
	    offset + sizeof(implementation_digest) > sizeof(canonical))
		return M102_ERR_PROVENANCE;
	memcpy(canonical + offset, implementation_digest,
	       sizeof(implementation_digest));
	offset += sizeof(implementation_digest);
	return digest_bytes(canonical, offset, digest);
}
static int install_landlock_write_scope(const char *scratch_dir)
{
	struct m102_landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = M102_LANDLOCK_ACCESS_FS_WRITE_FILE |
			M102_LANDLOCK_ACCESS_FS_REMOVE_DIR |
			M102_LANDLOCK_ACCESS_FS_REMOVE_FILE |
			M102_LANDLOCK_ACCESS_FS_MAKE_CHAR |
			M102_LANDLOCK_ACCESS_FS_MAKE_DIR |
			M102_LANDLOCK_ACCESS_FS_MAKE_REG |
			M102_LANDLOCK_ACCESS_FS_MAKE_SOCK |
			M102_LANDLOCK_ACCESS_FS_MAKE_FIFO |
			M102_LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			M102_LANDLOCK_ACCESS_FS_MAKE_SYM |
			M102_LANDLOCK_ACCESS_FS_REFER |
			M102_LANDLOCK_ACCESS_FS_TRUNCATE,
	};
	struct m102_landlock_path_beneath_attr path_attr;
	int ruleset_fd;
	int dir_fd;

	ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset_attr,
			     sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		if (errno == ENOSYS || errno == EOPNOTSUPP || errno == EINVAL)
			return M102_LANDLOCK_UNAVAILABLE;
		return M102_ERR_SANDBOX;
	}
	dir_fd = open(scratch_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		close(ruleset_fd);
		return M102_ERR_SCOPE;
	}
	memset(&path_attr, 0, sizeof(path_attr));
	path_attr.allowed_access = ruleset_attr.handled_access_fs;
	path_attr.parent_fd = dir_fd;
	if (syscall(SYS_landlock_add_rule, ruleset_fd,
			M102_LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
		close(dir_fd);
		close(ruleset_fd);
		return M102_ERR_SANDBOX;
	}
	close(dir_fd);
	close(ruleset_fd);
	return M102_OK;
}

#define M102_ALLOW_SYSCALL(number) \
	M102_BPF_JUMP(M102_BPF_JMP | M102_BPF_JEQ | M102_BPF_K, number, 0, 1), \
	M102_BPF_STMT(M102_BPF_RET | M102_BPF_K, M102_SECCOMP_RET_ALLOW)

static int install_network_deny_seccomp(void)
{
	struct m102_sock_filter filter[] = {
		M102_BPF_STMT(M102_BPF_LD | M102_BPF_W | M102_BPF_ABS,
				offsetof(struct m102_seccomp_data, arch)),
		M102_BPF_JUMP(M102_BPF_JMP | M102_BPF_JEQ | M102_BPF_K,
				M102_AUDIT_ARCH_X86_64, 1, 0),
		M102_BPF_STMT(M102_BPF_RET | M102_BPF_K,
				M102_SECCOMP_RET_KILL_PROCESS),
		M102_BPF_STMT(M102_BPF_LD | M102_BPF_W | M102_BPF_ABS,
				offsetof(struct m102_seccomp_data, nr)),
		M102_ALLOW_SYSCALL(__NR_read),
		M102_ALLOW_SYSCALL(__NR_write),
		M102_ALLOW_SYSCALL(__NR_close),
		M102_BPF_JUMP(M102_BPF_JMP | M102_BPF_JEQ | M102_BPF_K,
				__NR_openat, 0, 5),
		M102_BPF_STMT(M102_BPF_LD | M102_BPF_W | M102_BPF_ABS,
				offsetof(struct m102_seccomp_data, args) +
				2 * sizeof(uint64_t)),
		M102_BPF_STMT(M102_BPF_ALU | M102_BPF_AND | M102_BPF_K,
				M102_READONLY_OPEN_FLAGS),
		M102_BPF_JUMP(M102_BPF_JMP | M102_BPF_JEQ | M102_BPF_K,
				0, 0, 1),
		M102_BPF_STMT(M102_BPF_RET | M102_BPF_K, M102_SECCOMP_RET_ALLOW),
		M102_BPF_STMT(M102_BPF_RET | M102_BPF_K, M102_SECCOMP_RET_KILL_PROCESS),
		M102_ALLOW_SYSCALL(__NR_newfstatat),
		M102_ALLOW_SYSCALL(__NR_fstat),
		M102_ALLOW_SYSCALL(__NR_lseek),
		M102_ALLOW_SYSCALL(__NR_pread64),
		M102_ALLOW_SYSCALL(__NR_pwrite64),
		M102_ALLOW_SYSCALL(__NR_readv),
		M102_ALLOW_SYSCALL(__NR_writev),
		M102_ALLOW_SYSCALL(__NR_readlink),
		M102_ALLOW_SYSCALL(__NR_readlinkat),
		M102_ALLOW_SYSCALL(__NR_access),
		M102_ALLOW_SYSCALL(__NR_faccessat),
		M102_ALLOW_SYSCALL(__NR_faccessat2),
		M102_ALLOW_SYSCALL(__NR_statx),
		M102_ALLOW_SYSCALL(__NR_getdents64),
		M102_ALLOW_SYSCALL(__NR_fcntl),
		M102_ALLOW_SYSCALL(__NR_ioctl),
		M102_ALLOW_SYSCALL(__NR_getcwd),
		M102_ALLOW_SYSCALL(__NR_chdir),
		M102_ALLOW_SYSCALL(__NR_execve),
		M102_ALLOW_SYSCALL(__NR_execveat),
		M102_ALLOW_SYSCALL(__NR_exit),
		M102_ALLOW_SYSCALL(__NR_exit_group),
		M102_ALLOW_SYSCALL(__NR_rt_sigaction),
		M102_ALLOW_SYSCALL(__NR_rt_sigprocmask),
		M102_ALLOW_SYSCALL(__NR_rt_sigreturn),
		M102_ALLOW_SYSCALL(__NR_brk),
		M102_ALLOW_SYSCALL(__NR_mmap),
		M102_ALLOW_SYSCALL(__NR_munmap),
		M102_ALLOW_SYSCALL(__NR_mprotect),
		M102_ALLOW_SYSCALL(__NR_madvise),
		M102_ALLOW_SYSCALL(__NR_arch_prctl),
		M102_ALLOW_SYSCALL(__NR_set_tid_address),
		M102_ALLOW_SYSCALL(__NR_set_robust_list),
		M102_ALLOW_SYSCALL(__NR_rseq),
		M102_ALLOW_SYSCALL(__NR_futex),
		M102_ALLOW_SYSCALL(__NR_clock_gettime),
		M102_ALLOW_SYSCALL(__NR_getpid),
		M102_ALLOW_SYSCALL(__NR_gettid),
		M102_ALLOW_SYSCALL(__NR_getrandom),
		M102_ALLOW_SYSCALL(__NR_prlimit64),
		M102_ALLOW_SYSCALL(__NR_uname),
		M102_BPF_STMT(M102_BPF_RET | M102_BPF_K,
				M102_SECCOMP_RET_KILL_PROCESS),
	};
	struct m102_sock_fprog program = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    prctl(PR_SET_SECCOMP, M102_SECCOMP_MODE_FILTER, &program) < 0)
		return M102_ERR_SANDBOX;
	return M102_OK;
}

static int write_proc_map(const char *path, unsigned int value)
{
	char mapping[64];
	int fd;
	int length;

	length = snprintf(mapping, sizeof(mapping), "0 %u 1\n", value);
	if (length < 0 || (size_t)length >= sizeof(mapping))
		return M102_ERR_SANDBOX;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return M102_ERR_SANDBOX;
	if (write_all(fd, mapping, (size_t)length) != M102_OK) {
		close(fd);
		return M102_ERR_SANDBOX;
	}
	close(fd);
	return M102_OK;
}

static int enter_private_network_namespace(void)
{
	char setgroups_path[] = "/proc/self/setgroups";
	uid_t host_uid = getuid();
	gid_t host_gid = getgid();
	int fd;
	int result;

	if (unshare(CLONE_NEWUSER) < 0)
		return M102_OK;
	fd = open(setgroups_path, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)write_all(fd, "deny\n", 5);
		close(fd);
	}
	result = write_proc_map("/proc/self/uid_map", (unsigned int)host_uid);
	if (result != M102_OK)
		return M102_OK;
	result = write_proc_map("/proc/self/gid_map", (unsigned int)host_gid);
	if (result != M102_OK)
		return M102_OK;
	if (unshare(CLONE_NEWNET) < 0)
		return M102_OK;
	return M102_OK;
}

static void sanitize_output(const unsigned char *raw, size_t length,
				char output[M102_MAX_OUTPUT])
{
	size_t input_index;
	size_t output_index = 0;

	for (input_index = 0; input_index < length &&
	     output_index + 1 < M102_MAX_OUTPUT; input_index++) {
		unsigned char value = raw[input_index];

		if (value == '\n' || value == '\r' || value == '\t' ||
		    (value >= 0x20 && value <= 0x7e))
			output[output_index++] = (char)value;
		else
			output[output_index++] = '.';
	}
	output[output_index] = '\0';
}

static int child_run_program(const char *scratch_dir, const char *program,
				     const char *const argv[], size_t argc,
				     int output_fd)
{
		char *const *exec_argv = (char *const *)argv;
		int result;

	if (dup2(output_fd, STDOUT_FILENO) < 0 ||
	    dup2(output_fd, STDERR_FILENO) < 0)
		_exit(126);
	close(output_fd);
	result = enter_private_network_namespace();
	if (result != M102_OK)
		_exit(125);
	result = install_landlock_write_scope(scratch_dir);
	if (result != M102_OK && result != M102_LANDLOCK_UNAVAILABLE)
		_exit(124);
	for (int fd = 3; fd < 128; fd++)
		(void)close(fd);
	result = install_network_deny_seccomp();
	if (result != M102_OK)
		_exit(123);
	(void)clearenv();
	(void)setenv("PATH", "/usr/bin:/bin", 1);
	(void)argc;
	execv(program, exec_argv);
	_exit(127);
}

static int run_child(const char *scratch_dir, const char *program,
		     const char *const argv[], size_t argc,
		     unsigned char raw[M102_MAX_CAPTURE], size_t *raw_length,
		     int *exit_status)
{
	int pipefd[2];
	pid_t child;
	size_t length = 0;
	int overflow = 0;
	int status;

	if (pipe2(pipefd, O_CLOEXEC) < 0)
		return M102_ERR_IO;
	child = fork();
	if (child < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return M102_ERR_IO;
	}
	if (!child) {
		close(pipefd[0]);
		child_run_program(scratch_dir, program, argv, argc, pipefd[1]);
		_exit(126);
	}
	close(pipefd[1]);
	for (;;) {
		unsigned char buffer[512];
		ssize_t received = read(pipefd[0], buffer, sizeof(buffer));

		if (received < 0) {
			if (errno == EINTR)
				continue;
			close(pipefd[0]);
			(void)kill(child, SIGKILL);
			(void)waitpid(child, NULL, 0);
			return M102_ERR_IO;
		}
		if (!received)
			break;
		if (length + (size_t)received > M102_MAX_CAPTURE) {
			size_t available = M102_MAX_CAPTURE - length;

			if (available)
				memcpy(raw + length, buffer, available);
			length = M102_MAX_CAPTURE;
			overflow = 1;
		} else {
			memcpy(raw + length, buffer, (size_t)received);
			length += (size_t)received;
		}
	}
	close(pipefd[0]);
	if (waitpid(child, &status, 0) != child)
		return M102_ERR_IO;
	*raw_length = length;
	*exit_status = status;
	if (overflow)
		return M102_ERR_VERIFICATION;
	return M102_OK;
}

static int build_post_digest(const char *scratch_dir,
			     const uint8_t output_digest[M102_DIGEST_SIZE],
			     uint8_t digest[M102_DIGEST_SIZE])
{
	uint8_t scope_digest[M102_DIGEST_SIZE];
	unsigned char combined[M102_DIGEST_SIZE * 2];
	int result;

	result = digest_scope(scratch_dir, scope_digest);
	if (result != M102_OK)
		return result;
	memcpy(combined, scope_digest, M102_DIGEST_SIZE);
	memcpy(combined + M102_DIGEST_SIZE, output_digest, M102_DIGEST_SIZE);
	return digest_bytes(combined, sizeof(combined), digest);
}

int m102_open(struct m102_service *service, const char *journal_prefix,
		      int require_kernel)
{
	int result;

	if (!service || !journal_prefix || !journal_prefix[0])
		return M102_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->effect_fd = -1;
	result = m99_open(&service->tools, journal_prefix, require_kernel);
	if (result != M99_OK)
		return result;
	if (snprintf(service->effect_path, sizeof(service->effect_path), "%s.network-effects",
		     journal_prefix) >= (int)sizeof(service->effect_path)) {
		m99_close(&service->tools);
		return M102_ERR_ARGUMENT;
	}
	service->effect_fd = open(service->effect_path,
				 O_RDWR | O_CREAT | O_APPEND, 0600);
	if (service->effect_fd < 0) {
		m99_close(&service->tools);
		return M102_ERR_IO;
	}
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->effect_fd);
		m99_close(&service->tools);
		return M102_ERR_STATE;
	}
	service->lock_initialized = 1;
	result = replay_unlocked(service);
	if (result != M102_OK) {
		m102_close(service);
		return result;
	}
	return M102_OK;
}

void m102_close(struct m102_service *service)
{
	if (!service)
		return;
	if (service->effect_fd >= 0)
		close(service->effect_fd);
	if (service->lock_initialized)
		pthread_mutex_destroy(&service->lock);
	m99_close(&service->tools);
	memset(service, 0, sizeof(*service));
	service->effect_fd = -1;
}

int m102_query(const struct m102_service *service, uint64_t effect_id,
		       struct m102_effect *out)
{
	const struct m102_effect *effect;

	if (!service || !out)
		return M102_ERR_ARGUMENT;
	effect = find_effect_const(service, effect_id);
	if (!effect)
		return M102_ERR_NOT_FOUND;
	*out = *effect;
	return M102_OK;
}

int m102_run_program(struct m102_service *service, uint64_t invocation_id,
			    uint64_t now_ns, const char *scratch_dir,
			    const char *program, const char *const argv[], size_t argc,
			    const char *idempotency_key, struct m102_effect *out)
{
	struct m99_invocation invocation;
	struct m99_tool_spec tool;
	struct m102_effect effect;
	struct m102_effect updated;
	uint8_t command_digest[M102_DIGEST_SIZE];
	uint8_t key_digest[M102_DIGEST_SIZE];
	uint8_t pre_digest[M102_DIGEST_SIZE];
	uint8_t policy_digest[M102_DIGEST_SIZE];
	uint8_t output_digest[M102_DIGEST_SIZE];
	unsigned char raw_output[M102_MAX_CAPTURE];
	char sanitized[M102_MAX_OUTPUT];
	size_t raw_length = 0;
	int child_status = 0;
	int result;
	int completion;
	struct m99_invocation completed_invocation;

	if (!service || !out || !scratch_dir || !idempotency_key ||
	    !program || !argv || !argc || !idempotency_key[0] ||
	    strnlen(idempotency_key, M102_MAX_KEY) >= M102_MAX_KEY)
		return M102_ERR_ARGUMENT;
	result = validate_scope(scratch_dir);
	if (result != M102_OK)
		return result;
	result = m102_command_digest(program, argv, argc, command_digest);
	if (result != M102_OK)
		return result;
	result = m99_invocation_query(&service->tools, invocation_id, &invocation);
	if (result != M99_OK)
		return M102_ERR_NOT_FOUND;
	result = m99_tool_query(&service->tools, invocation.tool_id, &tool);
	if (result != M99_OK || tool.state != M99_TOOL_REGISTERED ||
	    tool.revocation_generation != invocation.revocation_generation)
		return M102_ERR_REVOKED;
	if (memcmp(tool.implementation_digest, command_digest,
		   sizeof(command_digest)))
		return M102_ERR_PROVENANCE;
	if (!nonzero_digest(invocation.input_digest) ||
	    digest_bytes(idempotency_key, strlen(idempotency_key), key_digest) != M102_OK ||
	    digest_bytes("M102-LANDLOCK-SECCOMP-NETWORK-DENY-V1", 36,
			 policy_digest) != M102_OK)
		return M102_ERR_IO;
	result = digest_scope(scratch_dir, pre_digest);
	if (result != M102_OK)
		return result;
	result = lock_service(service);
	if (result != M102_OK)
		return result;
	{
		struct m102_effect *existing = find_key(service, idempotency_key);

		if (existing) {
			*out = *existing;
			if (memcmp(existing->input_digest, invocation.input_digest,
				   sizeof(existing->input_digest)) ||
			    memcmp(existing->program, program, strlen(program) + 1))
				result = M102_ERR_CONFLICT;
			else if (existing->state == M102_EFFECT_EFFECTED ||
				 existing->state == M102_EFFECT_AMBIGUOUS)
				result = M102_ERR_AMBIGUOUS;
			else if (existing->state == M102_EFFECT_COMMITTED)
				result = M102_ERR_DUPLICATE;
			else
				result = M102_ERR_SANDBOX;
			goto out_unlock;
		}
	}
	if (invocation.state != M99_INVOCATION_EXECUTING) {
		result = M102_ERR_STATE;
		goto out_unlock;
	}
	memset(&effect, 0, sizeof(effect));
	effect.effect_id = service->next_effect_id++;
	effect.invocation_id = invocation.invocation_id;
	effect.mission_id = invocation.mission_id;
	effect.tool_id = invocation.tool_id;
	effect.created_at_ns = now_ns;
	effect.agent_id = invocation.agent_id;
	effect.authority_lease_id = invocation.authority_lease_id;
	effect.registry_generation = invocation.registry_generation;
	effect.revocation_generation = invocation.revocation_generation;
	effect.state = M102_EFFECT_PENDING;
	effect.sandbox_kind = M102_SANDBOX_KIND_LANDLOCK_SECCOMP_NETWORK_DENY;
	memcpy(effect.idempotency_digest, key_digest, sizeof(key_digest));
	memcpy(effect.input_digest, invocation.input_digest,
	       sizeof(effect.input_digest));
	memcpy(effect.policy_digest, policy_digest, sizeof(policy_digest));
	memcpy(effect.pre_state_digest, pre_digest, sizeof(pre_digest));
	result = copy_text(effect.idempotency_key, sizeof(effect.idempotency_key),
			   idempotency_key, 0);
	if (result == M102_OK)
		result = copy_text(effect.scope, sizeof(effect.scope), scratch_dir, 0);
	if (result == M102_OK)
		result = copy_text(effect.program, sizeof(effect.program), program, 0);
	if (result == M102_OK)
		result = append_effect(service, &effect);
	if (result != M102_OK)
		goto out_unlock;
	service->effects[service->effect_count++] = effect;
	digest_bytes("", 0, output_digest);
	result = run_child(scratch_dir, program, argv, argc, raw_output,
			   &raw_length, &child_status);
	if (result == M102_OK &&
	    (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0))
		result = M102_ERR_SANDBOX;
	if (result == M102_OK &&
	    digest_bytes(raw_output, raw_length, output_digest) != M102_OK)
		result = M102_ERR_IO;
	sanitize_output(raw_output, raw_length, sanitized);
	updated = effect;
	updated.completed_at_ns = now_ns + 1;
	updated.result_code = result == M102_OK ? 0U : (uint32_t)(-result);
	copy_text(updated.output, sizeof(updated.output), sanitized, 1);
	if (result == M102_OK) {
		memcpy(updated.output_digest, output_digest, sizeof(output_digest));
		if (build_post_digest(scratch_dir, output_digest,
				      updated.post_state_digest) != M102_OK)
			result = M102_ERR_VERIFICATION;
	}
	if (result != M102_OK) {
		updated.state = M102_EFFECT_FAILED;
		updated.verification_ok = 0;
		if (result == M102_ERR_NETWORK || result == M102_ERR_SANDBOX)
			updated.result_code = (uint32_t)(-result);
		if (append_effect(service, &updated) != M102_OK) {
			updated.state = M102_EFFECT_AMBIGUOUS;
			(void)append_effect(service, &updated);
			service->effects[service->effect_count - 1] = updated;
			*out = updated;
			result = M102_ERR_AMBIGUOUS;
			goto out_unlock;
		}
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		completion = m99_complete(&service->tools, invocation_id, now_ns + 2,
					  updated.result_code, 0, output_digest,
					  sanitized, &completed_invocation);
		if (completion != M99_OK && completion != M99_ERR_VERIFICATION)
			result = M102_ERR_AMBIGUOUS;
		goto out_unlock;
	}
	updated.state = M102_EFFECT_EFFECTED;
	updated.verification_ok = 1;
	memcpy(updated.output_digest, output_digest, sizeof(output_digest));
	if (append_effect(service, &updated) != M102_OK) {
		updated.state = M102_EFFECT_AMBIGUOUS;
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M102_ERR_AMBIGUOUS;
		goto out_unlock;
	}
	service->effects[service->effect_count - 1] = updated;
	completion = m99_complete(&service->tools, invocation_id, now_ns + 2,
				  0, 1, output_digest, sanitized, &completed_invocation);
	if (completion != M99_OK) {
		updated.state = M102_EFFECT_AMBIGUOUS;
		updated.verification_ok = 0;
		(void)append_effect(service, &updated);
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M102_ERR_AMBIGUOUS;
		goto out_unlock;
	}
	updated.state = M102_EFFECT_COMMITTED;
	if (append_effect(service, &updated) != M102_OK) {
		updated.state = M102_EFFECT_AMBIGUOUS;
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M102_ERR_AMBIGUOUS;
		goto out_unlock;
	}
	service->effects[service->effect_count - 1] = updated;
	*out = updated;
	result = M102_OK;
out_unlock:
	unlock_service(service);
	return result;
}

int m102_test_corrupt_tail(const struct m102_service *service)
{
	static const unsigned char corrupt[] = { 0xde, 0xad, 0xbe, 0xef };
	int fd;

	if (!service || !service->effect_path[0])
		return M102_ERR_ARGUMENT;
	fd = open(service->effect_path, O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0)
		return M102_ERR_IO;
	if (write_all(fd, corrupt, sizeof(corrupt)) != M102_OK) {
		close(fd);
		return M102_ERR_IO;
	}
	if (fdatasync(fd) < 0) {
		close(fd);
		return M102_ERR_IO;
	}
	close(fd);
	return M102_OK;
}
