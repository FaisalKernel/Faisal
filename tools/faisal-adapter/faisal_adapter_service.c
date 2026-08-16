#define _GNU_SOURCE

#include "faisal_adapter_service.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define M100_SANDBOX_KIND_LANDLOCK_SECCOMP 3U
#define M100_LANDLOCK_RULE_PATH_BENEATH 1U
#define M100_LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define M100_LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define M100_LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define M100_LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define M100_LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define M100_LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define M100_LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define M100_LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define M100_LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define M100_LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define M100_LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define M100_LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define M100_LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define M100_LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define M100_LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define M100_SECCOMP_MODE_FILTER 2
#define M100_SECCOMP_RET_KILL_PROCESS 0x80000000U
#define M100_SECCOMP_RET_ALLOW 0x7fff0000U
#define M100_AUDIT_ARCH_X86_64 0xc000003eU

struct m100_landlock_ruleset_attr {
    uint64_t handled_access_fs;
};

struct m100_landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
};

struct m100_seccomp_data {
    int32_t nr;
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t args[6];
};
#define M100_RECORD_EFFECT 1U
#define M100_BPF_LD 0x00U
#define M100_BPF_W 0x00U
#define M100_BPF_ABS 0x20U
#define M100_BPF_JMP 0x05U
#define M100_BPF_JEQ 0x10U
#define M100_BPF_K 0x00U
#define M100_BPF_RET 0x06U

struct m100_sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

struct m100_sock_fprog {
    unsigned short len;
    struct m100_sock_filter *filter;
};

#define M100_BPF_STMT(opcode, value) ((struct m100_sock_filter){ \
    .code = (uint16_t)(opcode), .jt = 0, .jf = 0, .k = (uint32_t)(value) })
#define M100_BPF_JUMP(opcode, value, true_jump, false_jump) ((struct m100_sock_filter){ \
    .code = (uint16_t)(opcode), .jt = (uint8_t)(true_jump), \
    .jf = (uint8_t)(false_jump), .k = (uint32_t)(value) })

struct m100_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t record_size;
	uint64_t sequence;
	uint8_t digest[M100_DIGEST_SIZE];
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return M100_ERR_IO;
		}
		if (!written)
			return M100_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return M100_OK;
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
			return M100_ERR_IO;
		}
		if (!received)
			return total ? M100_ERR_CORRUPT : 1;
		total += (size_t)received;
	}
	return M100_OK;
}

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[M100_DIGEST_SIZE])
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = M100_ERR_IO;

	if (!context || (!data && length) || !digest)
		goto out;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, data, length) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M100_DIGEST_SIZE)
		result = M100_OK;
out:
	EVP_MD_CTX_free(context);
	return result;
}

static int nonzero_digest(const uint8_t digest[M100_DIGEST_SIZE])
{
	unsigned int index;

	if (!digest)
		return 0;
	for (index = 0; index < M100_DIGEST_SIZE; index++)
		if (digest[index])
			return 1;
	return 0;
}

static int copy_text(char *destination, size_t destination_size,
			     const char *source, int allow_empty)
{
	size_t length;

	if (!destination || !destination_size || !source)
		return M100_ERR_ARGUMENT;
	length = strnlen(source, destination_size);
	if ((!allow_empty && !length) || length >= destination_size)
		return M100_ERR_ARGUMENT;
	memcpy(destination, source, length + 1);
	return M100_OK;
}

static int lock_service(struct m100_service *service)
{
	if (!service || !service->lock_initialized)
		return M100_ERR_ARGUMENT;
	return pthread_mutex_lock(&service->lock) == 0 ? M100_OK : M100_ERR_STATE;
}

static void unlock_service(struct m100_service *service)
{
	(void)pthread_mutex_unlock(&service->lock);
}

static struct m100_effect *find_effect(struct m100_service *service,
					       uint64_t effect_id)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (service->effects[index].effect_id == effect_id)
			return &service->effects[index];
	return NULL;
}

static const struct m100_effect *find_effect_const(
		const struct m100_service *service, uint64_t effect_id)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (service->effects[index].effect_id == effect_id)
			return &service->effects[index];
	return NULL;
}

static struct m100_effect *find_key(struct m100_service *service,
					    const char *key)
{
	size_t index;

	for (index = 0; index < service->effect_count; index++)
		if (!strcmp(service->effects[index].idempotency_key, key))
			return &service->effects[index];
	return NULL;
}

static int digest_effect(const struct m100_effect *effect,
				 uint8_t digest[M100_DIGEST_SIZE])
{
	struct m100_effect canonical;

	if (!effect)
		return M100_ERR_ARGUMENT;
	canonical = *effect;
	memset(canonical.post_state_digest, 0, sizeof(canonical.post_state_digest));
	return digest_bytes(&canonical, sizeof(canonical), digest);
}

static int append_effect(struct m100_service *service,
				 const struct m100_effect *effect)
{
	struct m100_disk_header header;
	uint8_t digest[M100_DIGEST_SIZE];
	int result;

	if (!service || service->effect_fd < 0 || !effect)
		return M100_ERR_ARGUMENT;
	result = digest_effect(effect, digest);
	if (result != M100_OK)
		return result;
	memset(&header, 0, sizeof(header));
	header.magic = M100_EFFECT_JOURNAL_MAGIC;
	header.version = M100_EFFECT_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.record_size = sizeof(header) + sizeof(*effect);
	header.sequence = service->effect_sequence + 1;
	memcpy(header.digest, digest, sizeof(header.digest));
	result = write_all(service->effect_fd, &header, sizeof(header));
	if (result == M100_OK)
		result = write_all(service->effect_fd, effect, sizeof(*effect));
	if (result == M100_OK && fdatasync(service->effect_fd) < 0)
		result = M100_ERR_IO;
	if (result == M100_OK)
		service->effect_sequence = header.sequence;
	return result;
}

static int apply_effect(struct m100_service *service,
				const struct m100_effect *effect)
{
	struct m100_effect *existing = find_effect(service, effect->effect_id);

	if (existing) {
		*existing = *effect;
		return M100_OK;
	}
	if (service->effect_count >= M100_MAX_EFFECTS)
		return M100_ERR_FULL;
	service->effects[service->effect_count++] = *effect;
	return M100_OK;
}

static int validate_effect(const struct m100_effect *effect)
{
	if (!effect || !effect->effect_id || !effect->invocation_id ||
	    !effect->mission_id || !effect->tool_id || !effect->agent_id ||
	    !effect->authority_lease_id || effect->state < M100_EFFECT_PENDING ||
	    effect->state > M100_EFFECT_FAILED ||
	    !nonzero_digest(effect->idempotency_digest) ||
	    !nonzero_digest(effect->input_digest) ||
	    !nonzero_digest(effect->policy_digest) ||
	    !nonzero_digest(effect->pre_state_digest) ||
	    !effect->idempotency_key[0] || !effect->scope[0] ||
	    effect->sandbox_kind != M100_SANDBOX_KIND_LANDLOCK_SECCOMP)
		return M100_ERR_CORRUPT;
	return M100_OK;
}

static int replay_unlocked(struct m100_service *service)
{
	struct m100_disk_header header;
	uint64_t last_sequence = 0;
	int result;

	if (lseek(service->effect_fd, 0, SEEK_SET) < 0)
		return M100_ERR_IO;
	service->effect_count = 0;
	service->effect_sequence = 0;
	service->next_effect_id = 1;
	for (;;) {
		struct m100_effect effect;
		uint8_t digest[M100_DIGEST_SIZE];

		result = read_exact_or_eof(service->effect_fd, &header, sizeof(header));
		if (result == 1)
			break;
		if (result != M100_OK || header.magic != M100_EFFECT_JOURNAL_MAGIC ||
		    header.version != M100_EFFECT_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    header.record_size != sizeof(header) + sizeof(effect) ||
		    header.sequence <= last_sequence)
			return M100_ERR_CORRUPT;
		result = read_exact_or_eof(service->effect_fd, &effect, sizeof(effect));
		if (result != M100_OK || validate_effect(&effect) != M100_OK ||
		    digest_effect(&effect, digest) != M100_OK ||
		    memcmp(digest, header.digest, sizeof(digest)) != 0 ||
		    apply_effect(service, &effect) != M100_OK)
			return M100_ERR_CORRUPT;
		if (effect.effect_id >= service->next_effect_id)
			service->next_effect_id = effect.effect_id + 1;
		last_sequence = header.sequence;
	}
	service->effect_sequence = last_sequence;
	return lseek(service->effect_fd, 0, SEEK_END) < 0 ? M100_ERR_IO : M100_OK;
}

int m100_replay(struct m100_service *service)
{
	int result;

	if (!service)
		return M100_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M100_OK)
		return result;
	result = replay_unlocked(service);
	unlock_service(service);
	return result;
}

int m100_open(struct m100_service *service, const char *journal_prefix,
		      int require_kernel)
{
	int result;

	if (!service || !journal_prefix || !*journal_prefix)
		return M100_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->effect_fd = -1;
	result = m99_open(&service->tools, journal_prefix, require_kernel);
	if (result != M99_OK)
		return result;
	if (snprintf(service->effect_path, sizeof(service->effect_path), "%s.effects",
		     journal_prefix) >= (int)sizeof(service->effect_path)) {
		m99_close(&service->tools);
		return M100_ERR_ARGUMENT;
	}
	service->effect_fd = open(service->effect_path, O_RDWR | O_CREAT | O_APPEND,
			0600);
	if (service->effect_fd < 0) {
		m99_close(&service->tools);
		return M100_ERR_IO;
	}
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->effect_fd);
		service->effect_fd = -1;
		m99_close(&service->tools);
		return M100_ERR_STATE;
	}
	service->lock_initialized = 1;
	service->next_effect_id = 1;
	result = replay_unlocked(service);
	if (result != M100_OK) {
		pthread_mutex_destroy(&service->lock);
		service->lock_initialized = 0;
		close(service->effect_fd);
		service->effect_fd = -1;
		m99_close(&service->tools);
		return result;
	}
	return M100_OK;
}

void m100_close(struct m100_service *service)
{
	if (!service)
		return;
	if (service->lock_initialized) {
		(void)pthread_mutex_lock(&service->lock);
		if (service->effect_fd >= 0) {
			(void)fdatasync(service->effect_fd);
			close(service->effect_fd);
			service->effect_fd = -1;
		}
		(void)pthread_mutex_unlock(&service->lock);
		pthread_mutex_destroy(&service->lock);
		service->lock_initialized = 0;
	} else if (service->effect_fd >= 0) {
		close(service->effect_fd);
		service->effect_fd = -1;
	}
	m99_close(&service->tools);
}

static int install_landlock(const char *scratch_dir)
{
	struct m100_landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = M100_LANDLOCK_ACCESS_FS_EXECUTE |
			M100_LANDLOCK_ACCESS_FS_WRITE_FILE |
			M100_LANDLOCK_ACCESS_FS_READ_FILE |
			M100_LANDLOCK_ACCESS_FS_READ_DIR |
			M100_LANDLOCK_ACCESS_FS_REMOVE_DIR |
			M100_LANDLOCK_ACCESS_FS_REMOVE_FILE |
			M100_LANDLOCK_ACCESS_FS_MAKE_CHAR |
			M100_LANDLOCK_ACCESS_FS_MAKE_DIR |
			M100_LANDLOCK_ACCESS_FS_MAKE_REG |
			M100_LANDLOCK_ACCESS_FS_MAKE_SOCK |
			M100_LANDLOCK_ACCESS_FS_MAKE_FIFO |
			M100_LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			M100_LANDLOCK_ACCESS_FS_MAKE_SYM |
			M100_LANDLOCK_ACCESS_FS_REFER |
			M100_LANDLOCK_ACCESS_FS_TRUNCATE,
	};
	struct m100_landlock_path_beneath_attr path_attr;
	int ruleset_fd;
	int dir_fd;

	ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset_attr,
				     sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		if (errno == ENOSYS)
			return M100_OK;
		return M100_ERR_SANDBOX;
	}
	dir_fd = open(scratch_dir, O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (dir_fd < 0) {
		close(ruleset_fd);
		return M100_ERR_SCOPE;
	}
	memset(&path_attr, 0, sizeof(path_attr));
	path_attr.allowed_access = ruleset_attr.handled_access_fs;
	path_attr.parent_fd = dir_fd;
	if (syscall(SYS_landlock_add_rule, ruleset_fd,
			M100_LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0) < 0 ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
		close(dir_fd);
		close(ruleset_fd);
		return M100_ERR_SANDBOX;
	}
	close(dir_fd);
	close(ruleset_fd);
	return M100_OK;
}

#define M100_ALLOW_SYSCALL(number) \
    M100_BPF_JUMP(M100_BPF_JMP | M100_BPF_JEQ | M100_BPF_K, number, 0, 1), \
    M100_BPF_STMT(M100_BPF_RET | M100_BPF_K, M100_SECCOMP_RET_ALLOW)

static int install_seccomp(void)
{
	struct m100_sock_filter filter[] = {
		M100_BPF_STMT(M100_BPF_LD | M100_BPF_W | M100_BPF_ABS,
			 offsetof(struct m100_seccomp_data, arch)),
		M100_BPF_JUMP(M100_BPF_JMP | M100_BPF_JEQ | M100_BPF_K, M100_AUDIT_ARCH_X86_64, 1, 0),
		M100_BPF_STMT(M100_BPF_RET | M100_BPF_K, M100_SECCOMP_RET_KILL_PROCESS),
		M100_BPF_STMT(M100_BPF_LD | M100_BPF_W | M100_BPF_ABS,
			 offsetof(struct m100_seccomp_data, nr)),
		M100_ALLOW_SYSCALL(__NR_read),
		M100_ALLOW_SYSCALL(__NR_write),
		M100_ALLOW_SYSCALL(__NR_close),
		M100_ALLOW_SYSCALL(__NR_openat),
		M100_ALLOW_SYSCALL(__NR_newfstatat),
		M100_ALLOW_SYSCALL(__NR_fstat),
		M100_ALLOW_SYSCALL(__NR_lseek),
		M100_ALLOW_SYSCALL(__NR_fsync),
		M100_ALLOW_SYSCALL(__NR_fdatasync),
		M100_ALLOW_SYSCALL(__NR_exit),
		M100_ALLOW_SYSCALL(__NR_exit_group),
		M100_ALLOW_SYSCALL(__NR_rt_sigaction),
		M100_ALLOW_SYSCALL(__NR_rt_sigprocmask),
		M100_ALLOW_SYSCALL(__NR_rt_sigreturn),
		M100_ALLOW_SYSCALL(__NR_brk),
		M100_ALLOW_SYSCALL(__NR_mmap),
		M100_ALLOW_SYSCALL(__NR_munmap),
		M100_ALLOW_SYSCALL(__NR_mprotect),
		M100_ALLOW_SYSCALL(__NR_arch_prctl),
		M100_ALLOW_SYSCALL(__NR_set_tid_address),
		M100_ALLOW_SYSCALL(__NR_set_robust_list),
		M100_ALLOW_SYSCALL(__NR_rseq),
		M100_BPF_STMT(M100_BPF_RET | M100_BPF_K, M100_SECCOMP_RET_KILL_PROCESS),
	};
	struct m100_sock_fprog program = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
	    prctl(PR_SET_SECCOMP, M100_SECCOMP_MODE_FILTER, &program) < 0)
		return M100_ERR_SANDBOX;
	return M100_OK;
}

static int validate_scope(const char *scratch_dir, char *path, size_t path_size)
{
	struct stat stat_buffer;

	if (!scratch_dir || !path || !scratch_dir[0] || scratch_dir[0] != '/' ||
	    strstr(scratch_dir, "..") ||
	    strnlen(scratch_dir, M100_MAX_SCOPE) >= M100_MAX_SCOPE ||
	    stat(scratch_dir, &stat_buffer) < 0 || !S_ISDIR(stat_buffer.st_mode))
		return M100_ERR_SCOPE;
	if (snprintf(path, path_size, "%s/%s", scratch_dir,
		     M100_EFFECT_FILE) >= (int)path_size)
		return M100_ERR_SCOPE;
	return M100_OK;
}

static int read_effect_file(const char *path, uint8_t digest[M100_DIGEST_SIZE],
				char output[M100_MAX_OUTPUT])
{
	unsigned char buffer[M100_MAX_OUTPUT];
	struct stat stat_buffer;
	int fd;
	ssize_t length;
	int result;

	if (stat(path, &stat_buffer) < 0) {
		if (errno == ENOENT) {
			static const char absent[] = "ABSENT";
			return digest_bytes(absent, sizeof(absent) - 1, digest);
		}
		return M100_ERR_IO;
	}
	if (stat_buffer.st_size < 0 || stat_buffer.st_size >= (off_t)sizeof(buffer))
		return M100_ERR_VERIFICATION;
	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return M100_ERR_IO;
	length = read(fd, buffer, sizeof(buffer));
	if (length < 0 || (off_t)length != stat_buffer.st_size) {
		close(fd);
		return M100_ERR_VERIFICATION;
	}
	close(fd);
	result = digest_bytes(buffer, (size_t)length, digest);
	if (result == M100_OK && output) {
		memcpy(output, buffer, (size_t)length);
		output[length] = '\0';
	}
	return result;
}

static int child_write_effect(const char *path, const char *scratch_dir,
				      const char *payload)
{
	int fd;
	int result;

	result = install_landlock(scratch_dir);
	if (result != M100_OK)
		return result;
	result = install_seccomp();
	if (result != M100_OK)
		return result;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return M100_ERR_SCOPE;
	result = write_all(fd, payload, strlen(payload));
	if (result == M100_OK && fdatasync(fd) < 0)
		result = M100_ERR_IO;
	if (close(fd) < 0 && result == M100_OK)
		result = M100_ERR_IO;
	return result;
}

int m100_run_effect(struct m100_service *service, uint64_t invocation_id,
			    uint64_t now_ns, const char *scratch_dir,
			    const char *idempotency_key, const char *payload,
			    struct m100_effect *out)
{
	struct m99_invocation invocation;
	struct m99_tool_spec tool;
	struct m100_effect effect;
	struct m100_effect updated;
	char path[FTS_MAX_JOURNAL_PATH];
	char readback[M100_MAX_OUTPUT];
	uint8_t key_digest[M100_DIGEST_SIZE];
	uint8_t pre_digest[M100_DIGEST_SIZE];
	uint8_t post_digest[M100_DIGEST_SIZE];
	uint8_t output_digest[M100_DIGEST_SIZE];
	uint8_t policy_digest[M100_DIGEST_SIZE];
	pid_t child;
	int status;
	int result;
	int completion;

	if (!service || !now_ns || !scratch_dir || !idempotency_key || !payload || !out ||
	    !idempotency_key[0] || !payload[0] ||
	    strnlen(idempotency_key, M100_MAX_KEY) >= M100_MAX_KEY ||
	    strnlen(payload, M100_MAX_OUTPUT) >= M100_MAX_OUTPUT)
		return M100_ERR_ARGUMENT;
	result = validate_scope(scratch_dir, path, sizeof(path));
	if (result != M100_OK)
		return result;
	result = m99_invocation_query(&service->tools, invocation_id, &invocation);
	if (result != M99_OK)
		return M100_ERR_NOT_FOUND;
	result = m99_tool_query(&service->tools, invocation.tool_id, &tool);
	if (result != M99_OK || tool.state != M99_TOOL_REGISTERED ||
	    tool.revocation_generation != invocation.revocation_generation)
		return M100_ERR_REVOKED;
	if (digest_bytes(idempotency_key, strlen(idempotency_key), key_digest) != M100_OK ||
	    digest_bytes("M100-LANDLOCK-SECCOMP-NNP-V1", 28, policy_digest) != M100_OK ||
	    !nonzero_digest(invocation.input_digest))
		return M100_ERR_IO;
	result = lock_service(service);
	if (result != M100_OK)
		return result;
	{
		struct m100_effect *existing = find_key(service, idempotency_key);

		if (existing) {
			*out = *existing;
			if (memcmp(existing->input_digest, invocation.input_digest,
				   sizeof(existing->input_digest)) != 0)
				result = M100_ERR_CONFLICT;
			else if (existing->state == M100_EFFECT_EFFECTED ||
				 existing->state == M100_EFFECT_PENDING)
				result = M100_ERR_AMBIGUOUS;
			else if (existing->state == M100_EFFECT_COMMITTED)
				result = M100_ERR_DUPLICATE;
			else
				result = M100_ERR_SANDBOX;
			goto out_unlock;
		}
	}
	if (invocation.state != M99_INVOCATION_EXECUTING) {
		result = M100_ERR_STATE;
		goto out_unlock;
	}
	result = read_effect_file(path, pre_digest, NULL);

	if (result != M100_OK)
		goto out_unlock;
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
	effect.state = M100_EFFECT_PENDING;
	effect.sandbox_kind = M100_SANDBOX_KIND_LANDLOCK_SECCOMP;
	memcpy(effect.idempotency_digest, key_digest, sizeof(effect.idempotency_digest));
	memcpy(effect.input_digest, invocation.input_digest, sizeof(effect.input_digest));
	memcpy(effect.policy_digest, policy_digest, sizeof(effect.policy_digest));
	memcpy(effect.pre_state_digest, pre_digest, sizeof(effect.pre_state_digest));
	result = copy_text(effect.idempotency_key, sizeof(effect.idempotency_key),
			   idempotency_key, 0);
	if (result == M100_OK)
		result = copy_text(effect.scope, sizeof(effect.scope), scratch_dir, 0);
	if (result == M100_OK)
		result = append_effect(service, &effect);
	if (result != M100_OK)
		goto out_unlock;
	service->effects[service->effect_count++] = effect;
	child = fork();
	if (child < 0) {
		updated = effect;
		updated.state = M100_EFFECT_FAILED;
		(void)append_effect(service, &updated);
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M100_ERR_SANDBOX;
		goto out_unlock;
	}
	if (child == 0) {
		int child_result = child_write_effect(path, scratch_dir, payload);
		_exit(child_result == M100_OK ? 0 : 111);
	}
	if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		updated = effect;
		updated.state = M100_EFFECT_FAILED;
		updated.result_code = M100_ERR_SANDBOX;
		(void)append_effect(service, &updated);
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M100_ERR_SANDBOX;
		goto out_unlock;
	}
	result = read_effect_file(path, post_digest, readback);
	if (result != M100_OK || strcmp(readback, payload) != 0 ||
	    digest_bytes(readback, strlen(readback), output_digest) != M100_OK) {
		updated = effect;
		updated.state = M100_EFFECT_FAILED;
		updated.result_code = M100_ERR_VERIFICATION;
		(void)append_effect(service, &updated);
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
		result = M100_ERR_VERIFICATION;
		goto out_unlock;
	}
	updated = effect;
	updated.state = M100_EFFECT_EFFECTED;
	updated.completed_at_ns = now_ns;
	updated.verification_ok = 1;
	memcpy(updated.post_state_digest, post_digest, sizeof(updated.post_state_digest));
	memcpy(updated.output_digest, output_digest, sizeof(updated.output_digest));
	(void)copy_text(updated.output, sizeof(updated.output), readback, 1);
	result = append_effect(service, &updated);
	if (result != M100_OK)
		goto out_unlock;
	service->effects[service->effect_count - 1] = updated;
	*out = updated;
	if (service->fail_after_effect) {
		service->fail_after_effect = 0;
		result = M100_ERR_AMBIGUOUS;
		goto out_unlock;
	}
	completion = m99_complete(&service->tools, invocation_id, now_ns + 1, 0, 1,
				 output_digest, readback, &invocation);
	if (completion != M99_OK) {
			result = M100_ERR_AMBIGUOUS;
			goto out_unlock;
	}
	updated.state = M100_EFFECT_COMMITTED;
	result = append_effect(service, &updated);
	if (result == M100_OK) {
		service->effects[service->effect_count - 1] = updated;
		*out = updated;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m100_query(const struct m100_service *service, uint64_t effect_id,
		      struct m100_effect *out)
{
	const struct m100_effect *effect;
	struct m100_service *mutable_service = (struct m100_service *)service;
	int result;

	if (!service || !out)
		return M100_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M100_OK)
		return result;
	effect = find_effect_const(service, effect_id);
	if (!effect)
		result = M100_ERR_NOT_FOUND;
	else
		*out = *effect;
	unlock_service(mutable_service);
	return result;
}

int m100_test_inject_fail_after_effect(struct m100_service *service)
{
	int result;

	result = lock_service(service);
	if (result != M100_OK)
		return result;
	service->fail_after_effect = 1;
	unlock_service(service);
	return M100_OK;
}

int m100_test_corrupt_tail(const struct m100_service *service)
{
	struct m100_service *mutable_service = (struct m100_service *)service;
	unsigned char corrupt = 0x5a;
	int result;

	if (!service)
		return M100_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M100_OK)
		return result;
	if (write(mutable_service->effect_fd, &corrupt, sizeof(corrupt)) !=
	    (ssize_t)sizeof(corrupt) || fdatasync(mutable_service->effect_fd) < 0)
		result = M100_ERR_IO;
	else
		result = M100_OK;
	unlock_service(mutable_service);
	return result;
}
