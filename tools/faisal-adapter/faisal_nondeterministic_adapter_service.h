#ifndef FAISAL_NONDETERMINISTIC_ADAPTER_SERVICE_H
#define FAISAL_NONDETERMINISTIC_ADAPTER_SERVICE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../faisal-tool/faisal_tool_service.h"

#define M102_MAX_EFFECTS 32U
#define M102_MAX_KEY 96U
#define M102_MAX_SCOPE 160U
#define M102_MAX_PROGRAM 192U
#define M102_MAX_ARGS 8U
#define M102_MAX_OUTPUT 256U
#define M102_MAX_CAPTURE 4096U
#define M102_EFFECT_JOURNAL_MAGIC 0x464d4132U
#define M102_EFFECT_JOURNAL_VERSION 1U
#define M102_DIGEST_SIZE FTS_DIGEST_SIZE

#define M102_SANDBOX_KIND_LANDLOCK_SECCOMP_NETWORK_DENY 4U

enum m102_effect_state {
	M102_EFFECT_PENDING = 1,
	M102_EFFECT_EFFECTED = 2,
	M102_EFFECT_COMMITTED = 3,
	M102_EFFECT_FAILED = 4,
	M102_EFFECT_AMBIGUOUS = 5
};

enum m102_status {
	M102_OK = 0,
	M102_ERR_ARGUMENT = -1,
	M102_ERR_IO = -2,
	M102_ERR_CORRUPT = -3,
	M102_ERR_FULL = -4,
	M102_ERR_NOT_FOUND = -5,
	M102_ERR_STATE = -6,
	M102_ERR_SANDBOX = -7,
	M102_ERR_SCOPE = -8,
	M102_ERR_CONFLICT = -9,
	M102_ERR_DUPLICATE = -10,
	M102_ERR_AMBIGUOUS = -11,
	M102_ERR_VERIFICATION = -12,
	M102_ERR_REVOKED = -13,
	M102_ERR_PROVENANCE = -14,
	M102_ERR_NETWORK = -15
};

struct m102_effect {
	uint64_t effect_id;
	uint64_t invocation_id;
	uint64_t mission_id;
	uint64_t tool_id;
	uint64_t created_at_ns;
	uint64_t completed_at_ns;
	uint64_t agent_id;
	uint64_t authority_lease_id;
	uint64_t registry_generation;
	uint64_t revocation_generation;
	uint32_t state;
	uint32_t result_code;
	uint32_t verification_ok;
	uint32_t sandbox_kind;
	uint8_t idempotency_digest[M102_DIGEST_SIZE];
	uint8_t input_digest[M102_DIGEST_SIZE];
	uint8_t policy_digest[M102_DIGEST_SIZE];
	uint8_t pre_state_digest[M102_DIGEST_SIZE];
	uint8_t post_state_digest[M102_DIGEST_SIZE];
	uint8_t output_digest[M102_DIGEST_SIZE];
	char idempotency_key[M102_MAX_KEY];
	char scope[M102_MAX_SCOPE];
	char program[M102_MAX_PROGRAM];
	char output[M102_MAX_OUTPUT];
};

struct m102_service {
	struct m99_service tools;
	int effect_fd;
	int lock_initialized;
	uint64_t next_effect_id;
	uint64_t effect_sequence;
	char effect_path[FTS_MAX_JOURNAL_PATH];
	struct m102_effect effects[M102_MAX_EFFECTS];
	size_t effect_count;
	pthread_mutex_t lock;
};

int m102_open(struct m102_service *service, const char *journal_prefix,
		      int require_kernel);
void m102_close(struct m102_service *service);
int m102_replay(struct m102_service *service);
int m102_command_digest(const char *program, const char *const argv[],
			 size_t argc, uint8_t digest[M102_DIGEST_SIZE]);
int m102_run_program(struct m102_service *service, uint64_t invocation_id,
			    uint64_t now_ns, const char *scratch_dir,
			    const char *program, const char *const argv[], size_t argc,
			    const char *idempotency_key, struct m102_effect *out);
int m102_query(const struct m102_service *service, uint64_t effect_id,
		       struct m102_effect *out);
int m102_test_corrupt_tail(const struct m102_service *service);

#endif
