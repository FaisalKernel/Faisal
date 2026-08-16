#ifndef FAISAL_ADAPTER_SERVICE_H
#define FAISAL_ADAPTER_SERVICE_H

#include <pthread.h>
#include <stdint.h>
#include "../faisal-tool/faisal_tool_service.h"

#define M100_MAX_EFFECTS 32U
#define M100_MAX_KEY 96U
#define M100_MAX_SCOPE 160U
#define M100_MAX_OUTPUT 160U
#define M100_EFFECT_JOURNAL_MAGIC 0x464d4130U
#define M100_EFFECT_JOURNAL_VERSION 1U
#define M100_DIGEST_SIZE FTS_DIGEST_SIZE
#define M100_EFFECT_FILE "effect.bin"

enum m100_effect_state {
	M100_EFFECT_PENDING = 1,
	M100_EFFECT_EFFECTED = 2,
	M100_EFFECT_COMMITTED = 3,
	M100_EFFECT_FAILED = 4
};

enum m100_status {
	M100_OK = 0,
	M100_ERR_ARGUMENT = -1,
	M100_ERR_IO = -2,
	M100_ERR_CORRUPT = -3,
	M100_ERR_FULL = -4,
	M100_ERR_NOT_FOUND = -5,
	M100_ERR_STATE = -6,
	M100_ERR_SANDBOX = -7,
	M100_ERR_SCOPE = -8,
	M100_ERR_CONFLICT = -9,
	M100_ERR_DUPLICATE = -10,
	M100_ERR_AMBIGUOUS = -11,
	M100_ERR_VERIFICATION = -12,
	M100_ERR_REVOKED = -13,
	M100_ERR_PROVENANCE = -14
};

struct m100_effect {
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
	uint8_t idempotency_digest[M100_DIGEST_SIZE];
	uint8_t input_digest[M100_DIGEST_SIZE];
	uint8_t policy_digest[M100_DIGEST_SIZE];
	uint8_t pre_state_digest[M100_DIGEST_SIZE];
	uint8_t post_state_digest[M100_DIGEST_SIZE];
	uint8_t output_digest[M100_DIGEST_SIZE];
	char idempotency_key[M100_MAX_KEY];
	char scope[M100_MAX_SCOPE];
	char output[M100_MAX_OUTPUT];
};

struct m100_service {
	struct m99_service tools;
	int effect_fd;
	int lock_initialized;
	uint64_t next_effect_id;
	uint64_t effect_sequence;
	uint32_t fail_after_effect;
	char effect_path[FTS_MAX_JOURNAL_PATH];
	struct m100_effect effects[M100_MAX_EFFECTS];
	size_t effect_count;
	pthread_mutex_t lock;
};

int m100_open(struct m100_service *service, const char *journal_prefix,
		      int require_kernel);
void m100_close(struct m100_service *service);
int m100_replay(struct m100_service *service);
int m100_run_effect(struct m100_service *service, uint64_t invocation_id,
			    uint64_t now_ns, const char *scratch_dir,
			    const char *idempotency_key, const char *payload,
			    struct m100_effect *out);
int m100_query(const struct m100_service *service, uint64_t effect_id,
		      struct m100_effect *out);
int m100_test_inject_fail_after_effect(struct m100_service *service);
int m100_test_corrupt_tail(const struct m100_service *service);

#endif
