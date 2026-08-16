#ifndef FAISAL_MEMORY_TRANSACTION_H
#define FAISAL_MEMORY_TRANSACTION_H

#include "faisal_memory_service.h"

#define M83_MAX_OPS 2U
#define M83_PATH_MAX 256U
#define M83_CONTENT_MAX FMS_MAX_CONTENT
#define M83_TXN_MAGIC 0x4d383331U
#define M83_TXN_VERSION 1U
#define M83_STATE_EMPTY 0U
#define M83_STATE_PREPARED 1U
#define M83_STATE_COMMITTED 2U
#define M83_STATE_ABORTED 3U

enum m83_status {
	M83_OK = 0,
	M83_ERR_ARGUMENT = -1,
	M83_ERR_IO = -2,
	M83_ERR_CORRUPT = -3,
	M83_ERR_INJECTED_CRASH = -4,
	M83_ERR_INCOMPLETE = -5
};

struct m83_operation {
	char journal_path[M83_PATH_MAX];
	char content[M83_CONTENT_MAX];
	uint32_t tier;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint64_t provenance_sequence;
};

struct m83_transaction {
	uint64_t transaction_id;
	uint32_t operation_count;
	char coordinator_path[M83_PATH_MAX];
	struct m83_operation operations[M83_MAX_OPS];
};

int m83_begin(struct m83_transaction *transaction, const char *coordinator_path,
	      uint64_t transaction_id);
int m83_add_operation(struct m83_transaction *transaction, unsigned int index,
		      const char *journal_path, const char *content,
		      uint32_t tier, uint32_t confidence_ppm,
		      uint32_t importance_ppm, uint64_t provenance_sequence);
int m83_commit(struct m83_transaction *transaction, unsigned int fail_after);
int m83_recover(const char *coordinator_path);
int m83_read_manifest(const char *coordinator_path, uint32_t *state,
		      uint64_t *transaction_id);

#endif
