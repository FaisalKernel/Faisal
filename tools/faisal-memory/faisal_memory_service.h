#ifndef FAISAL_MEMORY_SERVICE_H
#define FAISAL_MEMORY_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <linux/agi_lifecycle.h>

#define FMS_MAX_RECORDS 64
#define FMS_MAX_CONTENT 4096
#define FMS_DIGEST_SIZE 32
#define FMS_JOURNAL_MAGIC 0x464d5331U
#define FMS_JOURNAL_VERSION 1U

enum fms_status {
	FMS_OK = 0,
	FMS_ERR_ARGUMENT = -1,
	FMS_ERR_IO = -2,
	FMS_ERR_CORRUPT = -3,
	FMS_ERR_FULL = -4,
	FMS_ERR_KERNEL = -5,
	FMS_ERR_CAPABILITY = -6,
	FMS_ERR_NOT_FOUND = -7
};

struct fms_entry {
	uint64_t sequence;
	uint64_t record_id;
	uint64_t authority_capability;
	uint64_t kernel_generation;
	uint64_t provenance_sequence;
	uint32_t tier;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint32_t content_len;
	uint8_t digest[FMS_DIGEST_SIZE];
	char content[FMS_MAX_CONTENT];
};

struct fms_checkpoint_state {
	uint64_t checkpoint_id;
	uint64_t checkpoint_sequence;
	uint64_t parent_sequence;
	uint8_t state_digest[FMS_DIGEST_SIZE];
	uint8_t manifest_digest[FMS_DIGEST_SIZE];
	struct agi_lc_handoff handoff;
};

struct fms_service {
	int kernel_fd;
	int journal_fd;
	uint64_t agent_id;
	uint64_t agent_capability;
	uint64_t next_sequence;
	uint64_t scope_id;
	char journal_path[4096];
	struct fms_entry entries[FMS_MAX_RECORDS];
	size_t entry_count;
	struct fms_checkpoint_state checkpoint;
	int checkpoint_valid;
};

int fms_open(struct fms_service *service, const char *journal_path);
void fms_close(struct fms_service *service);
int fms_put(struct fms_service *service, const char *content,
	    uint32_t tier, uint32_t confidence_ppm, uint32_t importance_ppm,
	    uint64_t provenance_sequence, struct fms_entry *out);
int fms_get(const struct fms_service *service, uint64_t record_id,
	   struct fms_entry *out);
int fms_checkpoint(struct fms_service *service);
int fms_mark_crash(struct fms_service *service);
int fms_restore(struct fms_service *service);
int fms_replay(struct fms_service *service);
int fms_test_stale_capability(struct fms_service *service, uint64_t record_id);

#endif
