#ifndef FAISAL_SNAPSHOT_INDEX_H
#define FAISAL_SNAPSHOT_INDEX_H

#include <stddef.h>
#include <stdint.h>

#define FSI_ABI_VERSION 1U
#define FSI_DIGEST_SIZE 32U
#define FSI_MAX_SNAPSHOTS 128U
#define FSI_MAX_PAYLOAD 2048U
#define FSI_MAX_JOURNAL_PATH 4096U
#define FSI_MAGIC 0x46534931U
#define FSI_VERSION 1U
#define FSI_KIND_SNAPSHOT 1U
#define FSI_KIND_COMPACT 2U
#define FSI_KIND_EXPIRE 3U
#define FSI_RETENTION_EPHEMERAL 1U
#define FSI_RETENTION_STANDARD 2U
#define FSI_RETENTION_PINNED 3U
#define FSI_STATE_ACTIVE 1U
#define FSI_STATE_COMPACTED 2U
#define FSI_STATE_EXPIRED 3U
#define FSI_FLAG_VERIFIED (1U << 0)
#define FSI_FLAG_MODEL_PROPOSAL (1U << 1)
#define FSI_FLAGS_ALL (FSI_FLAG_VERIFIED | FSI_FLAG_MODEL_PROPOSAL)

enum fsi_status {
	FSI_OK = 0,
	FSI_ERR_ARGUMENT = -1,
	FSI_ERR_IO = -2,
	FSI_ERR_CORRUPT = -3,
	FSI_ERR_FULL = -4,
	FSI_ERR_NOT_FOUND = -5,
	FSI_ERR_GENERATION = -6,
	FSI_ERR_STALE = -7,
	FSI_ERR_TAMPER = -8,
	FSI_ERR_POLICY = -9,
	FSI_ERR_OVERFLOW = -10
};

struct fsi_snapshot {
	uint64_t snapshot_id;
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t agent_id;
	uint64_t objective_generation;
	uint64_t task_generation;
	uint64_t sequence;
	uint64_t created_ns;
	uint64_t expires_ns;
	uint32_t state;
	uint32_t retention_class;
	uint32_t importance_ppm;
	uint32_t flags;
	uint32_t payload_len;
	uint8_t parent_digest[FSI_DIGEST_SIZE];
	uint8_t payload_digest[FSI_DIGEST_SIZE];
	uint8_t snapshot_digest[FSI_DIGEST_SIZE];
	uint8_t payload[FSI_MAX_PAYLOAD];
};

struct fsi_snapshot_request {
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t agent_id;
	uint64_t objective_generation;
	uint64_t task_generation;
	uint64_t now_ns;
	uint64_t max_age_ns;
	uint32_t retention_class;
	uint32_t minimum_importance_ppm;
	uint32_t flags;
};

struct fsi_compaction_policy {
	uint64_t now_ns;
	uint64_t minimum_age_ns;
	uint32_t maximum_live_snapshots;
	uint32_t minimum_importance_ppm;
	uint32_t preserve_pinned;
};

struct fsi_attestation {
	uint64_t next_snapshot_id;
	uint64_t next_sequence;
	uint64_t journal_records;
	uint64_t active_snapshots;
	uint64_t compacted_snapshots;
	uint64_t expired_snapshots;
	uint8_t chain_digest[FSI_DIGEST_SIZE];
};

struct fsi_disk_record {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t record_sequence;
	uint8_t previous_digest[FSI_DIGEST_SIZE];
	struct fsi_snapshot snapshot;
	uint8_t record_digest[FSI_DIGEST_SIZE];
};

struct fsi_service {
	int journal_fd;
	char journal_path[FSI_MAX_JOURNAL_PATH];
	struct fsi_snapshot snapshots[FSI_MAX_SNAPSHOTS];
	size_t count;
	size_t active_indices[FSI_MAX_SNAPSHOTS];
	size_t active_count;
	uint64_t next_snapshot_id;
	uint64_t next_sequence;
	uint64_t journal_records;
	uint8_t chain_digest[FSI_DIGEST_SIZE];
};

int fsi_open(struct fsi_service *service, const char *journal_path);
void fsi_close(struct fsi_service *service);
int fsi_replay(struct fsi_service *service);
int fsi_append(struct fsi_service *service,
	       const struct fsi_snapshot_request *request,
	       const uint8_t *payload, size_t payload_len,
	       const uint8_t parent_digest[FSI_DIGEST_SIZE],
	       uint64_t expires_ns, uint32_t importance_ppm,
	       struct fsi_snapshot *out);
int fsi_restore_latest(const struct fsi_service *service,
		       const struct fsi_snapshot_request *request,
		       struct fsi_snapshot *out);
int fsi_expire(struct fsi_service *service, uint64_t now_ns,
	       uint32_t *expired_count);
int fsi_compact(struct fsi_service *service,
		const struct fsi_compaction_policy *policy,
		uint32_t *compacted_count);
int fsi_verify_snapshot(const struct fsi_snapshot *snapshot);
int fsi_query_attestation(const struct fsi_service *service,
			  struct fsi_attestation *out);
int fsi_verify_record(const struct fsi_disk_record *record,
		      const uint8_t previous_digest[FSI_DIGEST_SIZE]);

#endif
