#ifndef FAISAL_UNIFIED_MEMORY_H
#define FAISAL_UNIFIED_MEMORY_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include "../faisal-memory/faisal_memory_service.h"

#define FUM_MAX_RECORDS 128U
#define FUM_MAX_BACKENDS 16U
#define FUM_MAX_KEY 96U
#define FUM_MAX_RELATION 96U
#define FUM_MAX_CONTENT 4096U
#define FUM_MAX_BACKEND_NAME 64U
#define FUM_JOURNAL_MAGIC 0x46554d31U
#define FUM_JOURNAL_VERSION 1U
#define FUM_DIGEST_SIZE FMS_DIGEST_SIZE

enum fum_memory_class {
	FUM_WORKING = 1,
	FUM_EPISODIC = 2,
	FUM_SEMANTIC = 3,
	FUM_PROCEDURAL = 4,
	FUM_TEMPORAL = 5,
	FUM_ENTITY = 6,
	FUM_TASK = 7,
	FUM_ORGANIZATIONAL = 8,
	FUM_SYSTEM = 9,
	FUM_OPERATIONAL = 10,
	FUM_FAILURE = 11,
	FUM_DECISION = 12,
	FUM_PROVENANCE = 13
};

enum fum_record_state {
	FUM_RECORD_ACTIVE = 1,
	FUM_RECORD_SUPERSEDED = 2,
	FUM_RECORD_EXPIRED = 3,
	FUM_RECORD_REDACTED = 4
};

enum fum_status {
	FUM_OK = 0,
	FUM_ERR_ARGUMENT = -1,
	FUM_ERR_IO = -2,
	FUM_ERR_CORRUPT = -3,
	FUM_ERR_FULL = -4,
	FUM_ERR_NOT_FOUND = -5,
	FUM_ERR_CONFLICT = -6,
	FUM_ERR_ACCESS = -7,
	FUM_ERR_BACKEND = -8,
	FUM_ERR_STALE = -9
};

struct fum_backend {
	uint64_t backend_id;
	uint32_t kind;
	uint32_t state;
	char name[FUM_MAX_BACKEND_NAME];
};

struct fum_record {
	uint64_t record_id;
	uint64_t version;
	uint64_t parent_version;
	uint64_t created_at_ns;
	uint64_t expires_at_ns;
	uint64_t provenance_sequence;
	uint64_t owner_agent_id;
	uint64_t access_capability;
	uint32_t memory_class;
	uint32_t state;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint32_t encrypted;
	uint32_t backend_id;
	uint8_t content_digest[FUM_DIGEST_SIZE];
	char key[FUM_MAX_KEY];
	char relation[FUM_MAX_RELATION];
	char content[FUM_MAX_CONTENT];
};

struct fum_query {
	uint32_t memory_class;
	uint32_t include_expired;
	uint64_t owner_agent_id;
	uint64_t now_ns;
	char key[FUM_MAX_KEY];
	char relation[FUM_MAX_RELATION];
};

struct fum_service {
	int journal_fd;
	uint64_t next_record_id;
	uint64_t next_sequence;
	uint64_t next_backend_id;
	char journal_path[4096];
	struct fum_backend backends[FUM_MAX_BACKENDS];
	struct fum_record records[FUM_MAX_RECORDS];
	size_t backend_count;
	size_t record_count;
	pthread_mutex_t lock;
	int lock_initialized;
};

int fum_open(struct fum_service *service, const char *journal_path);
void fum_close(struct fum_service *service);
int fum_replay(struct fum_service *service);
int fum_register_backend(struct fum_service *service, const char *name,
				 uint32_t kind, struct fum_backend *out);
int fum_put(struct fum_service *service, uint32_t memory_class,
		    const char *key, const char *relation, const char *content,
		    uint64_t now_ns, uint64_t expires_at_ns,
		    uint64_t provenance_sequence, uint64_t owner_agent_id,
		    uint64_t access_capability, uint32_t confidence_ppm,
		    uint32_t importance_ppm, uint32_t backend_id,
		    struct fum_record *out);
int fum_get(const struct fum_service *service, uint64_t record_id,
		   uint64_t requester_agent_id, uint64_t requester_capability,
		   struct fum_record *out);
int fum_query(const struct fum_service *service, const struct fum_query *query,
		      struct fum_record *out, size_t out_count, size_t *found);
int fum_supersede(struct fum_service *service, uint64_t record_id,
			  const char *content, uint64_t now_ns,
			  struct fum_record *out);
int fum_forget_expired(struct fum_service *service, uint64_t now_ns,
			      uint32_t *forgotten);
int fum_conflict(const struct fum_service *service, const char *key,
			const char *content, uint64_t *conflict_record_id);
int fum_test_backend_neutrality(const struct fum_service *service,
					uint32_t backend_id);

#endif
