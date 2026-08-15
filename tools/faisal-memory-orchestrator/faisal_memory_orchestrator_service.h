#ifndef FAISAL_MEMORY_ORCHESTRATOR_SERVICE_H
#define FAISAL_MEMORY_ORCHESTRATOR_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"
#include "../faisal-experience/faisal_experience_service.h"
#include "../faisal-world/faisal_world_state_service.h"

#define FMO_MAX_RECORDS 96U
#define FMO_MAX_SCOPE 64U
#define FMO_MAX_TOPIC 128U
#define FMO_MAX_SOURCE 256U
#define FMO_MAX_CONTENT 1024U
#define FMO_MAX_SKILL 256U
#define FMO_MAX_CAUSAL 256U
#define FMO_MAX_RESULTS 16U
#define FMO_MAX_CONTEXT 4096U
#define FMO_JOURNAL_MAGIC 0x464d4f31U
#define FMO_JOURNAL_VERSION 1U
#define FMO_QUERY_ALL 0U

enum fmo_status {
	FMO_OK = 0,
	FMO_ERR_ARGUMENT = -1,
	FMO_ERR_IO = -2,
	FMO_ERR_CORRUPT = -3,
	FMO_ERR_FULL = -4,
	FMO_ERR_KERNEL = -5,
	FMO_ERR_NOT_FOUND = -6,
	FMO_ERR_POLICY = -7
};

enum fmo_memory_class {
	FMO_CLASS_WORKING = 1,
	FMO_CLASS_EPISODIC = 2,
	FMO_CLASS_SEMANTIC = 3,
	FMO_CLASS_PROCEDURAL = 4,
	FMO_CLASS_WORLD = 5,
	FMO_CLASS_SIMULATION = 6,
	FMO_CLASS_SELF = 7,
	FMO_CLASS_EXPERIENCE = 8,
	FMO_CLASS_MAX = FMO_CLASS_EXPERIENCE
};

enum fmo_truth_class {
	FMO_TRUTH_REAL_WORLD_FACT = 1,
	FMO_TRUTH_SIMULATION_RESULT = 2,
	FMO_TRUTH_PREDICTION = 3,
	FMO_TRUTH_HYPOTHESIS = 4,
	FMO_TRUTH_UNCERTAINTY = 5
};

enum fmo_record_state {
	FMO_STATE_ACTIVE = 1,
	FMO_STATE_SUPERSEDED = 2,
	FMO_STATE_CONFLICT = 3,
	FMO_STATE_EXPIRED = 4,
	FMO_STATE_DELETED = 5
};

enum fmo_ingest_result {
	FMO_INGEST_NEW = 1,
	FMO_INGEST_DEDUPLICATED = 2,
	FMO_INGEST_SUPERSEDES = 3,
	FMO_INGEST_CONFLICT = 4
};

struct fmo_provenance {
	uint64_t source_id;
	uint64_t experience_sequence;
	uint64_t agent_id;
	uint64_t task_id;
	uint64_t event_sequence;
	uint64_t verification_sequence;
};

struct fmo_record {
	uint64_t id;
	uint64_t memory_sequence;
	uint64_t memory_record_id;
	uint64_t memory_capability;
	uint64_t supersedes_id;
	uint64_t superseded_by_id;
	uint64_t conflict_with_id;
	uint64_t created_at_ns;
	uint64_t observed_at_ns;
	uint64_t freshness_deadline_ns;
	uint32_t memory_class;
	uint32_t truth_class;
	uint32_t state;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	struct fmo_provenance provenance;
	char scope[FMO_MAX_SCOPE];
	char topic[FMO_MAX_TOPIC];
	char source[FMO_MAX_SOURCE];
	char content[FMO_MAX_CONTENT];
	char skill[FMO_MAX_SKILL];
	char causal[FMO_MAX_CAUSAL];
};

struct fmo_ingest {
	uint32_t memory_class;
	uint32_t truth_class;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint64_t observed_at_ns;
	uint64_t freshness_ttl_ns;
	struct fmo_provenance provenance;
	char scope[FMO_MAX_SCOPE];
	char topic[FMO_MAX_TOPIC];
	char source[FMO_MAX_SOURCE];
	char content[FMO_MAX_CONTENT];
	char skill[FMO_MAX_SKILL];
	char causal[FMO_MAX_CAUSAL];
};

struct fmo_experience_input {
	uint64_t agent_id;
	uint64_t task_id;
	uint64_t event_sequence;
	uint64_t verification_sequence;
	uint64_t observed_at_ns;
	uint64_t freshness_ttl_ns;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	char scope[FMO_MAX_SCOPE];
	char topic[FMO_MAX_TOPIC];
	char source[FMO_MAX_SOURCE];
	char action[FMO_MAX_CONTENT];
	char observation[FMO_MAX_CONTENT];
	char result[FMO_MAX_CONTENT];
	char lesson[FMO_MAX_CONTENT];
	char skill[FMO_MAX_SKILL];
	char causal[FMO_MAX_CAUSAL];
};

struct fmo_query {
	char query[FMO_MAX_CONTENT];
	char scope[FMO_MAX_SCOPE];
	uint32_t class_mask;
	uint32_t truth_mask;
	uint32_t top_k;
	uint32_t include_stale;
	uint32_t include_simulation;
	uint32_t require_provenance;
	uint32_t minimum_confidence_ppm;
	uint32_t minimum_importance_ppm;
	uint64_t task_id;
	uint64_t observed_after_ns;
	uint64_t observed_before_ns;
};

struct fmo_result {
	uint64_t record_id;
	uint32_t score;
	uint32_t state;
	uint32_t memory_class;
	uint32_t truth_class;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint64_t observed_at_ns;
	uint64_t freshness_deadline_ns;
	char topic[FMO_MAX_TOPIC];
	char source[FMO_MAX_SOURCE];
	char content[FMO_MAX_CONTENT];
};

struct fmo_context {
	uint32_t count;
	uint32_t truncated;
	uint32_t total_score;
	char text[FMO_MAX_CONTEXT];
	struct fmo_result results[FMO_MAX_RESULTS];
};

struct fmo_stats {
	uint32_t total_records;
	uint32_t active_records;
	uint32_t stale_records;
	uint32_t conflict_records;
	uint32_t superseded_records;
	uint32_t expired_records;
	uint32_t simulation_records;
	uint32_t provenance_complete_records;
};

struct fmo_service {
	struct fms_service memory;
	struct fes_service experience;
	struct fws_service world;
	int index_fd;
	uint64_t next_id;
	char journal_prefix[4096];
	char index_path[4096];
	struct fmo_record records[FMO_MAX_RECORDS];
	uint32_t record_count;
};

int fmo_open(struct fmo_service *service, const char *journal_prefix);
void fmo_close(struct fmo_service *service);
int fmo_ingest(struct fmo_service *service, const struct fmo_ingest *input,
	       struct fmo_record *out, uint32_t *result);
int fmo_consolidate(struct fmo_service *service,
		   const struct fmo_experience_input *input,
		   uint32_t *records_created);
int fmo_retrieve(struct fmo_service *service, const struct fmo_query *query,
		struct fmo_result *results, uint32_t *count);
int fmo_build_context(struct fmo_service *service, const struct fmo_query *query,
			struct fmo_context *out);
int fmo_mark_stale(struct fmo_service *service, uint64_t now_ns,
			uint32_t *expired_count);
int fmo_get(const struct fmo_service *service, uint64_t record_id,
		   struct fmo_record *out);
int fmo_stats(const struct fmo_service *service, uint64_t now_ns,
		     struct fmo_stats *out);
int fmo_test_simulation_boundary(struct fmo_service *service,
				 const char *scope, uint64_t *record_id);
int fmo_test_contradiction_lifecycle(struct fmo_service *service,
				     const char *scope, uint64_t observed_at_ns,
				     uint64_t *new_record_id);

#endif
