#ifndef FAISAL_WORLD_STATE_SERVICE_H
#define FAISAL_WORLD_STATE_SERVICE_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"

#define FWS_MAX_FACTS 64
#define FWS_MAX_ENTITY 64
#define FWS_MAX_PROPERTY 64
#define FWS_MAX_VALUE 256

enum fws_conflict_state {
	FWS_CONFLICT_NONE = 0,
	FWS_CONFLICT_DETECTED = 1,
	FWS_CONFLICT_RESOLVED = 2
};

struct fws_fact {
	uint64_t key_hash;
	uint64_t memory_record_id;
	uint64_t memory_capability;
	uint64_t provenance_sequence;
	uint64_t event_sequence;
	uint64_t generation;
	uint64_t freshness_deadline_ns;
	uint32_t confidence_ppm;
	uint32_t freshness_state;
	uint32_t conflict_state;
	uint8_t digest[FMS_DIGEST_SIZE];
	char entity[FWS_MAX_ENTITY];
	char property[FWS_MAX_PROPERTY];
	char value[FWS_MAX_VALUE];
};

struct fws_temporal_handle {
	uint64_t record_id;
	uint64_t authority_capability;
	uint64_t event_sequence;
	uint64_t generation;
};

struct fws_service {
	struct fms_service memory;
	struct fws_fact facts[FWS_MAX_FACTS];
	uint32_t fact_count;
	uint64_t last_ack_sequence;
	uint64_t last_observed_sequence;
	uint64_t world_generation;
	uint32_t resync_required;
};

int fws_open(struct fws_service *service, const char *journal_path);
void fws_close(struct fws_service *service);
int fws_world_query(struct fws_service *service, struct agi_lc_world_sync *out);
int fws_world_ack(struct fws_service *service, uint64_t sequence,
		  struct agi_lc_world_sync *out);
int fws_add_fact(struct fws_service *service, const char *entity,
		const char *property, const char *value, uint64_t provenance_sequence,
		uint64_t freshness_ttl_ns, uint32_t confidence_ppm,
		struct fws_fact *out);
int fws_get_fresh(struct fws_service *service, const char *entity,
			const char *property, struct fws_fact *out);
int fws_resolve_conflict(struct fws_service *service, const char *entity,
			const char *property, const char *value, uint64_t provenance_sequence,
			uint64_t freshness_ttl_ns, uint32_t confidence_ppm,
			struct fws_fact *out);
int fws_temporal_probe(struct fws_service *service,
			struct fws_temporal_handle *out);
int fws_resource_snapshot(struct fws_service *service,
			struct agi_lc_resource_snapshot *out);
int fws_test_sequence_guard(struct fws_service *service);
int fws_test_stale_temporal(struct fws_service *service,
			    const struct fws_temporal_handle *handle);

#endif
