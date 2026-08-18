#ifndef FAISAL_ADAPTIVE_H
#define FAISAL_ADAPTIVE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FAP_ABI_VERSION 1U
#define FAP_DIGEST_SIZE 32U
#define FAP_MAX_EVENTS 4096U
#define FAP_MAX_PAYLOAD 1024U
#define FAP_MAX_REASON 128U
#define FAP_EVENT_MAGIC 0x46415031U
#define FAP_EVENT_VERSION 1U
#define FAP_FLAG_AUTHORITY_GRANTED (1U << 0)
#define FAP_FLAG_VERIFIED_INPUT (1U << 1)
#define FAP_FLAG_MODEL_PROPOSAL (1U << 2)
#define FAP_FLAG_FALLBACK (1U << 3)
#define FAP_FLAG_EXPERIMENTAL (1U << 4)
#define FAP_FLAGS_ALL (FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT | \
			  FAP_FLAG_MODEL_PROPOSAL | FAP_FLAG_FALLBACK | \
			  FAP_FLAG_EXPERIMENTAL)

enum fap_mode {
	FAP_MODE_BASELINE = 1U,
	FAP_MODE_ADAPTIVE = 2U,
	FAP_MODE_FALLBACK = 3U,
	FAP_MODE_QUARANTINED = 4U
};

enum fap_event_kind {
	FAP_EVENT_OBSERVATION = 1U,
	FAP_EVENT_PROPOSAL = 2U,
	FAP_EVENT_COMMIT = 3U,
	FAP_EVENT_ROLLBACK = 4U
};

enum fap_status {
	FAP_OK = 0,
	FAP_ERR_ARGUMENT = -1,
	FAP_ERR_IO = -2,
	FAP_ERR_FULL = -3,
	FAP_ERR_NOT_FOUND = -4,
	FAP_ERR_STATE = -5,
	FAP_ERR_AUTHORITY = -6,
	FAP_ERR_GENERATION = -7,
	FAP_ERR_DEADLINE = -8,
	FAP_ERR_BOUNDS = -9,
	FAP_ERR_TAMPER = -10,
	FAP_ERR_REPLAY = -11,
	FAP_ERR_OVERFLOW = -12,
	FAP_ERR_POLICY = -13,
	FAP_ERR_CORRUPT = -14,
	FAP_ERR_UNSAFE = -15
};

struct fap_action {
	uint32_t admission_permille;
	uint32_t migration_permille;
	uint32_t lease_permille;
	int32_t priority_delta;
	uint32_t mode;
	uint64_t policy_generation;
	uint64_t action_generation;
	uint8_t action_digest[FAP_DIGEST_SIZE];
};

struct fap_policy {
	uint64_t current_time_ns;
	uint64_t observation_max_age_ns;
	uint32_t minimum_admission_permille;
	uint32_t maximum_admission_permille;
	uint32_t minimum_migration_permille;
	uint32_t maximum_migration_permille;
	uint32_t minimum_lease_permille;
	uint32_t maximum_lease_permille;
	int32_t minimum_priority_delta;
	int32_t maximum_priority_delta;
	uint32_t maximum_action_delta;
	uint32_t maximum_queue_depth;
	uint32_t maximum_pressure_permille;
	uint32_t maximum_thermal_permille;
	uint32_t minimum_health_permille;
	struct fap_action baseline;
	struct fap_action fallback;
	uint8_t authority_digest[FAP_DIGEST_SIZE];
	uint8_t policy_digest[FAP_DIGEST_SIZE];
};

struct fap_observation {
	uint64_t observation_seq;
	uint64_t policy_generation;
	uint64_t observed_at_ns;
	uint64_t source_generation;
	uint32_t queue_depth;
	uint32_t pressure_permille;
	uint32_t thermal_permille;
	uint32_t health_permille;
	uint32_t cache_hit_permille;
	uint32_t deadline_misses;
	uint64_t latency_ns;
	uint64_t throughput_units;
	uint8_t source_digest[FAP_DIGEST_SIZE];
	uint8_t provenance_digest[FAP_DIGEST_SIZE];
	uint8_t observation_digest[FAP_DIGEST_SIZE];
};

struct fap_recommendation {
	uint64_t recommendation_id;
	uint64_t observation_seq;
	uint64_t policy_generation;
	uint64_t created_at_ns;
	uint32_t flags;
	uint32_t source_kind;
	struct fap_action action;
	uint8_t source_digest[FAP_DIGEST_SIZE];
	uint8_t recommendation_digest[FAP_DIGEST_SIZE];
	char reason[FAP_MAX_REASON];
};

struct fap_observation_record {
	struct fap_observation observation;
	struct fap_recommendation recommendation;
};

struct fap_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t observation_seq;
	uint64_t recommendation_id;
	uint64_t policy_generation;
	uint64_t observed_at_ns;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FAP_DIGEST_SIZE];
	uint8_t payload_digest[FAP_DIGEST_SIZE];
	uint8_t event_digest[FAP_DIGEST_SIZE];
};

struct fap_disk_record {
	struct fap_event event;
	uint8_t payload[FAP_MAX_PAYLOAD];
};

struct fap_attestation {
	uint64_t last_sequence;
	uint64_t last_observation_seq;
	uint64_t last_recommendation_id;
	uint64_t policy_generation;
	uint64_t fallback_count;
	uint64_t rollback_count;
	uint8_t chain_digest[FAP_DIGEST_SIZE];
};

struct fap_service {
	int journal_fd;
	pthread_mutex_t lock;
	struct fap_policy policy;
	struct fap_action current_action;
	struct fap_observation last_observation;
	struct fap_recommendation current_recommendation;
	uint64_t policy_generation;
	uint64_t next_recommendation_id;
	uint64_t event_sequence;
	uint64_t fallback_count;
	uint64_t rollback_count;
	uint32_t has_observation;
	uint8_t chain_digest[FAP_DIGEST_SIZE];
};

int fap_open(struct fap_service *service, const char *journal_path,
	     const struct fap_policy *policy);
void fap_close(struct fap_service *service);
int fap_observe(struct fap_service *service, const struct fap_observation *observation,
		struct fap_recommendation *out);
int fap_propose(struct fap_service *service, const struct fap_recommendation *proposal,
		struct fap_recommendation *out);
int fap_commit(struct fap_service *service, uint64_t recommendation_id,
	       uint64_t now_ns, uint32_t flags,
	       struct fap_action *out);
int fap_rollback(struct fap_service *service, uint64_t now_ns, uint32_t flags,
		const char *reason, struct fap_action *out);
int fap_query(const struct fap_service *service, struct fap_attestation *out);
int fap_verify_event(const struct fap_event *event, const uint8_t *payload,
		     const uint8_t previous_digest[FAP_DIGEST_SIZE]);

#endif
