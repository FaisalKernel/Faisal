#ifndef FAISAL_OPTIMIZER_H
#define FAISAL_OPTIMIZER_H

#include "../faisal-adaptive/faisal_adaptive.h"
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FAO_ABI_VERSION 1U
#define FAO_DIGEST_SIZE 32U
#define FAO_MAX_SAMPLES 64U
#define FAO_MAX_EVENTS 4096U
#define FAO_MAX_PAYLOAD 2048U
#define FAO_EVENT_MAGIC 0x46414f31U
#define FAO_EVENT_VERSION 1U
#define FAO_FLAG_AUTHORITY_GRANTED (1U << 0)
#define FAO_FLAG_VERIFIED_INPUT (1U << 1)
#define FAO_FLAG_MODEL_ADVISORY (1U << 2)
#define FAO_FLAG_EXPERIMENTAL (1U << 3)
#define FAO_FLAGS_ALL (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | \
			  FAO_FLAG_MODEL_ADVISORY | FAO_FLAG_EXPERIMENTAL)

enum fao_lane {
	FAO_LANE_CONTROL = 1U,
	FAO_LANE_CANARY = 2U
};

enum fao_stage {
	FAO_STAGE_IDLE = 1U,
	FAO_STAGE_PROPOSED = 2U,
	FAO_STAGE_APPROVED = 3U,
	FAO_STAGE_CANARY = 4U,
	FAO_STAGE_ACTIVE = 5U,
	FAO_STAGE_ROLLED_BACK = 6U
};

enum fao_regression_flag {
	FAO_REGRESSION_LATENCY = 1U << 0,
	FAO_REGRESSION_THROUGHPUT = 1U << 1,
	FAO_REGRESSION_PRESSURE = 1U << 2,
	FAO_REGRESSION_THERMAL = 1U << 3,
	FAO_REGRESSION_HEALTH = 1U << 4,
	FAO_REGRESSION_QUEUE = 1U << 5
};

enum fao_status {
	FAO_OK = 0,
	FAO_ERR_ARGUMENT = -1,
	FAO_ERR_IO = -2,
	FAO_ERR_FULL = -3,
	FAO_ERR_STATE = -4,
	FAO_ERR_AUTHORITY = -5,
	FAO_ERR_GENERATION = -6,
	FAO_ERR_DEADLINE = -7,
	FAO_ERR_BOUNDS = -8,
	FAO_ERR_TAMPER = -9,
	FAO_ERR_REPLAY = -10,
	FAO_ERR_OVERFLOW = -11,
	FAO_ERR_NOT_FOUND = -12,
	FAO_ERR_UNSAFE = -13
};

struct fao_policy {
	uint64_t now_ns;
	uint64_t max_age_ns;
	uint32_t minimum_canary_samples;
	uint32_t maximum_latency_increase_permille;
	uint32_t maximum_throughput_decrease_permille;
	uint32_t maximum_pressure_permille;
	uint32_t maximum_thermal_permille;
	uint32_t minimum_health_permille;
	uint32_t maximum_queue_depth;
	uint32_t maximum_forecast_risk_permille;
	uint32_t minimum_confidence_permille;
	uint8_t authority_digest[FAO_DIGEST_SIZE];
	uint8_t policy_digest[FAO_DIGEST_SIZE];
};

struct fao_sample {
	uint64_t sequence;
	uint64_t policy_generation;
	uint64_t observed_at_ns;
	uint64_t source_generation;
	uint32_t lane;
	uint32_t queue_depth;
	uint32_t pressure_permille;
	uint32_t thermal_permille;
	uint32_t health_permille;
	uint32_t cache_hit_permille;
	uint32_t deadline_misses;
	uint64_t latency_ns;
	uint64_t throughput_units;
	uint64_t energy_uj;
	uint8_t source_digest[FAO_DIGEST_SIZE];
	uint8_t provenance_digest[FAO_DIGEST_SIZE];
	uint8_t sample_digest[FAO_DIGEST_SIZE];
};

struct fao_window_stats {
	uint32_t count;
	uint64_t first_sequence;
	uint64_t last_sequence;
	uint64_t mean_latency_ns;
	uint64_t mean_throughput_units;
	uint32_t mean_pressure_permille;
	uint32_t mean_thermal_permille;
	uint32_t mean_health_permille;
	uint64_t mean_energy_uj;
};

struct fao_forecast {
	uint64_t forecast_id;
	uint64_t sample_sequence;
	uint64_t policy_generation;
	uint64_t created_at_ns;
	uint32_t risk_permille;
	uint32_t confidence_permille;
	uint32_t regression_flags;
	uint64_t predicted_latency_ns;
	uint64_t predicted_throughput_units;
	uint32_t predicted_queue_depth;
	uint32_t predicted_pressure_permille;
	uint32_t predicted_thermal_permille;
	uint32_t predicted_health_permille;
	uint8_t source_digest[FAO_DIGEST_SIZE];
	uint8_t forecast_digest[FAO_DIGEST_SIZE];
};

struct fao_sample_record {
	struct fao_sample sample;
	struct fao_forecast forecast;
};

struct fao_candidate {
	uint64_t candidate_id;
	uint64_t forecast_id;
	uint64_t recommendation_id;
	uint64_t policy_generation;
	uint64_t created_at_ns;
	uint32_t flags;
	uint32_t stage;
	struct fap_action action;
	uint8_t candidate_digest[FAO_DIGEST_SIZE];
};

struct fao_compare {
	uint32_t control_count;
	uint32_t canary_count;
	uint64_t control_mean_latency_ns;
	uint64_t canary_mean_latency_ns;
	uint64_t control_mean_throughput_units;
	uint64_t canary_mean_throughput_units;
	uint32_t control_mean_pressure_permille;
	uint32_t canary_mean_pressure_permille;
	uint32_t control_mean_thermal_permille;
	uint32_t canary_mean_thermal_permille;
	uint32_t control_min_health_permille;
	uint32_t canary_min_health_permille;
	uint32_t regression_flags;
	uint8_t compare_digest[FAO_DIGEST_SIZE];
};

struct fao_transition {
	uint64_t candidate_id;
	uint64_t policy_generation;
	uint32_t from_stage;
	uint32_t to_stage;
	int32_t status;
	uint8_t reason_digest[FAO_DIGEST_SIZE];
};

enum fao_event_kind {
	FAO_EVENT_SAMPLE = 1U,
	FAO_EVENT_FORECAST = 2U,
	FAO_EVENT_CANDIDATE = 3U,
	FAO_EVENT_TRANSITION = 4U,
	FAO_EVENT_COMPARE = 5U
};

struct fao_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t policy_generation;
	uint64_t object_id;
	uint64_t observed_at_ns;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FAO_DIGEST_SIZE];
	uint8_t payload_digest[FAO_DIGEST_SIZE];
	uint8_t event_digest[FAO_DIGEST_SIZE];
};

struct fao_disk_record {
	struct fao_event event;
	uint8_t payload[FAO_MAX_PAYLOAD];
};

struct fao_attestation {
	uint64_t event_sequence;
	uint64_t sample_sequence;
	uint64_t forecast_id;
	uint64_t candidate_id;
	uint64_t policy_generation;
	uint32_t stage;
	uint32_t regression_flags;
	uint32_t rollback_count;
	uint8_t chain_digest[FAO_DIGEST_SIZE];
};

struct fao_service {
	int journal_fd;
	pthread_mutex_t lock;
	struct fap_service *adaptive;
	struct fao_policy policy;
	struct fao_sample samples[FAO_MAX_SAMPLES];
	uint32_t sample_count;
	uint32_t sample_cursor;
	uint64_t last_sample_sequence;
	uint64_t next_forecast_id;
	uint64_t next_candidate_id;
	uint64_t event_sequence;
	uint32_t stage;
	uint32_t rollback_count;
	struct fao_forecast forecast;
	struct fao_candidate candidate;
	struct fao_compare compare;
	uint8_t chain_digest[FAO_DIGEST_SIZE];
};

int fao_open(struct fao_service *service, const char *journal_path,
	     const struct fao_policy *policy, struct fap_service *adaptive);
void fao_close(struct fao_service *service);
int fao_ingest(struct fao_service *service, const struct fao_sample *sample,
	       struct fao_forecast *out);
int fao_attach_recommendation(struct fao_service *service,
			      const struct fap_recommendation *recommendation,
			      struct fao_candidate *out);
int fao_approve(struct fao_service *service, uint64_t candidate_id,
		uint64_t now_ns, uint32_t flags);
int fao_begin_canary(struct fao_service *service, uint64_t candidate_id,
		     uint64_t now_ns, uint32_t flags);
int fao_monitor(struct fao_service *service, uint64_t now_ns,
		uint32_t flags, struct fao_compare *out);
int fao_query(const struct fao_service *service, struct fao_attestation *out);
int fao_verify_event(const struct fao_event *event, const uint8_t *payload,
		     const uint8_t previous_digest[FAO_DIGEST_SIZE]);

#endif
