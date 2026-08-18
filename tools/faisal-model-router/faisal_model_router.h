#ifndef FAISAL_MODEL_ROUTER_H
#define FAISAL_MODEL_ROUTER_H

#include <stddef.h>
#include <stdint.h>

#define FMR_MAX_MODELS 64U
#define FMR_MAX_NAME 96U
#define FMR_MAX_REASON 256U
#define FMR_MAX_ERROR 128U
#define FMR_DIGEST_SIZE 32U
#define FMR_SCORE_MAX 1000000U
#define FMR_DEFAULT_FAILURE_THRESHOLD 3U
#define FMR_DEFAULT_COOLDOWN_NS 1000000000ULL

/* Provider/runtime capability claims are metadata, not execution authority. */
#define FMR_CAP_STRUCTURED_OUTPUT (1U << 0)
#define FMR_CAP_TOOL_CALLING      (1U << 1)
#define FMR_CAP_BACKGROUND       (1U << 2)
#define FMR_CAP_STREAMING        (1U << 3)
#define FMR_CAP_VISION           (1U << 4)
#define FMR_CAP_SPEECH           (1U << 5)
#define FMR_CAP_EMBEDDING        (1U << 6)
#define FMR_CAP_MULTIMODAL       (1U << 7)
#define FMR_CAP_CITATIONS        (1U << 8)
#define FMR_CAP_JSON_SCHEMA      (1U << 9)

#define FMR_LOCAL 1U
#define FMR_CLOUD 2U
#define FMR_OPEN 4U
#define FMR_PROPRIETARY 8U
#define FMR_REASONING 16U
#define FMR_CODING 32U
#define FMR_VISION 64U
#define FMR_SPEECH 128U
#define FMR_EMBEDDING 256U
#define FMR_MULTIMODAL 512U

enum fmr_status {
	FMR_OK = 0,
	FMR_ERR_ARGUMENT = -1,
	FMR_ERR_IO = -2,
	FMR_ERR_CORRUPT = -3,
	FMR_ERR_FULL = -4,
	FMR_ERR_NOT_FOUND = -5,
	FMR_ERR_NO_ROUTE = -6,
	FMR_ERR_REPLAY = -7,
	FMR_ERR_STALE = -8,
	FMR_ERR_COOLDOWN = -9
};

enum fmr_route_state {
	FMR_ROUTE_SELECTED = 1,
	FMR_ROUTE_ESCALATED = 2,
	FMR_ROUTE_DEESCALATED = 3,
	FMR_ROUTE_FALLBACK = 4
};

enum fmr_circuit_state {
	FMR_CIRCUIT_CLOSED = 1,
	FMR_CIRCUIT_OPEN = 2,
	FMR_CIRCUIT_HALF_OPEN = 3
};

struct fmr_model {
	uint64_t model_id;
	uint64_t generation;
	uint32_t provider_kind;
	uint32_t modalities;
	uint32_t capability_mask;
	uint32_t health_ppm;
	uint32_t accuracy_ppm;
	uint32_t confidence_ppm;
	uint32_t uncertainty_ppm;
	uint32_t circuit_state;
	uint32_t failure_streak;
	uint32_t failure_threshold;
	uint64_t cooldown_until_ns;
	uint64_t latency_ns;
	uint64_t cost_micro;
	uint64_t context_tokens;
	uint64_t hardware_mask;
	uint64_t locality_mask;
	uint32_t privacy_level;
	uint32_t reserved;
	uint64_t successes;
	uint64_t failures;
	uint64_t total_latency_ns;
	uint64_t last_result_ns;
	char provider[FMR_MAX_NAME];
	char name[FMR_MAX_NAME];
	char last_error[FMR_MAX_ERROR];
};

struct fmr_request {
	uint64_t request_sequence;
	uint64_t now_ns;
	uint32_t difficulty;
	uint32_t required_modalities;
	uint32_t required_capabilities;
	uint32_t privacy_level;
	uint32_t retry_budget;
	uint64_t max_latency_ns;
	uint64_t max_cost_micro;
	uint32_t min_accuracy_ppm;
	uint64_t context_tokens;
	uint64_t hardware_mask;
	uint64_t locality_mask;
	uint32_t require_local;
	uint32_t allow_cloud;
};

struct fmr_route {
	uint64_t request_sequence;
	uint64_t model_id;
	uint64_t model_generation;
	uint32_t state;
	uint32_t attempt;
	uint32_t score;
	uint32_t fallback_count;
	uint64_t estimated_latency_ns;
	uint64_t estimated_cost_micro;
	uint8_t receipt_digest[FMR_DIGEST_SIZE];
	char reason[FMR_MAX_REASON];
};

struct fmr_router {
	struct fmr_model models[FMR_MAX_MODELS];
	size_t count;
	uint64_t next_model_id;
	uint64_t next_generation;
	uint32_t failure_threshold;
	uint64_t cooldown_ns;
};

int fmr_init(struct fmr_router *router);
int fmr_register(struct fmr_router *router, const char *provider,
		 const char *name, uint32_t provider_kind, uint32_t modalities,
		 uint32_t health_ppm, uint64_t latency_ns, uint64_t cost_micro,
		 uint64_t context_tokens, uint64_t hardware_mask,
		 uint32_t privacy_level, uint32_t locality_mask,
		 struct fmr_model *out);
int fmr_set_capabilities(struct fmr_router *router, uint64_t model_id,
			 uint32_t capability_mask, uint32_t confidence_ppm);
int fmr_set_generation(struct fmr_router *router, uint64_t model_id,
			uint64_t generation);
int fmr_record_result(struct fmr_router *router, uint64_t model_id,
			 int success, uint64_t latency_ns, uint32_t accuracy_ppm);
int fmr_record_result_at(struct fmr_router *router, uint64_t model_id,
			 int success, uint64_t latency_ns, uint32_t accuracy_ppm,
			 uint64_t now_ns, const char *error_text);
int fmr_route(const struct fmr_router *router, const struct fmr_request *request,
	      struct fmr_route *out);
int fmr_verify_route(const struct fmr_router *router,
		     const struct fmr_request *request,
		     const struct fmr_route *route);
int fmr_get(const struct fmr_router *router, uint64_t model_id,
	   struct fmr_model *out);

#endif
