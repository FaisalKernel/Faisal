#ifndef FAISAL_RUNTIME_ATTESTATION_H
#define FAISAL_RUNTIME_ATTESTATION_H

#include <stdint.h>
#include <linux/agi_lifecycle.h>

#define FRA_DIGEST_SIZE AGI_LC_DIGEST_SIZE
#define FRA_HEALTH_SELF_STATE (1U << 0)
#define FRA_HEALTH_RESOURCE (1U << 1)
#define FRA_HEALTH_OBSERVABILITY (1U << 2)
#define FRA_HEALTH_IDENTITY (1U << 3)
#define FRA_HEALTH_CAPABILITY (1U << 4)
#define FRA_HEALTH_BUDGET (1U << 5)

#define FRA_SAMPLE_REQUIRED_MASK (FRA_HEALTH_SELF_STATE | FRA_HEALTH_RESOURCE | \
				      FRA_HEALTH_OBSERVABILITY | FRA_HEALTH_IDENTITY | \
				      FRA_HEALTH_CAPABILITY)

#define FRA_OK 0
#define FRA_ERR_ARGUMENT -1
#define FRA_ERR_OPEN -2
#define FRA_ERR_IOCTL -3
#define FRA_ERR_HEALTH -4
#define FRA_ERR_DIGEST -5

struct fra_attestation {
	struct agi_lc_self_state self_state;
	struct agi_lc_resource_snapshot resource;
	struct agi_lc_observability observability;
	struct agi_lc_light_agent identity;
	uint8_t digest[FRA_DIGEST_SIZE];
	uint32_t valid_mask;
	uint32_t health_mask;
	uint32_t state;
	uint32_t reserved;
	uint64_t sampled_at_ns;
	uint64_t sample_sequence;
};

enum fra_state {
	FRA_STATE_EMPTY = 0,
	FRA_STATE_HEALTHY = 1,
	FRA_STATE_DEGRADED = 2,
	FRA_STATE_UNAVAILABLE = 3
};

struct fra_service {
	int kernel_fd;
	uint64_t session_id;
	uint64_t agent_id;
	uint64_t capability;
	struct agi_lc_light_agent identity;
	struct fra_attestation attestation;
};

int fra_open(struct fra_service *service);
void fra_close(struct fra_service *service);
int fra_sample(struct fra_service *service);
int fra_compute_digest(struct fra_service *service);
int fra_evaluate(struct fra_service *service);
int fra_run(struct fra_service *service);

#endif
