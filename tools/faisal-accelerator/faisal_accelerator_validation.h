#ifndef FAISAL_ACCELERATOR_VALIDATION_H
#define FAISAL_ACCELERATOR_VALIDATION_H

#include <stdint.h>
#include <linux/agi_lifecycle.h>

#define M79_PROVIDER_NAME_MAX 96
#define M79_FUZZ_CASES 64

#define M79_PROVIDER_AVAILABLE 1U
#define M79_PROVIDER_UNSUPPORTED 2U
#define M79_PROVIDER_REJECTED 3U

struct m79_provider_evidence {
	uint32_t provider_state;
	char provider_name[M79_PROVIDER_NAME_MAX];
	uint32_t device_mask;
	uint32_t fabric_mask;
	uint32_t provider_kind;
	uint32_t address_space_mode;
	uint32_t flags;
	uint32_t reserved;
	uint64_t provider_device_id;
};

struct m79_report {
	uint32_t provider_state;
	uint32_t active_device_mask;
	uint32_t unsupported_device_mask;
	uint32_t active_fabric;
	uint32_t unsupported_fabric;
	uint32_t resource_measured_mask;
	uint32_t resource_unavailable_mask;
	uint32_t resource_unsupported_mask;
	uint32_t power_applied_features;
	uint32_t power_unsupported_features;
	uint32_t tensor_state;
	uint32_t telemetry_state;
	uint64_t context_id;
	uint64_t context_capability;
	uint64_t region_id;
	uint64_t region_capability;
	uint64_t transport_id;
	uint64_t transport_capability;
	uint64_t telemetry_id;
	uint64_t telemetry_capability;
	uint64_t power_policy_id;
	uint64_t power_capability;
	uint64_t provider_sequence;
};

struct m79_service {
	int kernel_fd;
	int backing_fd;
	struct m79_report report;
	struct agi_lc_memory_region region;
	struct agi_lc_compute_context context;
	struct agi_lc_tensor_transport transport;
	struct agi_lc_graph_telemetry telemetry;
	struct agi_lc_power_policy power;
	struct agi_lc_resource_snapshot snapshot;
};

int m79_open(struct m79_service *service);
void m79_close(struct m79_service *service);
int m79_validate_provider_evidence(const struct m79_provider_evidence *evidence);
int m79_discover_provider(struct m79_provider_evidence *evidence);
int m79_run(struct m79_service *service,
	    const struct m79_provider_evidence *evidence);
int m79_test_metadata_fuzz(const struct m79_provider_evidence *evidence);
int m79_test_stale_capabilities(struct m79_service *service);

#endif
