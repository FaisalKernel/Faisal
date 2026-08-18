#ifndef FAISAL_HARDWARE_H
#define FAISAL_HARDWARE_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FHD_ABI_VERSION 1U
#define FHD_DIGEST_SIZE 32U
#define FHD_MAX_DEVICES 128U
#define FHD_MAX_PATHS 256U
#define FHD_MAX_NAME 64U
#define FHD_MAX_REASON 192U

#define FHD_CAP_SCALAR (1ULL << 0)
#define FHD_CAP_SIMD (1ULL << 1)
#define FHD_CAP_VECTOR (1ULL << 2)
#define FHD_CAP_TENSOR (1ULL << 3)
#define FHD_CAP_PREEMPT (1ULL << 4)
#define FHD_CAP_PARTITION (1ULL << 5)
#define FHD_CAP_DMA (1ULL << 6)
#define FHD_CAP_PEER_DMA (1ULL << 7)
#define FHD_CAP_RDMA (1ULL << 8)
#define FHD_CAP_CXL (1ULL << 9)
#define FHD_CAP_IOMMU (1ULL << 10)
#define FHD_CAP_CONFIDENTIAL (1ULL << 11)
#define FHD_CAP_HOTPLUG (1ULL << 12)
#define FHD_CAP_POWER_TELEMETRY (1ULL << 13)
#define FHD_CAP_THERMAL_TELEMETRY (1ULL << 14)
#define FHD_CAP_ASYNC_IO (1ULL << 15)
#define FHD_CAP_DIRECT_USERSpace (1ULL << 16)

#define FHD_ISOLATION_NONE 0U
#define FHD_ISOLATION_PROCESS 1U
#define FHD_ISOLATION_IOMMU_GROUP 2U
#define FHD_ISOLATION_CONFIDENTIAL 3U

#define FHD_STATE_HEALTHY 1U
#define FHD_STATE_DEGRADED 2U
#define FHD_STATE_OFFLINE 3U
#define FHD_STATE_QUARANTINED 4U

#define FHD_CLASS_CPU 1U
#define FHD_CLASS_GPU 2U
#define FHD_CLASS_NPU 3U
#define FHD_CLASS_TPU 4U
#define FHD_CLASS_FPGA 5U
#define FHD_CLASS_MEMORY 6U
#define FHD_CLASS_STORAGE 7U
#define FHD_CLASS_NETWORK 8U
#define FHD_CLASS_VIRTUAL 9U

#define FHD_TRANSPORT_SOFTWARE 1U
#define FHD_TRANSPORT_PCIE 2U
#define FHD_TRANSPORT_CXL 3U
#define FHD_TRANSPORT_NVLINK 4U
#define FHD_TRANSPORT_XGMI 5U
#define FHD_TRANSPORT_RDMA 6U
#define FHD_TRANSPORT_DMA_BUF 7U
#define FHD_TRANSPORT_IO_URING 8U
#define FHD_TRANSPORT_VFIO 9U
#define FHD_TRANSPORT_IOMMUFD 10U

#define FHD_REQUEST_ALLOW_FALLBACK (1U << 0)
#define FHD_REQUEST_REQUIRE_ATTESTATION (1U << 1)
#define FHD_REQUEST_REQUIRE_ISOLATION (1U << 2)
#define FHD_REQUEST_REQUIRE_DIRECT (1U << 3)
#define FHD_REQUEST_PREFER_LOW_LATENCY (1U << 4)
#define FHD_REQUEST_PREFER_LOW_POWER (1U << 5)
#define FHD_REQUEST_PREFER_BANDWIDTH (1U << 6)

#define FHD_VIOLATION_ABI (1U << 0)
#define FHD_VIOLATION_CLASS (1U << 1)
#define FHD_VIOLATION_CAPABILITY (1U << 2)
#define FHD_VIOLATION_MEMORY (1U << 3)
#define FHD_VIOLATION_BANDWIDTH (1U << 4)
#define FHD_VIOLATION_LATENCY (1U << 5)
#define FHD_VIOLATION_ISOLATION (1U << 6)
#define FHD_VIOLATION_ATTESTATION (1U << 7)
#define FHD_VIOLATION_HEALTH (1U << 8)
#define FHD_VIOLATION_POWER (1U << 9)
#define FHD_VIOLATION_THERMAL (1U << 10)
#define FHD_VIOLATION_GENERATION (1U << 11)
#define FHD_VIOLATION_PARTITION (1U << 12)
#define FHD_VIOLATION_PATH (1U << 13)
#define FHD_VIOLATION_NO_FALLBACK (1U << 14)

#define FHD_ACTION_REJECT 0U
#define FHD_ACTION_SELECT 1U
#define FHD_ACTION_RESERVE 2U
#define FHD_ACTION_FALLBACK 3U

#define FHD_STATUS_OK 0
#define FHD_ERR_ARGUMENT -1
#define FHD_ERR_FULL -2
#define FHD_ERR_NOT_FOUND -3
#define FHD_ERR_CONFLICT -4
#define FHD_ERR_UNAVAILABLE -5
#define FHD_ERR_POLICY -6
#define FHD_ERR_GENERATION -7
#define FHD_ERR_TAMPER -8
#define FHD_ERR_NO_PATH -9
#define FHD_ERR_PARTITION -10

struct fhd_device {
	uint32_t abi_version;
	uint32_t class_id;
	uint32_t state;
	uint32_t isolation_level;
	uint64_t device_id;
	uint64_t generation;
	uint64_t numa_node;
	uint64_t pci_domain;
	uint64_t total_memory_bytes;
	uint64_t available_memory_bytes;
	uint64_t total_compute_units;
	uint64_t available_compute_units;
	uint64_t memory_bandwidth_mb_s;
	uint64_t power_budget_uw;
	uint64_t power_now_uw;
	uint32_t thermal_permille;
	uint32_t driver_verified;
	uint32_t attestation_verified;
	uint32_t reserved;
	uint64_t capabilities;
	uint8_t identity_digest[FHD_DIGEST_SIZE];
	char name[FHD_MAX_NAME];
};

struct fhd_path {
	uint32_t abi_version;
	uint32_t transport;
	uint32_t state;
	uint32_t isolation_level;
	uint64_t path_id;
	uint64_t source_id;
	uint64_t destination_id;
	uint64_t generation;
	uint64_t bandwidth_mb_s;
	uint64_t latency_ns;
	uint64_t capabilities;
	uint32_t attestation_verified;
	uint32_t reserved;
	uint8_t path_digest[FHD_DIGEST_SIZE];
};

struct fhd_request {
	uint32_t abi_version;
	uint32_t class_id;
	uint32_t flags;
	uint32_t required_isolation;
	uint64_t generation;
	uint64_t required_capabilities;
	uint64_t memory_bytes;
	uint64_t compute_units;
	uint64_t min_bandwidth_mb_s;
	uint64_t max_latency_ns;
	uint64_t max_power_uw;
	uint32_t max_thermal_permille;
	uint32_t preferred_numa_node;
	uint64_t source_device_id;
};

struct fhd_decision {
	uint64_t decision_id;
	uint64_t generation;
	uint64_t device_id;
	uint64_t path_id;
	uint64_t estimated_bandwidth_mb_s;
	uint64_t estimated_latency_ns;
	uint64_t reserved_memory_bytes;
	uint64_t reserved_compute_units;
	uint64_t selected_capabilities;
	uint32_t action;
	uint32_t fallback_used;
	uint32_t violation_mask;
	uint32_t reserved;
	uint8_t request_digest[FHD_DIGEST_SIZE];
	uint8_t decision_digest[FHD_DIGEST_SIZE];
	char reason[FHD_MAX_REASON];
};

struct fhd_partition {
	uint64_t device_id;
	uint64_t generation;
	uint64_t allocation_id;
	uint64_t memory_bytes;
	uint64_t compute_units;
	uint64_t capabilities;
	uint8_t grant_digest[FHD_DIGEST_SIZE];
};

#define FHD_DISCOVERY_SSE2 (1U << 0)
#define FHD_DISCOVERY_AVX2 (1U << 1)
#define FHD_DISCOVERY_AVX512 (1U << 2)
#define FHD_DISCOVERY_NEON (1U << 3)
#define FHD_DISCOVERY_SVE (1U << 4)
#define FHD_DISCOVERY_SME (1U << 5)

struct fhd_discovery_report {
	uint32_t abi_version;
	uint32_t online_cpus;
	uint32_t vector_features;
	uint32_t drm_devices;
	uint32_t rdma_devices;
	uint32_t nvme_devices;
	uint32_t cxl_devices;
	uint32_t power_telemetry;
	uint32_t thermal_telemetry;
	uint32_t attestation_observed;
	uint64_t memory_total_bytes;
	uint64_t memory_available_bytes;
	uint8_t host_digest[FHD_DIGEST_SIZE];
};

struct fhd_service {
	pthread_mutex_t lock;
	struct fhd_device devices[FHD_MAX_DEVICES];
	struct fhd_path paths[FHD_MAX_PATHS];
	size_t device_count;
	size_t path_count;
	uint64_t next_decision_id;
	uint64_t next_allocation_id;
	uint64_t generation;
};

int fhd_init(struct fhd_service *service, uint64_t generation);
void fhd_close(struct fhd_service *service);
int fhd_add_device(struct fhd_service *service, const struct fhd_device *device);
int fhd_update_device(struct fhd_service *service, const struct fhd_device *device);
int fhd_add_path(struct fhd_service *service, const struct fhd_path *path);
int fhd_fail_device(struct fhd_service *service, uint64_t device_id,
		    uint64_t generation, uint32_t state);
int fhd_query_device(const struct fhd_service *service, uint64_t device_id,
		     struct fhd_device *out);
int fhd_query_path(const struct fhd_service *service, uint64_t path_id,
		  struct fhd_path *out);
int fhd_compute_path_digest(const struct fhd_path *path,
			    uint8_t digest[FHD_DIGEST_SIZE]);
int fhd_select(struct fhd_service *service, const struct fhd_request *request,
	      struct fhd_decision *out);
int fhd_reserve(struct fhd_service *service, const struct fhd_request *request,
		struct fhd_decision *decision, struct fhd_partition *out);
int fhd_release(struct fhd_service *service, const struct fhd_partition *partition);
int fhd_verify_decision(const struct fhd_decision *decision,
			const struct fhd_request *request);
int fhd_discover_host(struct fhd_service *service, const char *proc_root,
			      const char *sysfs_root,
			      struct fhd_discovery_report *out);
int fhd_compute_discovery_digest(const struct fhd_discovery_report *report,
				 uint8_t digest[FHD_DIGEST_SIZE]);
int fhd_test_invalid_device_rejection(struct fhd_service *service);
int fhd_test_path_tamper_rejection(struct fhd_service *service);

#endif
