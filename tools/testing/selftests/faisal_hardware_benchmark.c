#include "../../faisal-hardware/faisal_hardware.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 2048U

static uint64_t clock_ns(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
		return 0U;
	return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void digest(uint8_t output[FHD_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FHD_DIGEST_SIZE);
}

static struct fhd_device device(uint64_t id, uint32_t class_id, uint64_t capabilities,
				uint64_t bandwidth)
{
	struct fhd_device value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FHD_ABI_VERSION;
	value.class_id = class_id;
	value.state = FHD_STATE_HEALTHY;
	value.isolation_level = FHD_ISOLATION_IOMMU_GROUP;
	value.device_id = id;
	value.generation = 1U;
	value.total_memory_bytes = 8ULL << 30;
	value.available_memory_bytes = value.total_memory_bytes;
	value.total_compute_units = 128U;
	value.available_compute_units = value.total_compute_units;
	value.memory_bandwidth_mb_s = bandwidth;
	value.power_budget_uw = 500000U;
	value.power_now_uw = 100000U;
	value.thermal_permille = 250U;
	value.driver_verified = 1U;
	value.attestation_verified = 1U;
	value.capabilities = capabilities;
	digest(value.identity_digest, (uint8_t)id);
	snprintf(value.name, sizeof(value.name), "bench-%llu", (unsigned long long)id);
	return value;
}

static struct fhd_request request(void)
{
	struct fhd_request value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FHD_ABI_VERSION;
	value.flags = FHD_REQUEST_REQUIRE_ISOLATION | FHD_REQUEST_REQUIRE_ATTESTATION |
		FHD_REQUEST_PREFER_BANDWIDTH;
	value.required_isolation = FHD_ISOLATION_IOMMU_GROUP;
	value.class_id = FHD_CLASS_GPU;
	value.generation = 1U;
	value.required_capabilities = FHD_CAP_TENSOR | FHD_CAP_DMA;
	value.memory_bytes = 1U << 20;
	value.compute_units = 8U;
	value.min_bandwidth_mb_s = 100000U;
	value.max_latency_ns = 2000U;
	value.max_power_uw = 450000U;
	value.max_thermal_permille = 800U;
	value.source_device_id = 1U;
	return value;
}

int main(void)
{
	struct fhd_service service;
	struct fhd_device cpu = device(1U, FHD_CLASS_CPU,
		FHD_CAP_SCALAR | FHD_CAP_VECTOR | FHD_CAP_DMA, 100000U);
	struct fhd_device gpu = device(2U, FHD_CLASS_GPU,
		FHD_CAP_VECTOR | FHD_CAP_TENSOR | FHD_CAP_DMA | FHD_CAP_IOMMU, 900000U);
	struct fhd_path path;
	struct fhd_request request_value = request();
	struct fhd_decision decision;
	uint64_t selection_start;
	uint64_t selection_end;
	uint64_t static_start;
	uint64_t static_end;
	uint64_t checksum = 0U;
	unsigned int i;

	memset(&path, 0, sizeof(path));
	path.abi_version = FHD_ABI_VERSION;
	path.transport = FHD_TRANSPORT_PCIE;
	path.state = FHD_STATE_HEALTHY;
	path.isolation_level = FHD_ISOLATION_IOMMU_GROUP;
	path.path_id = 1U;
	path.source_id = 1U;
	path.destination_id = 2U;
	path.generation = 1U;
	path.bandwidth_mb_s = 800000U;
	path.latency_ns = 400U;
	path.capabilities = FHD_CAP_DMA | FHD_CAP_IOMMU;
	path.attestation_verified = 1U;
	if (fhd_compute_path_digest(&path, path.path_digest) != FHD_STATUS_OK ||
	    fhd_init(&service, 1U) != FHD_STATUS_OK ||
	    fhd_add_device(&service, &cpu) != FHD_STATUS_OK ||
	    fhd_add_device(&service, &gpu) != FHD_STATUS_OK ||
	    fhd_add_path(&service, &path) != FHD_STATUS_OK)
		return 1;
	selection_start = clock_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		request_value.memory_bytes = (uint64_t)(i % 16U + 1U) << 20;
		if (fhd_select(&service, &request_value, &decision) != FHD_STATUS_OK)
			return 1;
		checksum ^= decision.device_id ^ decision.path_id;
	}
	selection_end = clock_ns();
	static_start = clock_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		int allowed = gpu.state == FHD_STATE_HEALTHY &&
			gpu.available_memory_bytes >= ((uint64_t)(i % 16U + 1U) << 20) &&
			gpu.available_compute_units >= request_value.compute_units &&
			gpu.memory_bandwidth_mb_s >= request_value.min_bandwidth_mb_s &&
			gpu.attestation_verified && gpu.driver_verified;
		checksum ^= (uint64_t)allowed;
	}
	static_end = clock_ns();
	fhd_close(&service);
	printf("M247_HARDWARE_BENCHMARK_EXIT=0 rounds=%u selection_total_ns=%llu selection_ns_per_request=%.2f static_total_ns=%llu static_ns_per_check=%.2f checksum=%llu scope=capability_path_selection_not_physical_accelerator_throughput\n",
	       ROUNDS, (unsigned long long)(selection_end - selection_start),
	       (double)(selection_end - selection_start) / (double)ROUNDS,
	       (unsigned long long)(static_end - static_start),
	       (double)(static_end - static_start) / (double)ROUNDS,
	       (unsigned long long)checksum);
	return 0;
}
