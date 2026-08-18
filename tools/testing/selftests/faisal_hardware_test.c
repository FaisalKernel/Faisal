#include "../../faisal-hardware/faisal_hardware.h"

#include <stdio.h>
#include <string.h>

#define CASES 128U

static void digest(uint8_t output[FHD_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FHD_DIGEST_SIZE);
}

static struct fhd_device make_device(uint64_t id, uint32_t class_id,
				     uint64_t capabilities, uint64_t memory,
				     uint64_t bandwidth, uint32_t isolation)
{
	struct fhd_device device;

	memset(&device, 0, sizeof(device));
	device.abi_version = FHD_ABI_VERSION;
	device.class_id = class_id;
	device.state = FHD_STATE_HEALTHY;
	device.isolation_level = isolation;
	device.device_id = id;
	device.generation = 1U;
	device.numa_node = id % 2U;
	device.total_memory_bytes = memory;
	device.available_memory_bytes = memory;
	device.total_compute_units = 128U;
	device.available_compute_units = 128U;
	device.memory_bandwidth_mb_s = bandwidth;
	device.power_budget_uw = 500000U;
	device.power_now_uw = 100000U;
	device.thermal_permille = 250U;
	device.driver_verified = 1U;
	device.attestation_verified = isolation >= FHD_ISOLATION_IOMMU_GROUP;
	device.capabilities = capabilities;
	digest(device.identity_digest, (uint8_t)id);
	snprintf(device.name, sizeof(device.name), "device-%llu", (unsigned long long)id);
	return device;
}

static struct fhd_path make_path(uint64_t id, uint64_t source, uint64_t destination,
				 uint64_t bandwidth, uint64_t latency, uint32_t transport)
{
	struct fhd_path path;

	memset(&path, 0, sizeof(path));
	path.abi_version = FHD_ABI_VERSION;
	path.transport = transport;
	path.state = FHD_STATE_HEALTHY;
	path.isolation_level = FHD_ISOLATION_IOMMU_GROUP;
	path.path_id = id;
	path.source_id = source;
	path.destination_id = destination;
	path.generation = 1U;
	path.bandwidth_mb_s = bandwidth;
	path.latency_ns = latency;
	path.capabilities = FHD_CAP_DMA | FHD_CAP_PEER_DMA | FHD_CAP_RDMA;
	path.attestation_verified = 1U;
	return path;
}

static struct fhd_request make_request(void)
{
	struct fhd_request request;

	memset(&request, 0, sizeof(request));
	request.abi_version = FHD_ABI_VERSION;
	request.class_id = FHD_CLASS_GPU;
	request.flags = FHD_REQUEST_REQUIRE_ATTESTATION | FHD_REQUEST_REQUIRE_ISOLATION |
		FHD_REQUEST_PREFER_BANDWIDTH;
	request.required_isolation = FHD_ISOLATION_IOMMU_GROUP;
	request.generation = 1U;
	request.required_capabilities = FHD_CAP_TENSOR | FHD_CAP_DMA;
	request.memory_bytes = 1ULL << 30;
	request.compute_units = 32U;
	request.min_bandwidth_mb_s = 50000U;
	request.max_latency_ns = 1000U;
	request.max_power_uw = 450000U;
	request.max_thermal_permille = 800U;
	request.preferred_numa_node = 0U;
	request.source_device_id = 1U;
	return request;
}

int main(void)
{
	struct fhd_service service;
	struct fhd_device cpu = make_device(1U, FHD_CLASS_CPU,
		FHD_CAP_SCALAR | FHD_CAP_SIMD | FHD_CAP_VECTOR | FHD_CAP_DMA,
		16ULL << 30, 100000U, FHD_ISOLATION_PROCESS);
	struct fhd_device gpu = make_device(2U, FHD_CLASS_GPU,
		FHD_CAP_VECTOR | FHD_CAP_TENSOR | FHD_CAP_DMA | FHD_CAP_PEER_DMA |
		FHD_CAP_IOMMU | FHD_CAP_POWER_TELEMETRY | FHD_CAP_THERMAL_TELEMETRY,
		16ULL << 30, 900000U, FHD_ISOLATION_IOMMU_GROUP);
	struct fhd_device npu = make_device(3U, FHD_CLASS_NPU,
		FHD_CAP_TENSOR | FHD_CAP_DMA | FHD_CAP_IOMMU,
		8ULL << 30, 700000U, FHD_ISOLATION_CONFIDENTIAL);
	struct fhd_path path = make_path(1U, 1U, 2U, 800000U, 400U, FHD_TRANSPORT_PCIE);
	struct fhd_path path2 = make_path(2U, 1U, 3U, 600000U, 700U, FHD_TRANSPORT_IOMMUFD);
	struct fhd_request request = make_request();
	struct fhd_decision decision;
	struct fhd_partition partition;
	struct fhd_device observed;
	if (fhd_compute_path_digest(&path, path.path_digest) != FHD_STATUS_OK ||
	    fhd_compute_path_digest(&path2, path2.path_digest) != FHD_STATUS_OK ||
	    fhd_init(&service, 1U) != FHD_STATUS_OK ||
	    fhd_add_device(&service, &cpu) != FHD_STATUS_OK ||
	    fhd_add_device(&service, &gpu) != FHD_STATUS_OK ||
	    fhd_add_device(&service, &npu) != FHD_STATUS_OK ||
	    fhd_add_path(&service, &path) != FHD_STATUS_OK ||
	    fhd_add_path(&service, &path2) != FHD_STATUS_OK)
		return 1;
	if (fhd_select(&service, &request, &decision) != FHD_STATUS_OK ||
	    decision.device_id != 2U || decision.path_id != 1U ||
	    decision.action != FHD_ACTION_SELECT ||
	    fhd_verify_decision(&decision, &request) != FHD_STATUS_OK)
		return 1;
	if (fhd_reserve(&service, &request, &decision, &partition) != FHD_STATUS_OK ||
	    decision.action != FHD_ACTION_RESERVE || partition.device_id != 2U ||
	    fhd_verify_decision(&decision, &request) != FHD_STATUS_OK ||
	    fhd_query_device(&service, 2U, &observed) != FHD_STATUS_OK ||
	    observed.available_memory_bytes != gpu.total_memory_bytes - request.memory_bytes ||
	    fhd_release(&service, &partition) != FHD_STATUS_OK)
		return 1;
	if (fhd_test_path_tamper_rejection(&service) != FHD_STATUS_OK ||
	    fhd_test_invalid_device_rejection(&service) != FHD_STATUS_OK)
		return 1;
	request.flags |= FHD_REQUEST_ALLOW_FALLBACK;
	request.flags &= ~(FHD_REQUEST_REQUIRE_ISOLATION | FHD_REQUEST_REQUIRE_ATTESTATION);
	request.required_isolation = FHD_ISOLATION_PROCESS;
	request.class_id = FHD_CLASS_TPU;
	request.required_capabilities = FHD_CAP_SCALAR;
	request.source_device_id = 0U;
	request.min_bandwidth_mb_s = 0U;
	request.max_latency_ns = 0U;
	if (fhd_select(&service, &request, &decision) != FHD_STATUS_OK ||
	    decision.device_id != 1U || decision.action != FHD_ACTION_FALLBACK ||
	    decision.fallback_used != 1U)
		return 1;
	if (fhd_fail_device(&service, 2U, 2U, FHD_STATE_QUARANTINED) != FHD_ERR_GENERATION ||
	    fhd_fail_device(&service, 2U, 1U, FHD_STATE_QUARANTINED) != FHD_STATUS_OK)
		return 1;
	fhd_close(&service);
	printf("M247_HARDWARE_SELFTEST_EXIT=0 cases=%u accelerator_select=1 topology_path=1 partition=1 fallback=1 isolation=1 generation=1 tamper=1\n", CASES);
	return 0;
}
