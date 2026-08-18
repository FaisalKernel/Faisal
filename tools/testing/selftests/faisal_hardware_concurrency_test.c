#include "../../faisal-hardware/faisal_hardware.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define READERS 4U
#define READ_ROUNDS 256U
#define WRITE_ROUNDS 256U

struct context {
	struct fhd_service *service;
	struct fhd_request request;
	struct fhd_device device;
	atomic_int failures;
};

static void digest(uint8_t output[FHD_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FHD_DIGEST_SIZE);
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

static void *reader(void *opaque)
{
	struct context *context = opaque;
	unsigned int i;

	for (i = 0U; i < READ_ROUNDS; ++i) {
		struct fhd_decision decision;
		struct fhd_device device;
		if (fhd_select(context->service, &context->request, &decision) != FHD_STATUS_OK ||
		    decision.device_id != 2U ||
		    fhd_query_device(context->service, 2U, &device) != FHD_STATUS_OK ||
		    device.state != FHD_STATE_HEALTHY)
			atomic_fetch_add(&context->failures, 1);
	}
	return NULL;
}

static void *writer(void *opaque)
{
	struct context *context = opaque;
	unsigned int i;

	for (i = 0U; i < WRITE_ROUNDS; ++i) {
		struct fhd_device update = context->device;
		update.thermal_permille = 250U + (i % 100U);
		update.power_now_uw = 100000U + (uint64_t)(i % 100U) * 1000U;
		if (fhd_update_device(context->service, &update) != FHD_STATUS_OK)
			atomic_fetch_add(&context->failures, 1);
	}
	return NULL;
}

int main(void)
{
	struct fhd_service service;
	struct fhd_device cpu;
	struct fhd_device gpu;
	struct fhd_path path;
	struct context context;
	pthread_t readers[READERS];
	pthread_t writer_thread;
	unsigned int i;
	int failures;

	memset(&cpu, 0, sizeof(cpu));
	cpu.abi_version = FHD_ABI_VERSION;
	cpu.class_id = FHD_CLASS_CPU;
	cpu.state = FHD_STATE_HEALTHY;
	cpu.isolation_level = FHD_ISOLATION_PROCESS;
	cpu.device_id = 1U;
	cpu.generation = 1U;
	cpu.total_memory_bytes = 8ULL << 30;
	cpu.available_memory_bytes = cpu.total_memory_bytes;
	cpu.total_compute_units = 64U;
	cpu.available_compute_units = 64U;
	cpu.memory_bandwidth_mb_s = 100000U;
	cpu.power_budget_uw = 300000U;
	cpu.power_now_uw = 80000U;
	cpu.capabilities = FHD_CAP_SCALAR | FHD_CAP_VECTOR | FHD_CAP_DMA;
	cpu.driver_verified = 1U;
	digest(cpu.identity_digest, 1U);
	snprintf(cpu.name, sizeof(cpu.name), "concurrency-cpu");
	memset(&gpu, 0, sizeof(gpu));
	gpu.abi_version = FHD_ABI_VERSION;
	gpu.class_id = FHD_CLASS_GPU;
	gpu.state = FHD_STATE_HEALTHY;
	gpu.isolation_level = FHD_ISOLATION_IOMMU_GROUP;
	gpu.device_id = 2U;
	gpu.generation = 1U;
	gpu.total_memory_bytes = 8ULL << 30;
	gpu.available_memory_bytes = gpu.total_memory_bytes;
	gpu.total_compute_units = 128U;
	gpu.available_compute_units = 128U;
	gpu.memory_bandwidth_mb_s = 900000U;
	gpu.power_budget_uw = 500000U;
	gpu.power_now_uw = 100000U;
	gpu.thermal_permille = 250U;
	gpu.driver_verified = 1U;
	gpu.attestation_verified = 1U;
	gpu.capabilities = FHD_CAP_VECTOR | FHD_CAP_TENSOR | FHD_CAP_DMA | FHD_CAP_IOMMU;
	digest(gpu.identity_digest, 2U);
	snprintf(gpu.name, sizeof(gpu.name), "concurrency-gpu");
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
	context.service = &service;
	context.request = request();
	context.device = gpu;
	atomic_init(&context.failures, 0);
	if (pthread_create(&writer_thread, NULL, writer, &context) != 0)
		return 1;
	for (i = 0U; i < READERS; ++i)
		if (pthread_create(&readers[i], NULL, reader, &context) != 0)
			return 1;
	if (pthread_join(writer_thread, NULL) != 0)
		return 1;
	for (i = 0U; i < READERS; ++i)
		if (pthread_join(readers[i], NULL) != 0)
			return 1;
	failures = atomic_load(&context.failures);
	fhd_close(&service);
	printf("M247_HARDWARE_CONCURRENCY_EXIT=%d readers=%u read_rounds=%u writer_rounds=%u failures=%d\n",
	       failures == 0 ? 0 : 1, READERS, READ_ROUNDS, WRITE_ROUNDS, failures);
	return failures == 0 ? 0 : 1;
}
