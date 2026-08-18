#include "../../faisal-hardware/faisal_hardware.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
	struct fhd_service service;
	struct fhd_discovery_report report;
	uint8_t digest[FHD_DIGEST_SIZE];
	struct fhd_device cpu;

	if (fhd_init(&service, 1U) != FHD_STATUS_OK ||
	    fhd_discover_host(&service, "/proc", "/sys", &report) != FHD_STATUS_OK ||
	    report.abi_version != FHD_ABI_VERSION || report.online_cpus == 0U ||
	    report.memory_total_bytes == 0U || report.memory_available_bytes == 0U ||
	    fhd_compute_discovery_digest(&report, digest) != FHD_STATUS_OK ||
	    memcmp(digest, report.host_digest, FHD_DIGEST_SIZE) != 0 ||
	    fhd_query_device(&service, 1U, &cpu) != FHD_STATUS_OK ||
	    cpu.class_id != FHD_CLASS_CPU || cpu.total_compute_units != report.online_cpus ||
	    !cpu.driver_verified || cpu.attestation_verified != 0U)
		return 1;
	fhd_close(&service);
	printf("M247_HARDWARE_DISCOVERY_EXIT=0 online_cpus=%u vector_features=%u memory_total_bytes=%llu memory_available_bytes=%llu drm=%u rdma=%u nvme=%u cxl=%u power=%u thermal=%u attestation_observed=%u scope=host_observation_not_physical_qualification\n",
	       report.online_cpus, report.vector_features,
	       (unsigned long long)report.memory_total_bytes,
	       (unsigned long long)report.memory_available_bytes,
	       report.drm_devices, report.rdma_devices, report.nvme_devices,
	       report.cxl_devices, report.power_telemetry, report.thermal_telemetry,
	       report.attestation_observed);
	return 0;
}
