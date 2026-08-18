#include "../../faisal-hardware/faisal_hardware.h"

#include <stdio.h>
#include <string.h>

#define ITERATIONS 10000U

static struct fhd_path base_path(void)
{
	struct fhd_path path;

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
	return path;
}

int main(void)
{
	struct fhd_path original = base_path();
	unsigned int rejected = 0U;
	unsigned int i;

	if (fhd_compute_path_digest(&original, original.path_digest) != FHD_STATUS_OK)
		return 1;
	for (i = 0U; i < ITERATIONS; ++i) {
		struct fhd_path mutation = original;
		struct fhd_service service;
		int result;

		switch (i % 8U) {
		case 0U:
			mutation.path_id = 0U;
			break;
		case 1U:
			mutation.source_id = mutation.destination_id;
			break;
		case 2U:
			mutation.generation = 0U;
			break;
		case 3U:
			mutation.transport = 0U;
			break;
		case 4U:
			mutation.bandwidth_mb_s++;
			break;
		case 5U:
			mutation.latency_ns = 0U;
			break;
		case 6U:
			mutation.path_digest[i % FHD_DIGEST_SIZE] ^= (uint8_t)(i + 1U);
			break;
		default:
			mutation.abi_version = FHD_ABI_VERSION + 1U;
			break;
		}
		if (fhd_init(&service, 1U) != FHD_STATUS_OK)
			return 1;
		result = fhd_add_path(&service, &mutation);
		fhd_close(&service);
		if (result != FHD_ERR_ARGUMENT)
			return 1;
		rejected++;
	}
	printf("M247_HARDWARE_FUZZ_EXIT=0 iterations=%u rejected=%u accepted=%u scope=synthetic_path_metadata_not_physical_hardware\n",
	       ITERATIONS, rejected, ITERATIONS - rejected);
	return rejected == ITERATIONS ? 0 : 1;
}
