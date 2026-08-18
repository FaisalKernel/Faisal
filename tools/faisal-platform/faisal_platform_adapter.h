#ifndef FAISAL_PLATFORM_ADAPTER_H
#define FAISAL_PLATFORM_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "faisal_platform.h"

#define FPA_ABI_VERSION 1U
#define FPA_MAX_CLAIM_ID 96U
#define FPA_MAX_RUNTIME_REF 96U
#define FPA_MAX_CLASS 64U
#define FPA_MAX_TOPOLOGY 96U
#define FPA_FLAG_DEVICE_SHARING (1U << 0)
#define FPA_FLAG_TOPOLOGY_BOUND (1U << 1)
#define FPA_FLAG_CHECKPOINT_CAPABLE (1U << 2)
#define FPA_FLAG_NETWORK_DIRECT (1U << 3)

enum fpa_status {
	FPA_OK = 0,
	FPA_ERR_ARGUMENT = -1,
	FPA_ERR_BOUNDS = -2,
	FPA_ERR_PROVIDER = -3,
	FPA_ERR_TAMPER = -4,
	FPA_ERR_WORKLOAD = -5
};

struct fpa_provider_claim {
	uint32_t abi_version;
	uint32_t provider_kind;
	uint64_t workload_id;
	uint64_t requested_devices;
	uint64_t requested_memory_bytes;
	uint64_t requested_network_mbps;
	uint64_t requested_storage_bytes;
	uint32_t device_mask;
	uint32_t flags;
	char claim_id[FPA_MAX_CLAIM_ID];
	char runtime_ref[FPA_MAX_RUNTIME_REF];
	char device_class[FPA_MAX_CLASS];
	char topology[FPA_MAX_TOPOLOGY];
	uint8_t claim_digest[FPL_DIGEST_SIZE];
};

int fpa_provider_claim_digest(const struct fpa_provider_claim *claim,
			      uint8_t digest[FPL_DIGEST_SIZE]);
int fpa_validate_provider_claim(const struct fpa_provider_claim *claim);
int fpa_bind_provider_claim(struct fpl_intent *intent,
			    struct fpa_provider_claim *claim);
int fpa_test_untrusted_provider_metadata(const struct fpa_provider_claim *claim);

#endif
