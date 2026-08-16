#ifndef FAISAL_PROVIDER_GATE_H
#define FAISAL_PROVIDER_GATE_H

#include <stdint.h>

#define M91_REASON_SIZE 160

#define M91_PROVIDER_NONE 0U
#define M91_PROVIDER_TPM2 1U
#define M91_PROVIDER_TEE 2U
#define M91_PROVIDER_HSM 3U

#define M91_PROVIDER_SUPPORTED 0
#define M91_PROVIDER_UNSUPPORTED 1
#define M91_PROVIDER_UNVERIFIED 2
#define M91_ERR_ARGUMENT -1

struct m91_provider_result {
	uint32_t provider;
	int status;
	uint32_t device_present;
	uint32_t public_key_provisioned;
	uint32_t attestation_verified;
	uint32_t rotation_verified;
	uint32_t revocation_verified;
	char reason[M91_REASON_SIZE];
};

int m91_probe_provider(struct m91_provider_result *result);
int m91_validate_provider_evidence(const struct m91_provider_result *result);
const char *m91_provider_name(uint32_t provider);

#endif
