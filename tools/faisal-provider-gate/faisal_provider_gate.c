#include "faisal_provider_gate.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int exists(const char *path)
{
	struct stat st;

	return path && stat(path, &st) == 0;
}

const char *m91_provider_name(uint32_t provider)
{
	switch (provider) {
	case M91_PROVIDER_TPM2:
		return "tpm2";
	case M91_PROVIDER_TEE:
		return "tee";
	case M91_PROVIDER_HSM:
		return "hsm";
	default:
		return "none";
	}
}

int m91_probe_provider(struct m91_provider_result *result)
{
	if (!result)
		return M91_ERR_ARGUMENT;
	memset(result, 0, sizeof(*result));
	result->status = M91_PROVIDER_UNSUPPORTED;
	if (exists("/dev/tpmrm0") || exists("/dev/tpm0")) {
		result->provider = M91_PROVIDER_TPM2;
		result->device_present = 1;
		result->status = M91_PROVIDER_UNVERIFIED;
		snprintf(result->reason, sizeof(result->reason),
			 "tpm device present but no verified provider evidence");
		return result->status;
	}
	if (exists("/dev/tee0")) {
		result->provider = M91_PROVIDER_TEE;
		result->device_present = 1;
		result->status = M91_PROVIDER_UNVERIFIED;
		snprintf(result->reason, sizeof(result->reason),
			 "tee device present but no identified trusted application");
		return result->status;
	}
	snprintf(result->reason, sizeof(result->reason),
		 "no TPM2, TEE, HSM, or verified provider device exposed");
	return result->status;
}

int m91_validate_provider_evidence(const struct m91_provider_result *result)
{
	if (!result)
		return M91_ERR_ARGUMENT;
	if (result->status != M91_PROVIDER_SUPPORTED)
		return M91_PROVIDER_UNSUPPORTED;
	if (!result->provider || !result->device_present ||
	    !result->public_key_provisioned || !result->attestation_verified ||
	    !result->rotation_verified || !result->revocation_verified)
		return M91_PROVIDER_UNSUPPORTED;
	return M91_PROVIDER_SUPPORTED;
}
