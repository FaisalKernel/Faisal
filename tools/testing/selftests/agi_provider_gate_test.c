// SPDX-License-Identifier: GPL-2.0-only
#include "../../faisal-provider-gate/faisal_provider_gate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M91_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

int main(void)
{
	struct m91_provider_result result;
	struct m91_provider_result metadata_only;
	int rc;

	/* Deliberately demonstrate that environment metadata is not authority. */
	setenv("FAISAL_M91_PROVIDER", "tpm2", 1);
	rc = m91_probe_provider(&result);
	if (rc != M91_PROVIDER_UNSUPPORTED && rc != M91_PROVIDER_UNVERIFIED)
		return fail("probe classification", rc);
	if (m91_validate_provider_evidence(&result) != M91_PROVIDER_UNSUPPORTED)
		return fail("unsupported gate", M91_PROVIDER_UNSUPPORTED);
	printf("M91_PROVIDER_PROBE_OK provider=%s status=%d device_present=%u\n",
	       m91_provider_name(result.provider), result.status,
	       result.device_present);
	printf("M91_ENV_METADATA_NOT_AUTHORITY_OK\n");

	metadata_only = result;
	metadata_only.provider = M91_PROVIDER_TPM2;
	metadata_only.status = M91_PROVIDER_SUPPORTED;
	metadata_only.device_present = 1;
	metadata_only.public_key_provisioned = 1;
	metadata_only.attestation_verified = 0;
	metadata_only.rotation_verified = 0;
	metadata_only.revocation_verified = 0;
	if (m91_validate_provider_evidence(&metadata_only) !=
	    M91_PROVIDER_UNSUPPORTED)
		return fail("incomplete hardware evidence", M91_PROVIDER_SUPPORTED);
	printf("M91_INCOMPLETE_EVIDENCE_DENIAL_OK\n");

	if (result.status == M91_PROVIDER_UNVERIFIED)
		printf("M91_HARDWARE_ATTESTATION_UNSUPPORTED_OK reason=%s\n",
		       result.reason);
	else
		printf("M91_HARDWARE_ATTESTATION_UNSUPPORTED_OK reason=no-provider\n");
	printf("M91_SELFTEST_EXIT=0\n");
	return 0;
}
