#include "../../faisal-attestation/faisal_runtime_attestation.h"

#include <stdio.h>
#include <string.h>

static int nonzero_digest(const uint8_t digest[FRA_DIGEST_SIZE])
{
	unsigned int i;
	for (i = 0; i < FRA_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FRA_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

int main(void)
{
	struct fra_service service;
	uint8_t first_digest[FRA_DIGEST_SIZE];

	memset(&service, 0, sizeof(service));
	service.kernel_fd = -1;
	if (fra_open(&service) != FRA_OK)
		return fail("open", -1);
	if (service.identity.role != AGI_LC_LIGHT_AGENT_ROLE_VERIFIER ||
	    service.identity.workload != AGI_LC_WORKLOAD_VERIFICATION ||
	    !service.agent_id || !service.capability)
		return fail("least privilege identity", -1);
	printf("FRA_VERIFIER_IDENTITY_OK agent=%llu capability=%llu\n",
	       (unsigned long long)service.agent_id,
	       (unsigned long long)service.capability);
	if (fra_run(&service) != FRA_OK)
		return fail("run", -1);
	if ((service.attestation.valid_mask & FRA_SAMPLE_REQUIRED_MASK) !=
	    FRA_SAMPLE_REQUIRED_MASK || !service.attestation.sampled_at_ns ||
	    !service.attestation.sample_sequence ||
	    !nonzero_digest(service.attestation.digest))
		return fail("attestation completeness", -1);
	if (service.attestation.state != FRA_STATE_HEALTHY &&
	    service.attestation.state != FRA_STATE_DEGRADED)
		return fail("health state", (int)service.attestation.state);
	memcpy(first_digest, service.attestation.digest, sizeof(first_digest));
	printf("FRA_ATTESTATION_OK valid=0x%x health=0x%x state=%u generation=%llu\n",
	       service.attestation.valid_mask, service.attestation.health_mask,
	       service.attestation.state,
	       (unsigned long long)service.attestation.sample_sequence);
	printf("FRA_RESOURCE_OK rss=%llu cpu=%llu network_denied=%llu\n",
	       (unsigned long long)service.attestation.resource.memory_rss_bytes,
	       (unsigned long long)service.attestation.resource.cpu_time_ns,
	       (unsigned long long)service.attestation.resource.network_denied);
	printf("FRA_SELF_STATE_OK runnable=%llu blocked=%llu failed=%llu cancelled=%llu\n",
	       (unsigned long long)service.attestation.self_state.runnable_count,
	       (unsigned long long)service.attestation.self_state.blocked_count,
	       (unsigned long long)service.attestation.self_state.failed_count,
	       (unsigned long long)service.attestation.self_state.cancelled_count);
	if (fra_sample(&service) != FRA_OK || fra_compute_digest(&service) != FRA_OK ||
	    !nonzero_digest(service.attestation.digest))
		return fail("resample", -1);
	printf("FRA_RESAMPLE_OK generation=%llu\n",
	       (unsigned long long)service.attestation.sample_sequence);
	if (!memcmp(first_digest, service.attestation.digest, sizeof(first_digest)))
		printf("FRA_DIGEST_STABLE_OK\n");
	else
		printf("FRA_DIGEST_CHANGED_ON_RESAMPLE_OK\n");
	fra_close(&service);
	printf("FRA_SELFTEST_EXIT=0\n");
	return 0;
}
