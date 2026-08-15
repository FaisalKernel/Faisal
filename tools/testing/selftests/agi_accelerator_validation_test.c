#define _GNU_SOURCE
#include "../../faisal-accelerator/faisal_accelerator_validation.h"

#include <stdio.h>

static int fail(const char *what)
{
	perror(what);
	return 1;
}

int main(void)
{
	struct m79_provider_evidence evidence;
	struct m79_service service;
	int rc;
	if (m79_discover_provider(&evidence) != 0 ||
	    m79_validate_provider_evidence(&evidence) != 0)
		return fail("provider discovery");
	if (evidence.provider_state == M79_PROVIDER_UNSUPPORTED)
		printf("M79_PROVIDER_UNSUPPORTED_OK\n");
	else
		printf("M79_PROVIDER_DISCOVERED state=%u name=%s\n",
		       evidence.provider_state, evidence.provider_name);
	if (m79_test_metadata_fuzz(&evidence) != 0)
		return fail("metadata fuzz");
	printf("M79_PROVIDER_METADATA_FUZZ_OK iterations=64\n");
	if (m79_open(&service) != 0)
		return fail("open");
	rc = m79_run(&service, &evidence);
	if (rc != 0)
		return fail("validation run");
	if (service.report.provider_state != evidence.provider_state ||
	    !service.report.context_id || !service.report.context_capability ||
	    !service.report.region_id || !service.report.region_capability ||
	    !service.report.transport_id || !service.report.transport_capability ||
	    !service.report.telemetry_id ||
	    service.report.telemetry_state != AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE ||
	    !service.report.power_policy_id || !service.report.power_capability ||
	    !service.report.resource_measured_mask)
		return fail("report completeness");
	printf("M79_CONTEXT_FABRIC_OK active_devices=0x%x unsupported_devices=0x%x active_fabric=0x%x unsupported_fabric=0x%x\n",
	       service.report.active_device_mask,
	       service.report.unsupported_device_mask,
	       service.report.active_fabric,
	       service.report.unsupported_fabric);
	printf("M79_TENSOR_TRANSPORT_OK id=%llu\n",
	       (unsigned long long)service.report.transport_id);
	printf("M79_GRAPH_TELEMETRY_OK id=%llu state=%u\n",
	       (unsigned long long)service.report.telemetry_id,
	       service.report.telemetry_state);
	printf("M79_RESOURCE_MASKS_OK measured=0x%x unavailable=0x%x unsupported=0x%x\n",
	       service.report.resource_measured_mask,
	       service.report.resource_unavailable_mask,
	       service.report.resource_unsupported_mask);
	printf("M79_POWER_POLICY_INTENT_OK applied=0x%llx unsupported=0x%llx status=%d\n",
	       (unsigned long long)service.power.applied_features,
	       (unsigned long long)service.power.unsupported_features,
	       service.power.status);
	if (m79_test_stale_capabilities(&service) != 0)
		return fail("stale capability denial");
	printf("M79_STALE_CAPABILITY_REJECT_OK\n");
	if (evidence.provider_state == M79_PROVIDER_UNSUPPORTED &&
	    service.report.unsupported_device_mask == 0)
		return fail("unsupported device state");
	if (evidence.provider_state == M79_PROVIDER_UNSUPPORTED)
		printf("M79_NO_HARDWARE_CLAIM_OK\n");
	m79_close(&service);
	printf("M79_SELFTEST_EXIT=0\n");
	return 0;
}
