#define _GNU_SOURCE
#include "../../faisal-stress/faisal_stress_service.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
	struct m80_report report;
	memset(&report, 0, sizeof(report));
	if (m80_run("/tmp/faisal-m80", &report) != 0) {
		fprintf(stderr, "M80_FAIL:aggregate\n");
		return 1;
	}
	if (report.composition_runs != M80_COMPOSITION_RUNS ||
	    report.malformed_rejections != M80_MALFORMED_CASES ||
	    report.cancellation_passes != M80_CANCEL_CASES ||
	    report.resource_samples != M80_RESOURCE_SAMPLES ||
	    report.rollback_passes != 2 || report.failures != 0)
		return 1;
	printf("M80_MALFORMED_UAPI_REJECT_OK cases=%u\n",
	       report.malformed_rejections);
	printf("M80_RESOURCE_PRESSURE_OK samples=%u\n", report.resource_samples);
	printf("M80_COMPOSITION_OK runs=%u\n", report.composition_runs);
	printf("M80_CANCELLATION_OK passes=%u\n", report.cancellation_passes);
	printf("M80_ROLLBACK_FAULT_INJECTION_OK passes=%u\n", report.rollback_passes);
	printf("M80_AUDIT_RETENTION_OK records=%u\n", report.audit_records);
	printf("M80_PROVIDER_UNSUPPORTED_PROPAGATED=%u\n", report.provider_unsupported);
	printf("M80_SELFTEST_EXIT=0\n");
	return 0;
}
