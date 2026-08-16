#include "../../faisal-concurrency/faisal_concurrency_service.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
	struct m81_report report;
	memset(&report, 0, sizeof(report));
	if (m81_run(&report) != 0) {
		fprintf(stderr, "M81_FAIL:workers=%u passes=%u failures=%u sent=%u received=%u\n",
			report.workers, report.worker_passes, report.failures,
			report.live_messages_sent, report.live_messages_received);
		return 1;
	}
	if (report.workers != M81_WORKERS ||
	    report.worker_passes != M81_WORKERS ||
	    report.failures != 0 ||
	    report.malformed_rejections != M81_WORKERS * M81_MALFORMED_CASES ||
	    report.capability_denials != M81_WORKERS * 2U ||
	    report.cancellation_passes != M81_WORKERS * (M81_CANCEL_MESSAGES / 2U) ||
	    report.live_messages_sent != M81_WORKERS * M81_LIVE_MESSAGES ||
	    report.live_messages_received != report.live_messages_sent ||
    report.randomized_inputs != M81_WORKERS * (1U + M81_CANCEL_MESSAGES + M81_LIVE_MESSAGES))
		return 1;
	printf("M81_WORKERS_OK workers=%u passes=%u\n",
	       report.workers, report.worker_passes);
	printf("M81_MALFORMED_UAPI_REJECT_OK cases=%u\n",
	       report.malformed_rejections);
	printf("M81_CAPABILITY_ISOLATION_OK denials=%u\n",
	       report.capability_denials);
	printf("M81_CANCELLATION_OK passes=%u\n",
	       report.cancellation_passes);
	printf("M81_IPC_ROUNDTRIP_OK sent=%u received=%u\n",
	       report.live_messages_sent, report.live_messages_received);
	printf("M81_QUEUE_PRESSURE_OK events=%u\n",
	       report.queue_pressure_events);
	printf("M81_RANDOMIZED_INPUTS_OK cases=%u\n",
	       report.randomized_inputs);
	printf("M81_SELFTEST_EXIT=0\n");
	return 0;
}
