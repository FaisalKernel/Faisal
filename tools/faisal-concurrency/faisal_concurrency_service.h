#ifndef FAISAL_CONCURRENCY_SERVICE_H
#define FAISAL_CONCURRENCY_SERVICE_H

#include <stdint.h>

#define M81_WORKERS 8U
#define M81_MALFORMED_CASES 64U
#define M81_CANCEL_MESSAGES 12U
#define M81_LIVE_MESSAGES 96U
#define M81_QUEUE_MAX 32U

struct m81_report {
	uint32_t workers;
	uint32_t worker_passes;
	uint32_t malformed_rejections;
	uint32_t capability_denials;
	uint32_t cancellation_passes;
	uint32_t live_messages_sent;
	uint32_t live_messages_received;
	uint32_t queue_pressure_events;
	uint32_t randomized_inputs;
	uint32_t failures;
};

int m81_run(struct m81_report *report);

#endif
