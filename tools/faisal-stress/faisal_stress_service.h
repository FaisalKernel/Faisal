#ifndef FAISAL_STRESS_SERVICE_H
#define FAISAL_STRESS_SERVICE_H

#include <stdint.h>

#define M80_COMPOSITION_RUNS 3U
#define M80_MALFORMED_CASES 256U
#define M80_CANCEL_CASES 8U
#define M80_RESOURCE_SAMPLES 8U

struct m80_report {
	uint32_t composition_runs;
	uint32_t malformed_rejections;
	uint32_t cancellation_passes;
	uint32_t resource_samples;
	uint32_t rollback_passes;
	uint32_t audit_records;
	uint32_t provider_unsupported;
	uint32_t failures;
	uint64_t last_world_sequence;
	uint64_t last_observability_sequence;
};

int m80_run(const char *journal_prefix, struct m80_report *report);
int m80_test_malformed_uapi(uint32_t *accepted);
int m80_test_resource_pressure(uint32_t *samples);
int m80_test_cancellation(uint32_t *passes);
int m80_test_rollback(const char *journal_path);

#endif
