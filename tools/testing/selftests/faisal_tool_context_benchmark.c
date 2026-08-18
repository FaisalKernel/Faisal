#include "../../faisal-tool-context/faisal_tool_context.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void register_fixture(struct ftc_registry *registry)
{
	static const char *const names[] = {
		"get_document", "update_record", "click", "search_tools",
		"list_resources", "read_resource", "submit_job", "poll_job"
	};
	static const uint32_t caps[] = { 1U, 2U, 4U, 1U, 1U, 1U, 16U, 16U };
	static const uint32_t trust[] = { 900000U, 900000U, 850000U, 700000U,
		900000U, 900000U, 950000U, 950000U };
	static const uint64_t hints[] = { 400U, 400U, 128U, 1024U,
		256U, 256U, 512U, 512U };
	struct ftc_tool tool;
	size_t i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		assert(ftc_register(registry, "mcp", names[i], FTC_TOOL_FUNCTION,
				    caps[i], trust[i],
				    "{\"type\":\"object\",\"properties\":{\"value\":{\"type\":\"string\"}}}",
				    hints[i], &tool) == FTC_OK);
}

int main(void)
{
	struct ftc_registry registry;
	struct ftc_request request;
	struct ftc_admission admission;
	const uint64_t iterations = 20000U;
	uint64_t progressive_start;
	uint64_t progressive_end;
	uint64_t baseline_start;
	uint64_t baseline_end;
	uint64_t progressive_bytes = 0;
	uint64_t full_bytes = 0;
	uint64_t i;
	uint64_t checksum = 0;

	assert(ftc_init(&registry) == FTC_OK);
	register_fixture(&registry);
	memset(&request, 0, sizeof(request));
	request.tool_generation = registry.generation;
	request.required_capabilities = 1U;
	request.maximum_tools = 3U;
	request.maximum_definition_bytes = 240U;
	request.maximum_result_bytes = 800U;
	request.minimum_trust_level = 800000U;
	request.flags = FTC_FLAG_VERIFIED_INPUT;
	progressive_start = now_ns();
	for (i = 0; i < iterations; i++) {
		request.request_sequence = i + 1U;
		request.now_ns = i + 1U;
		assert(ftc_admit(&registry, &request, &admission) == FTC_OK);
		progressive_bytes += admission.projected_definition_bytes;
		checksum ^= admission.admission_digest[0];
	}
	progressive_end = now_ns();
	baseline_start = now_ns();
	for (i = 0; i < iterations; i++) {
		size_t j;
		uint64_t bytes = 0;

		for (j = 0; j < registry.count; j++)
			bytes += registry.tools[j].definition_bytes;
		full_bytes += bytes;
		checksum ^= (bytes + i) & 0xffU;
	}
	baseline_end = now_ns();
	printf("FTC_TOOL_CONTEXT_BENCHMARK_OK iterations=%" PRIu64
	       " progressive_ns=%" PRIu64 " baseline_scan_ns=%" PRIu64
	       " progressive_ns_per_request=%.2f baseline_ns_per_request=%.2f"
	       " full_definition_bytes=%" PRIu64 " admitted_definition_bytes=%" PRIu64
	       " reduction_permille=%" PRIu64 " checksum=%" PRIu64 "\n",
	       iterations, progressive_end - progressive_start,
	       baseline_end - baseline_start,
	       (double)(progressive_end - progressive_start) / (double)iterations,
	       (double)(baseline_end - baseline_start) / (double)iterations,
	       full_bytes, progressive_bytes,
	       full_bytes ? ((full_bytes - progressive_bytes) * 1000U) / full_bytes : 0U,
	       checksum);
	return 0;
}
