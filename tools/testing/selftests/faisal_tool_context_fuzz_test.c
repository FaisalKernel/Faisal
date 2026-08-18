#include "../../faisal-tool-context/faisal_tool_context.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
	struct ftc_registry registry;
	struct ftc_tool tool;
	struct ftc_request request;
	struct ftc_admission admission;
	uint32_t rejected = 0;
	uint32_t accepted = 0;
	uint32_t i;

	assert(ftc_init(&registry) == FTC_OK);
	assert(ftc_register(&registry, "mcp", "safe_search", FTC_TOOL_FUNCTION,
			    1U, 900000U,
			    "{\"type\":\"object\",\"properties\":{\"q\":{\"type\":\"string\"}}}",
			    128U, &tool) == FTC_OK);
	for (i = 0; i < 10000U; i++) {
		int rc;

		memset(&request, 0, sizeof(request));
		request.request_sequence = i + 1U;
		request.now_ns = i + 100U;
		request.tool_generation = registry.generation;
		request.required_capabilities = 1U;
		request.maximum_tools = 1U;
		request.maximum_definition_bytes = 256U;
		request.maximum_result_bytes = 256U;
		request.minimum_trust_level = 800000U;
		request.flags = FTC_FLAG_VERIFIED_INPUT;
		switch (i % 5U) {
		case 0U:
			request.request_sequence = 0U;
			break;
		case 1U:
			request.tool_generation++;
			break;
		case 2U:
			request.maximum_tools = 0U;
			break;
		case 3U:
			request.maximum_definition_bytes = 0U;
			break;
		default:
			break;
		}
		rc = ftc_admit(&registry, &request, &admission);
		if (i % 5U == 4U) {
			assert(rc == FTC_OK);
			accepted++;
		} else {
			assert(rc == FTC_ERR_ARGUMENT);
			rejected++;
		}
	}
	printf("FTC_TOOL_CONTEXT_FUZZ_OK iterations=10000 rejected=%u accepted=%u\n",
	       rejected, accepted);
	return 0;
}
