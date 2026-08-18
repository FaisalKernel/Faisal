#include "../../faisal-tool-context/faisal_tool_context.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void register_fixture(struct ftc_registry *registry)
{
	struct ftc_tool tool;

	assert(ftc_register(registry, "google-drive", "get_document",
			    FTC_TOOL_FUNCTION, 1U, 900000U,
			    "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}}}",
			    400U, &tool) == FTC_OK);
	assert(ftc_register(registry, "salesforce", "update_record",
			    FTC_TOOL_FUNCTION, 2U, 900000U,
			    "{\"type\":\"object\",\"properties\":{\"id\":{\"type\":\"string\"}}}",
			    400U, &tool) == FTC_OK);
	assert(ftc_register(registry, "browser", "click",
			    FTC_TOOL_FUNCTION, 4U, 850000U,
			    "{\"type\":\"object\",\"properties\":{\"x\":{\"type\":\"integer\"}}}",
			    128U, &tool) == FTC_OK);
	assert(ftc_register(registry, "secrets", "export",
			    FTC_TOOL_FUNCTION, 8U, 1000000U,
			    "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}}}",
			    512U, &tool) == FTC_OK);
	assert(ftc_register(registry, "mcp", "search_tools",
			    FTC_TOOL_FUNCTION, 1U, 700000U,
			    "{\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}",
			    1024U, &tool) == FTC_OK);
}

int main(void)
{
	struct ftc_registry registry;
	struct ftc_request request;
	struct ftc_request next_request;
	struct ftc_admission admission;
	struct ftc_admission repeat;
	struct ftc_admission next_admission;
	struct ftc_receipt receipt;
	struct ftc_result_projection projection;
	uint8_t payload[1024];
	uint8_t oversized[FTC_MAX_RESULT + 1U];
	uint32_t i;

	memset(payload, 'A', sizeof(payload));
	memset(oversized, 'B', sizeof(oversized));
	assert(ftc_init(&registry) == FTC_OK);
	register_fixture(&registry);
	memset(&request, 0, sizeof(request));
	request.request_sequence = 7U;
	request.now_ns = 1000000ULL;
	request.tool_generation = registry.generation;
	request.required_capabilities = 1U;
	request.maximum_tools = 2U;
	request.maximum_definition_bytes = 256U;
	request.maximum_result_bytes = 600U;
	request.minimum_trust_level = 800000U;
	request.flags = FTC_FLAG_VERIFIED_INPUT | FTC_FLAG_MODEL_PROPOSAL;
	assert(ftc_admit(&registry, &request, &admission) == FTC_OK);
	assert(admission.selected_count == 1U);
	assert(admission.skipped_count == 4U);
	assert(admission.projected_definition_bytes <= request.maximum_definition_bytes);
	assert(admission.projected_result_bytes <= request.maximum_result_bytes);
	assert(ftc_admit(&registry, &request, &repeat) == FTC_OK);
	assert(memcmp(admission.admission_digest, repeat.admission_digest,
		      FTC_DIGEST_SIZE) == 0);
	assert(ftc_make_receipt(&registry, &request, &admission, &receipt) == FTC_OK);
	assert(ftc_verify_receipt(&registry, &request, &admission, &receipt) == FTC_OK);
	receipt.projected_result_bytes++;
	assert(ftc_verify_receipt(&registry, &request, &admission, &receipt) == FTC_ERR_TAMPER);
	receipt.projected_result_bytes--;
	assert(ftc_project_result(&registry, &request, admission.selected_ids[0],
				  payload, sizeof(payload), &projection) == FTC_OK);
	assert(projection.original_bytes == sizeof(payload));
	assert(projection.projected_bytes == request.maximum_result_bytes);
	assert(projection.truncated == 1U);
	assert(ftc_verify_digest(payload, sizeof(payload), projection.original_digest) == FTC_OK);
	assert(ftc_project_result(&registry, &request, admission.selected_ids[0],
				  oversized, sizeof(oversized), &projection) == FTC_ERR_ARGUMENT);
	assert(ftc_bump_generation(&registry) == FTC_OK);
	assert(ftc_verify_receipt(&registry, &request, &admission, &receipt) == FTC_ERR_GENERATION);
	memset(&next_request, 0, sizeof(next_request));
	next_request = request;
	next_request.request_sequence++;
	next_request.tool_generation = registry.generation;
	assert(ftc_admit(&registry, &next_request, &next_admission) == FTC_OK);
	assert(ftc_make_receipt(&registry, &next_request, &next_admission, &receipt) == FTC_OK);
	assert(ftc_verify_receipt(&registry, &next_request, &next_admission, &receipt) == FTC_OK);
	for (i = 0; i < 100U; i++) {
		struct ftc_request malformed = next_request;
		malformed.maximum_definition_bytes = i == 0U ? 0U : malformed.maximum_definition_bytes;
		if (i == 0U)
			assert(ftc_admit(&registry, &malformed, &repeat) == FTC_ERR_ARGUMENT);
	}
	printf("FTC_TOOL_CONTEXT_SELFTEST_OK cases=18 selected=%u skipped=%u projected_definition=%u projected_result=%u generation=%llu\n",
	       admission.selected_count, admission.skipped_count,
	       admission.projected_definition_bytes, admission.projected_result_bytes,
	       (unsigned long long)registry.generation);
	return 0;
}
