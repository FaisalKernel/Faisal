#define _POSIX_C_SOURCE 200809L

#include "../../faisal-result-verify/faisal_result_verify.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void fill_digest(uint8_t digest[FSV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FSV_DIGEST_SIZE);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int run_round(struct fsv_service *service)
{
	struct fsv_tool_contract contract;
	struct fsv_result_request request;
	struct fsv_policy policy;
	struct fsv_receipt receipt;
	struct fsv_record record;

	memset(&contract, 0, sizeof(contract));
	contract.tool_id = 7U;
	contract.registry_generation = 3U;
	contract.schema_generation = 5U;
	contract.output_kind = FSV_OUTPUT_STRUCTURED;
	contract.active = 1U;
	fill_digest(contract.schema_digest, 0x21U);
	fill_digest(contract.implementation_digest, 0x22U);
	(void)snprintf(contract.name, sizeof(contract.name), "tool.result");
	if (fsv_init(service) != FSV_OK ||
	    fsv_register_tool(service, &contract, NULL) != FSV_OK)
		return FSV_ERR_ARGUMENT;
	memset(&request, 0, sizeof(request));
	request.tool_id = 7U;
	request.tool_call_id = 99U;
	request.objective_id = 10U;
	request.trace_id = 20U;
	request.agent_id = 30U;
	request.tenant_id = 40U;
	request.task_generation = 2U;
	request.registry_generation = 3U;
	request.schema_generation = 5U;
	request.session_generation = 6U;
	request.expected_world_generation = 7U;
	request.request_sequence = 1U;
	request.nonce = 100U;
	request.issued_at_ns = 1U;
	request.observed_at_ns = 1000U;
	request.deadline_ns = 10000U;
	request.schema_valid = 1U;
	request.output_kind = FSV_OUTPUT_STRUCTURED;
	request.artifact_count = 1U;
	request.validator_id = 4U;
	request.flags = FSV_FLAG_ARTIFACT_PRESENT | FSV_FLAG_PROMOTION_REQUEST;
	fill_digest(request.input_digest, 0x31U);
	fill_digest(request.arguments_digest, 0x32U);
	fill_digest(request.schema_digest, 0x21U);
	fill_digest(request.payload_digest, 0x33U);
	fill_digest(request.provenance_digest, 0x34U);
	fill_digest(request.validator_digest, 0x35U);
	fill_digest(request.artifact_digest, 0x36U);
	(void)snprintf(request.tool_call, sizeof(request.tool_call), "tool.result#99");
	memset(&policy, 0, sizeof(policy));
	policy.now_ns = 2000U;
	policy.expected_tool_id = 7U;
	policy.expected_tool_call_id = 99U;
	policy.expected_objective_id = 10U;
	policy.expected_trace_id = 20U;
	policy.expected_agent_id = 30U;
	policy.expected_tenant_id = 40U;
	policy.expected_task_generation = 2U;
	policy.expected_registry_generation = 3U;
	policy.expected_schema_generation = 5U;
	policy.expected_session_generation = 6U;
	policy.expected_world_generation = 7U;
	policy.max_age_ns = 5000U;
	policy.max_latency_ns = 5000U;
	policy.expected_validator_id = 4U;
	policy.expected_output_kind = FSV_OUTPUT_STRUCTURED;
	policy.require_schema = 1U;
	policy.require_provenance = 1U;
	policy.require_validator = 1U;
	policy.require_artifact = 1U;
	policy.authority_granted = 1U;
	policy.independent_verifier = 1U;
	if (fsv_admit_result(service, &request, &policy, &receipt) != FSV_OK)
		return FSV_ERR_STATE;
	if (fsv_verify_receipt(service, &receipt) != FSV_OK)
		return FSV_ERR_TAMPER;
	if (fsv_promote_result(service, receipt.result_id, &policy, &receipt) != FSV_OK)
		return FSV_ERR_AUTHORITY;
	if (fsv_query_result(service, receipt.result_id, &record) != FSV_OK)
		return FSV_ERR_NOT_FOUND;
	return record.state == FSV_STATE_PROMOTED ? FSV_OK : FSV_ERR_STATE;
}

int main(void)
{
	static struct fsv_service service;
	const uint64_t rounds = 100000U;
	uint64_t start;
	uint64_t elapsed;
	uint64_t i;
	int result;

	start = now_ns();
	for (i = 0U; i < rounds; ++i) {
		result = run_round(&service);
		if (result != FSV_OK) {
			printf("M237_BENCHMARK_EXIT=1 round=%llu status=%d\n",
			       (unsigned long long)i, result);
			return 1;
		}
	}
	elapsed = now_ns() - start;
	printf("M237_BENCHMARK_EXIT=0 rounds=%llu operations=%llu elapsed_ns=%llu ns_per_operation=%.2f\n",
	       (unsigned long long)rounds,
	       (unsigned long long)(rounds * 4ULL),
	       (unsigned long long)elapsed,
	       (double)elapsed / (double)(rounds * 4ULL));
	return 0;
}
