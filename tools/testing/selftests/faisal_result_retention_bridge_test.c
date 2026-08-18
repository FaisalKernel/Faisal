#include "faisal_result_retention_bridge.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_eq(const char *name, int actual, int expected)
{
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual,
			expected);
		failures++;
	}
}

static void fill_digest(uint8_t digest[FSV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FSV_DIGEST_SIZE);
}

static struct fsv_tool_contract tool_contract(void)
{
	struct fsv_tool_contract value;

	memset(&value, 0, sizeof(value));
	value.tool_id = 7U;
	value.registry_generation = 3U;
	value.schema_generation = 5U;
	value.output_kind = FSV_OUTPUT_STRUCTURED;
	value.active = 1U;
	fill_digest(value.schema_digest, 0x21U);
	fill_digest(value.implementation_digest, 0x22U);
	(void)snprintf(value.name, sizeof(value.name), "weather.lookup");
	return value;
}

static struct fsv_result_request result_request(void)
{
	struct fsv_result_request value;

	memset(&value, 0, sizeof(value));
	value.tool_id = 7U;
	value.tool_call_id = 99U;
	value.objective_id = 10U;
	value.trace_id = 20U;
	value.agent_id = 30U;
	value.tenant_id = 40U;
	value.task_generation = 2U;
	value.registry_generation = 3U;
	value.schema_generation = 5U;
	value.session_generation = 6U;
	value.expected_world_generation = 7U;
	value.request_sequence = 1U;
	value.nonce = 100U;
	value.issued_at_ns = 1U;
	value.observed_at_ns = 1000U;
	value.deadline_ns = 10000U;
	value.schema_valid = 1U;
	value.output_kind = FSV_OUTPUT_STRUCTURED;
	value.artifact_count = 1U;
	value.validator_id = 4U;
	value.flags = FSV_FLAG_ARTIFACT_PRESENT;
	fill_digest(value.input_digest, 0x31U);
	fill_digest(value.arguments_digest, 0x32U);
	fill_digest(value.schema_digest, 0x21U);
	fill_digest(value.payload_digest, 0x33U);
	fill_digest(value.provenance_digest, 0x34U);
	fill_digest(value.validator_digest, 0x35U);
	fill_digest(value.artifact_digest, 0x36U);
	(void)snprintf(value.tool_call, sizeof(value.tool_call), "weather.lookup#99");
	return value;
}

static struct fsv_policy verification_policy(int authority)
{
	struct fsv_policy value;

	memset(&value, 0, sizeof(value));
	value.now_ns = 2000U;
	value.expected_tool_id = 7U;
	value.expected_tool_call_id = 99U;
	value.expected_objective_id = 10U;
	value.expected_trace_id = 20U;
	value.expected_agent_id = 30U;
	value.expected_tenant_id = 40U;
	value.expected_task_generation = 2U;
	value.expected_registry_generation = 3U;
	value.expected_schema_generation = 5U;
	value.expected_session_generation = 6U;
	value.expected_world_generation = 7U;
	value.max_age_ns = 5000U;
	value.max_latency_ns = 5000U;
	value.expected_validator_id = 4U;
	value.expected_output_kind = FSV_OUTPUT_STRUCTURED;
	value.require_schema = 1U;
	value.require_provenance = 1U;
	value.require_validator = 1U;
	value.require_artifact = 1U;
	value.authority_granted = (uint32_t)authority;
	value.independent_verifier = 1U;
	return value;
}

static struct rdr_policy retention_policy(uint64_t now, uint64_t sequence)
{
	struct rdr_policy value;

	memset(&value, 0, sizeof(value));
	value.now_ns = now;
	value.expected_objective_id = 10U;
	value.expected_trace_id = 20U;
	value.expected_agent_id = 30U;
	value.expected_tenant_id = 40U;
	value.expected_task_generation = 2U;
	value.expected_session_generation = 6U;
	value.expected_world_generation = 7U;
	value.expected_next_sequence = sequence;
	value.max_age_ns = 10000U;
	value.require_verified = 1U;
	return value;
}

int main(void)
{
	struct fsv_service verification;
	struct fsv_tool_contract contract = tool_contract();
	struct fsv_result_request request = result_request();
	struct fsv_policy limits = verification_policy(1);
	struct fsv_policy authority = verification_policy(1);
	struct fsv_receipt receipt;
	struct fsv_receipt promoted;
	struct fsv_record record;
	struct rdr_service retention;
	struct rdr_event retained;
	struct rdr_event committed;
	struct rdr_policy policy;
	uint8_t transition[RDR_DIGEST_SIZE];

	request.flags |= FSV_FLAG_PROMOTION_REQUEST;
	expect_eq("fsv-init", fsv_init(&verification), FSV_OK);
	expect_eq("fsv-register", fsv_register_tool(&verification, &contract, NULL), FSV_OK);
	expect_eq("fsv-admit", fsv_admit_result(&verification, &request, &limits,
		&receipt), FSV_OK);
	expect_eq("retention-init", rdr_init(&retention), RDR_OK);
	policy = retention_policy(2000U, 1U);
	expect_eq("import-verified", rdr_import_fsv_result(&retention,
		&verification, receipt.result_id, &policy, &retained), RDR_OK);
	expect_eq("commit-before-fsv-promotion", rdr_commit_fsv_result(&retention,
		&verification, receipt.result_id, (uint8_t[ RDR_DIGEST_SIZE ]){ 1U },
		&(struct rdr_policy){
			.now_ns = 3000U,
			.expected_objective_id = 10U,
			.expected_trace_id = 20U,
			.expected_agent_id = 30U,
			.expected_tenant_id = 40U,
			.expected_task_generation = 2U,
			.expected_session_generation = 6U,
			.expected_world_generation = 7U,
			.expected_next_sequence = 2U,
			.max_age_ns = 10000U,
			.require_verified = 1U,
			.authority_granted = 1U,
			.independent_verifier = 1U
		}, &committed), RDR_ERR_AUTHORITY);
	expect_eq("fsv-promote", fsv_promote_result(&verification,
		receipt.result_id, &authority, &promoted), FSV_OK);
	expect_eq("fsv-query-promoted", fsv_query_result(&verification,
		promoted.result_id, &record), FSV_OK);
	expect_eq("fsv-promoted-state", (int)record.state, FSV_STATE_PROMOTED);
	fill_digest(transition, 9U);
	policy = retention_policy(3000U, 2U);
	policy.authority_granted = 1U;
	policy.independent_verifier = 1U;
	expect_eq("commit-promoted", rdr_commit_fsv_result(&retention,
		&verification, receipt.result_id, transition, &policy, &committed), RDR_OK);
	expect_eq("bridge-replay", rdr_verify_event(&retained,
		(uint8_t[RDR_DIGEST_SIZE]){ 0U }), RDR_OK);
	expect_eq("bridge-commit-state", rdr_query(&retention,
		receipt.result_id, &(struct rdr_projection){ 0 }), RDR_OK);
	printf("M238_RETENTION_BRIDGE_SELFTEST_EXIT=%d cases=12\n",
	       failures == 0 ? 0 : 1);
	return failures == 0 ? 0 : 1;
}
