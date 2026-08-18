#include "../../faisal-result-verify/faisal_result_verify.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int cases;

#define EXPECT_EQ(label, actual, expected) do { \
	int _actual = (actual); \
	int _expected = (expected); \
	++cases; \
	if (_actual != _expected) { \
		printf("FAIL %s actual=%d expected=%d\n", (label), _actual, _expected); \
		++failures; \
	} \
} while (0)

static void fill_digest(uint8_t digest[FSV_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FSV_DIGEST_SIZE);
}

static struct fsv_tool_contract contract(void)
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

static struct fsv_policy policy(int authority)
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

static struct fsv_result_request request(uint32_t flags)
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
	value.result_code = 0U;
	value.schema_valid = 1U;
	value.is_error = 0U;
	value.output_kind = FSV_OUTPUT_STRUCTURED;
	value.artifact_count = 1U;
	value.validator_id = 4U;
	value.flags = flags;
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

static int setup(struct fsv_service *service)
{
	struct fsv_tool_contract value = contract();

	if (fsv_init(service) != FSV_OK)
		return FSV_ERR_ARGUMENT;
	return fsv_register_tool(service, &value, NULL);
}

int main(void)
{
	struct fsv_service service;
	struct fsv_service fuzz_service;
	struct fsv_policy limits = policy(0);
	struct fsv_policy model_limits = policy(0);
	struct fsv_policy no_authority = policy(0);
	struct fsv_policy authority = policy(1);
	struct fsv_result_request good = request(FSV_FLAG_ARTIFACT_PRESENT);
	struct fsv_result_request model_only;
	struct fsv_result_request promotion = request(FSV_FLAG_ARTIFACT_PRESENT | FSV_FLAG_PROMOTION_REQUEST);
	struct fsv_result_request mutated;
	struct fsv_receipt receipt;
	struct fsv_receipt promoted;
	struct fsv_record record;
	uint8_t digest[FSV_DIGEST_SIZE];
	unsigned int mutation_rejections = 0U;
	unsigned int i;
	int result;

	model_limits.expected_tool_call_id = 0U;
	no_authority.expected_tool_call_id = 0U;
	EXPECT_EQ("init-register", setup(&service), FSV_OK);
	EXPECT_EQ("request-digest", fsv_digest_request(&good, digest), FSV_OK);
	EXPECT_EQ("admit-good", fsv_admit_result(&service, &good, &limits, &receipt), FSV_OK);
	EXPECT_EQ("query-good", fsv_query_result(&service, receipt.result_id, &record), FSV_OK);
	EXPECT_EQ("state-verified", (int)record.state, FSV_STATE_VERIFIED);
	EXPECT_EQ("receipt-verify", fsv_verify_receipt(&service, &receipt), FSV_OK);
	EXPECT_EQ("replay-sequence", fsv_admit_result(&service, &good, &limits, &promoted), FSV_ERR_REPLAY);

	mutated = good;
	mutated.schema_digest[0] ^= 0x01U;
	EXPECT_EQ("schema-tamper", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_SCHEMA);
	mutated = good;
	mutated.provenance_digest[0] = 0U;
	memset(mutated.provenance_digest + 1U, 0, FSV_DIGEST_SIZE - 1U);
	mutated.request_sequence = 2U;
	mutated.nonce = 101U;
	EXPECT_EQ("missing-provenance", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_PROVENANCE);
	mutated = good;
	mutated.flags = 0U;
	mutated.request_sequence = 2U;
	mutated.nonce = 102U;
	memset(mutated.artifact_digest, 0, FSV_DIGEST_SIZE);
	EXPECT_EQ("missing-artifact", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_ARTIFACT);
	mutated = good;
	mutated.is_error = 1U;
	mutated.request_sequence = 2U;
	mutated.nonce = 103U;
	EXPECT_EQ("provider-error", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_PROVIDER);
	mutated = good;
	mutated.task_generation = 9U;
	mutated.request_sequence = 2U;
	mutated.nonce = 104U;
	EXPECT_EQ("generation-fence", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_GENERATION);
	mutated = good;
	mutated.observed_at_ns = 12000U;
	mutated.request_sequence = 2U;
	mutated.nonce = 105U;
	EXPECT_EQ("deadline-fence", fsv_admit_result(&service, &mutated, &limits, &promoted), FSV_ERR_EXPIRED);

	model_only = request(FSV_FLAG_ARTIFACT_PRESENT | FSV_FLAG_MODEL_PROPOSAL | FSV_FLAG_PROMOTION_REQUEST);
	model_only.tool_call_id = 100U;
	model_only.request_sequence = 2U;
	model_only.nonce = 106U;
	EXPECT_EQ("model-only-authority", fsv_admit_result(&service, &model_only, &model_limits, &promoted), FSV_ERR_AUTHORITY);

	EXPECT_EQ("promotion-setup", setup(&service), FSV_OK);
	promotion.tool_call_id = 99U;
	promotion.request_sequence = 1U;
	promotion.nonce = 107U;
	EXPECT_EQ("promotion-admit", fsv_admit_result(&service, &promotion, &authority, &receipt), FSV_OK);
	EXPECT_EQ("promotion-no-independent", fsv_promote_result(&service, receipt.result_id, &(struct fsv_policy){
		.now_ns = 2000U,
		.expected_tool_id = 7U,
		.expected_tool_call_id = 99U,
		.expected_objective_id = 10U,
		.expected_trace_id = 20U,
		.expected_agent_id = 30U,
		.expected_tenant_id = 40U,
		.expected_task_generation = 2U,
		.expected_registry_generation = 3U,
		.expected_schema_generation = 5U,
		.expected_session_generation = 6U,
		.expected_world_generation = 7U,
		.max_age_ns = 5000U,
		.max_latency_ns = 5000U,
		.expected_validator_id = 4U,
		.expected_output_kind = FSV_OUTPUT_STRUCTURED,
		.require_schema = 1U,
		.require_provenance = 1U,
		.require_validator = 1U,
		.require_artifact = 1U,
		.authority_granted = 1U,
		.independent_verifier = 0U
	}, &promoted), FSV_ERR_AUTHORITY);
	EXPECT_EQ("promotion-commit", fsv_promote_result(&service, receipt.result_id, &authority, &promoted), FSV_OK);
	EXPECT_EQ("promotion-verify", fsv_verify_receipt(&service, &promoted), FSV_OK);
	EXPECT_EQ("promotion-query", fsv_query_result(&service, promoted.result_id, &record), FSV_OK);
	EXPECT_EQ("state-promoted", (int)record.state, FSV_STATE_PROMOTED);
	mutated = promotion;
	mutated.tool_call_id = 102U;
	mutated.request_sequence = 2U;
	mutated.nonce = 108U;
	EXPECT_EQ("promotion-admit-no-authority", fsv_admit_result(&service, &mutated, &no_authority, &receipt), FSV_ERR_AUTHORITY);
	record.receipt.receipt_digest[0] ^= 0xFFU;
	EXPECT_EQ("receipt-tamper", fsv_verify_receipt(&service, &record.receipt), FSV_ERR_TAMPER);

	for (i = 0U; i < 64U; ++i) {
		mutated = good;
		mutated.request_sequence = (uint64_t)i + 1U;
		mutated.nonce = (uint64_t)i + 1000U;
		switch (i % 8U) {
		case 0U: mutated.tool_id = 999U; break;
		case 1U: mutated.schema_generation = 99U; break;
		case 2U: memset(mutated.payload_digest, 0, FSV_DIGEST_SIZE); break;
		case 3U: mutated.provenance_digest[0] = 0U; memset(mutated.provenance_digest + 1U, 0, FSV_DIGEST_SIZE - 1U); break;
		case 4U: mutated.artifact_count = 0U; break;
		case 5U: mutated.is_error = 1U; break;
		case 6U: mutated.task_generation = 99U; break;
		default: mutated.observed_at_ns = 20000U; break;
		}
		if (setup(&fuzz_service) != FSV_OK)
			return 1;
		result = fsv_admit_result(&fuzz_service, &mutated, &limits, &promoted);
		if (result != FSV_OK)
			++mutation_rejections;
	}
	++cases;
	if (mutation_rejections != 64U) {
		printf("FAIL mutation-rejections actual=%u expected=64\n", mutation_rejections);
		++failures;
	}
	printf("M237_SELFTEST_EXIT=%d cases=%d mutation_rejections=%u\n",
	       failures == 0 ? 0 : 1, cases, mutation_rejections);
	return failures == 0 ? 0 : 1;
}
