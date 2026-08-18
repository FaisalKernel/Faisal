#include "faisal_budget.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct m240_policy test_policy(void)
{
	struct m240_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.current_time_ns = 1000U;
	policy.max_deadline_horizon_ns = 5000U;
	policy.minimum_priority = 100U;
	policy.require_authority = 1U;
	policy.require_verified_input = 1U;
	policy.maximum.cpu_ns = 100000U;
	policy.maximum.memory_bytes = 1024U * 1024U;
	policy.maximum.gpu_ns = 10000U;
	policy.maximum.npu_ns = 10000U;
	policy.maximum.network_bytes = 1000000U;
	policy.maximum.storage_bytes = 1000000U;
	policy.maximum.cost_micro = 10000U;
	policy.maximum.energy_uj = 1000000U;
	return policy;
}

static struct m240_request test_request(uint64_t objective_id)
{
	struct m240_request request;

	memset(&request, 0, sizeof(request));
	request.objective_id = objective_id;
	request.agent_id = 11U;
	request.tenant_id = 22U;
	request.trace_id = 33U;
	request.task_generation = 44U;
	request.session_generation = 55U;
	request.world_generation = 66U;
	request.model_generation = 77U;
	request.request_sequence = objective_id;
	request.issued_at_ns = 900U;
	request.deadline_ns = 2000U;
	request.priority = 500U;
	request.flags = M240_FLAG_VERIFIED_INPUT | M240_FLAG_AUTHORITY_GRANTED;
	request.requested.cpu_ns = 1000U;
	request.requested.memory_bytes = 4096U;
	request.requested.gpu_ns = 100U;
	request.requested.npu_ns = 50U;
	request.requested.network_bytes = 1000U;
	request.requested.storage_bytes = 200U;
	request.requested.cost_micro = 10U;
	request.requested.energy_uj = 20U;
	memset(request.objective_digest, 0x11, sizeof(request.objective_digest));
	memset(request.provenance_digest, 0x22, sizeof(request.provenance_digest));
	return request;
}

int main(void)
{
	struct m240_policy policy = test_policy();
	struct m240_service service;
	struct m240_request request = test_request(1U);
	struct m240_request second = test_request(2U);
	struct m240_receipt receipt;
	struct m240_receipt mutated;
	struct m240_record record;
	struct m240_budget usage;
	unsigned int mutation_rejections = 0U;
	unsigned int cases = 0U;
	unsigned int i;

	assert(m240_init(&service, &policy) == M240_OK);
	++cases;
	assert(m240_admit(&service, &request, &receipt) == M240_OK);
	assert(m240_verify_receipt(&receipt) == M240_OK);
	++cases;
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_DUPLICATE);
	++cases;
	assert(m240_query(&service, request.objective_id, &record) == M240_OK);
	assert(record.state == M240_STATE_ADMITTED);
	assert(record.remaining.cpu_ns == request.requested.cpu_ns);
	++cases;
	memset(&usage, 0, sizeof(usage));
	usage.cpu_ns = 100U;
	usage.memory_bytes = 512U;
	usage.gpu_ns = 10U;
	assert(m240_consume(&service, 1U, 999U, request.session_generation,
			    &usage, 1100U, &receipt) == M240_ERR_GENERATION);
	++cases;
	assert(m240_consume(&service, 1U, request.task_generation,
			    request.session_generation, &usage, 1100U,
			    &receipt) == M240_OK);
	assert(m240_verify_receipt(&receipt) == M240_OK);
	++cases;
	assert(m240_query(&service, 1U, &record) == M240_OK);
	assert(record.state == M240_STATE_ACTIVE);
	assert(record.remaining.cpu_ns == 900U);
	++cases;
	usage.cpu_ns = 10000U;
	assert(m240_consume(&service, 1U, request.task_generation,
			    request.session_generation, &usage, 1110U,
			    &receipt) == M240_ERR_BUDGET);
	++cases;
	assert(m240_complete(&service, 1U, request.task_generation,
			     request.session_generation, 1200U, &receipt) == M240_OK);
	assert(receipt.state == M240_STATE_COMPLETED);
	assert(m240_verify_receipt(&receipt) == M240_OK);
	++cases;
	assert(m240_consume(&service, 1U, request.task_generation,
			    request.session_generation, &usage, 1210U,
			    &receipt) == M240_ERR_STATE);
	++cases;
	mutated = receipt;
	mutated.receipt_digest[0] ^= 0x01U;
	assert(m240_verify_receipt(&mutated) == M240_ERR_TAMPER);
	++cases;
	for (i = 0U; i < 64U; ++i) {
		mutated = receipt;
		mutated.receipt_digest[i % M240_DIGEST_SIZE] ^= (uint8_t)(i + 1U);
		if (m240_verify_receipt(&mutated) == M240_ERR_TAMPER)
			++mutation_rejections;
	}
	assert(mutation_rejections == 64U);
	++cases;
	request = test_request(6U);
	request.flags = M240_FLAG_MODEL_PROPOSAL | M240_FLAG_VERIFIED_INPUT;
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_AUTHORITY);
	++cases;
	request = test_request(3U);
	request.requested.energy_uj = policy.maximum.energy_uj + 1U;
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_BUDGET);
	++cases;
	request = test_request(4U);
	request.deadline_ns = 900U;
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_DEADLINE);
	++cases;
	request = test_request(5U);
	request.flags = M240_FLAG_VERIFIED_INPUT | M240_FLAG_AUTHORITY_GRANTED;
	assert(m240_admit(&service, &request, &receipt) == M240_OK);
	assert(m240_cancel(&service, 5U, request.task_generation,
			   request.session_generation, 1300U, &receipt) == M240_OK);
	assert(receipt.state == M240_STATE_CANCELLED);
	++cases;
	assert(m240_cancel(&service, 5U, request.task_generation,
			   request.session_generation, 1301U, &receipt) == M240_ERR_STATE);
	++cases;
	second.flags = M240_FLAG_VERIFIED_INPUT | M240_FLAG_AUTHORITY_GRANTED;
	second.deadline_ns = 2500U;
	assert(m240_admit(&service, &second, &receipt) == M240_OK);
	assert(m240_verify_receipt(&receipt) == M240_OK);
	++cases;
	memset(&usage, 0, sizeof(usage));
	assert(m240_consume(&service, 2U, second.task_generation,
			    second.session_generation, &usage, 1400U,
			    &receipt) == M240_ERR_ARGUMENT);
	++cases;
	service.records[2].consumed.cpu_ns = UINT64_MAX;
	usage.cpu_ns = 1U;
	assert(m240_consume(&service, 2U, second.task_generation,
			    second.session_generation, &usage, 1401U,
			    &receipt) == M240_ERR_BUDGET);
	++cases;
	service.receipt_count = M240_MAX_RECEIPTS;
	request = test_request(7U);
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_FULL);
	++cases;
	service.receipt_count = 0U;
	service.record_count = M240_MAX_RECORDS;
	request = test_request(8U);
	assert(m240_admit(&service, &request, &receipt) == M240_ERR_FULL);
	++cases;
	printf("M240_BUDGET_SELFTEST_EXIT=0 cases=%u mutation_rejections=%u\n",
	       cases, mutation_rejections);
	return 0;
}
