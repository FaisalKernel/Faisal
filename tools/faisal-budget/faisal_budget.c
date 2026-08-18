#include "faisal_budget.h"

#include <openssl/evp.h>
#include <string.h>

static int digest_bytes(const uint8_t *data, size_t length,
			uint8_t digest[M240_DIGEST_SIZE])
{
	unsigned int digest_length = 0U;

	if ((data == NULL && length != 0U) || digest == NULL)
		return M240_ERR_ARGUMENT;
	if (EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 ||
	    digest_length != M240_DIGEST_SIZE)
		return M240_ERR_TAMPER;
	return M240_OK;
}

static void put64(uint8_t *buffer, size_t *offset, uint64_t value)
{
	memcpy(buffer + *offset, &value, sizeof(value));
	*offset += sizeof(value);
}

static void put32(uint8_t *buffer, size_t *offset, uint32_t value)
{
	memcpy(buffer + *offset, &value, sizeof(value));
	*offset += sizeof(value);
}

static int is_zero_digest(const uint8_t digest[M240_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < M240_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 0;
	}
	return 1;
}

static int budget_is_zero(const struct m240_budget *budget)
{
	return budget != NULL && budget->cpu_ns == 0U &&
	       budget->memory_bytes == 0U && budget->gpu_ns == 0U &&
	       budget->npu_ns == 0U && budget->network_bytes == 0U &&
	       budget->storage_bytes == 0U && budget->cost_micro == 0U &&
	       budget->energy_uj == 0U;
}

static int budget_exceeds(const struct m240_budget *left,
			 const struct m240_budget *right)
{
	return left == NULL || right == NULL || left->cpu_ns > right->cpu_ns ||
	       left->memory_bytes > right->memory_bytes ||
	       left->gpu_ns > right->gpu_ns || left->npu_ns > right->npu_ns ||
	       left->network_bytes > right->network_bytes ||
	       left->storage_bytes > right->storage_bytes ||
	       left->cost_micro > right->cost_micro ||
	       left->energy_uj > right->energy_uj;
}

static int budget_add_overflows(const struct m240_budget *left,
				const struct m240_budget *right)
{
	return left == NULL || right == NULL ||
	       UINT64_MAX - left->cpu_ns < right->cpu_ns ||
	       UINT64_MAX - left->memory_bytes < right->memory_bytes ||
	       UINT64_MAX - left->gpu_ns < right->gpu_ns ||
	       UINT64_MAX - left->npu_ns < right->npu_ns ||
	       UINT64_MAX - left->network_bytes < right->network_bytes ||
	       UINT64_MAX - left->storage_bytes < right->storage_bytes ||
	       UINT64_MAX - left->cost_micro < right->cost_micro ||
	       UINT64_MAX - left->energy_uj < right->energy_uj;
}

static void budget_subtract(struct m240_budget *remaining,
			    const struct m240_budget *usage)
{
	remaining->cpu_ns -= usage->cpu_ns;
	remaining->memory_bytes -= usage->memory_bytes;
	remaining->gpu_ns -= usage->gpu_ns;
	remaining->npu_ns -= usage->npu_ns;
	remaining->network_bytes -= usage->network_bytes;
	remaining->storage_bytes -= usage->storage_bytes;
	remaining->cost_micro -= usage->cost_micro;
	remaining->energy_uj -= usage->energy_uj;
}

static void budget_put(uint8_t *buffer, size_t *offset,
		       const struct m240_budget *budget)
{
	put64(buffer, offset, budget->cpu_ns);
	put64(buffer, offset, budget->memory_bytes);
	put64(buffer, offset, budget->gpu_ns);
	put64(buffer, offset, budget->npu_ns);
	put64(buffer, offset, budget->network_bytes);
	put64(buffer, offset, budget->storage_bytes);
	put64(buffer, offset, budget->cost_micro);
	put64(buffer, offset, budget->energy_uj);
}

static int digest_request(const struct m240_request *request,
			  uint8_t digest[M240_DIGEST_SIZE])
{
	uint8_t canonical[8U * 19U + 4U * 2U + M240_DIGEST_SIZE * 2U];
	size_t offset = 0U;

	if (request == NULL || digest == NULL)
		return M240_ERR_ARGUMENT;
	put64(canonical, &offset, request->objective_id);
	put64(canonical, &offset, request->agent_id);
	put64(canonical, &offset, request->tenant_id);
	put64(canonical, &offset, request->trace_id);
	put64(canonical, &offset, request->task_generation);
	put64(canonical, &offset, request->session_generation);
	put64(canonical, &offset, request->world_generation);
	put64(canonical, &offset, request->model_generation);
	put64(canonical, &offset, request->request_sequence);
	put64(canonical, &offset, request->issued_at_ns);
	put64(canonical, &offset, request->deadline_ns);
	budget_put(canonical, &offset, &request->requested);
	put32(canonical, &offset, request->priority);
	put32(canonical, &offset, request->flags);
	memcpy(canonical + offset, request->objective_digest, M240_DIGEST_SIZE);
	offset += M240_DIGEST_SIZE;
	memcpy(canonical + offset, request->provenance_digest, M240_DIGEST_SIZE);
	offset += M240_DIGEST_SIZE;
	return digest_bytes(canonical, offset, digest);
}

static int digest_usage(const struct m240_record *record,
			uint8_t digest[M240_DIGEST_SIZE])
{
	uint8_t canonical[8U * 17U + 4U];
	size_t offset = 0U;

	if (record == NULL || digest == NULL)
		return M240_ERR_ARGUMENT;
	budget_put(canonical, &offset, &record->consumed);
	budget_put(canonical, &offset, &record->remaining);
	put32(canonical, &offset, record->state);
	return digest_bytes(canonical, offset, digest);
}

static int digest_receipt(const struct m240_receipt *receipt,
			  uint8_t digest[M240_DIGEST_SIZE])
{
	uint8_t canonical[8U * 16U + 4U * 2U + M240_DIGEST_SIZE * 2U];
	size_t offset = 0U;

	if (receipt == NULL || digest == NULL)
		return M240_ERR_ARGUMENT;
	put64(canonical, &offset, receipt->receipt_id);
	put64(canonical, &offset, receipt->objective_id);
	put64(canonical, &offset, receipt->tenant_id);
	put64(canonical, &offset, receipt->trace_id);
	put64(canonical, &offset, receipt->task_generation);
	put64(canonical, &offset, receipt->session_generation);
	put64(canonical, &offset, receipt->receipt_sequence);
	put64(canonical, &offset, receipt->observed_at_ns);
	budget_put(canonical, &offset, &receipt->remaining);
	put32(canonical, &offset, receipt->state);
	put32(canonical, &offset, (uint32_t)receipt->status);
	memcpy(canonical + offset, receipt->request_digest, M240_DIGEST_SIZE);
	offset += M240_DIGEST_SIZE;
	memcpy(canonical + offset, receipt->usage_digest, M240_DIGEST_SIZE);
	offset += M240_DIGEST_SIZE;
	return digest_bytes(canonical, offset, digest);
}

static struct m240_record *find_record(struct m240_service *service,
				       uint64_t objective_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.objective_id == objective_id)
			return &service->records[i];
	}
	return NULL;
}

static const struct m240_record *find_record_const(
		const struct m240_service *service, uint64_t objective_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.objective_id == objective_id)
			return &service->records[i];
	}
	return NULL;
}

static int generation_match(const struct m240_request *request,
			    uint64_t task_generation, uint64_t session_generation)
{
	return request != NULL && request->task_generation == task_generation &&
	       request->session_generation == session_generation;
}

static int policy_match(const struct m240_request *request,
			const struct m240_policy *policy)
{
	uint64_t horizon;

	if (request == NULL || policy == NULL || request->objective_id == 0U ||
	    request->agent_id == 0U || request->tenant_id == 0U ||
	    request->trace_id == 0U || request->task_generation == 0U ||
	    request->session_generation == 0U || request->world_generation == 0U ||
	    request->model_generation == 0U || request->request_sequence == 0U ||
	    request->issued_at_ns == 0U || request->deadline_ns < request->issued_at_ns ||
	    request->priority < policy->minimum_priority ||
	    (request->flags & ~M240_FLAGS_ALL) != 0U ||
	    budget_is_zero(&request->requested) ||
	    is_zero_digest(request->objective_digest) ||
	    is_zero_digest(request->provenance_digest))
		return M240_ERR_ARGUMENT;
	if (policy->current_time_ns < request->issued_at_ns ||
	    policy->current_time_ns > request->deadline_ns)
		return M240_ERR_DEADLINE;
	horizon = request->deadline_ns - policy->current_time_ns;
	if (policy->max_deadline_horizon_ns != 0U &&
	    horizon > policy->max_deadline_horizon_ns)
		return M240_ERR_DEADLINE;
	if (policy->expected_tenant_id != 0U &&
	    request->tenant_id != policy->expected_tenant_id)
		return M240_ERR_GENERATION;
	if (policy->expected_agent_id != 0U &&
	    request->agent_id != policy->expected_agent_id)
		return M240_ERR_GENERATION;
	if (policy->expected_task_generation != 0U &&
	    request->task_generation != policy->expected_task_generation)
		return M240_ERR_GENERATION;
	if (policy->expected_session_generation != 0U &&
	    request->session_generation != policy->expected_session_generation)
		return M240_ERR_GENERATION;
	if (policy->expected_world_generation != 0U &&
	    request->world_generation != policy->expected_world_generation)
		return M240_ERR_GENERATION;
	if (policy->expected_model_generation != 0U &&
	    request->model_generation != policy->expected_model_generation)
		return M240_ERR_GENERATION;
	if (budget_exceeds(&request->requested, &policy->maximum))
		return M240_ERR_BUDGET;
	return M240_OK;
}

int m240_authority_check(const struct m240_request *request,
			 const struct m240_policy *policy)
{
	if (request == NULL || policy == NULL)
		return M240_ERR_ARGUMENT;
	if (policy->require_authority &&
	    !(request->flags & M240_FLAG_AUTHORITY_GRANTED))
		return M240_ERR_AUTHORITY;
	if (policy->require_verified_input &&
	    !(request->flags & M240_FLAG_VERIFIED_INPUT))
		return M240_ERR_POLICY;
	if ((request->flags & M240_FLAG_MODEL_PROPOSAL) &&
	    !(request->flags & M240_FLAG_AUTHORITY_GRANTED))
		return M240_ERR_AUTHORITY;
	return M240_OK;
}

static int append_receipt(struct m240_service *service,
			  struct m240_record *record, int status,
			  uint64_t observed_at_ns, struct m240_receipt *out)
{
	struct m240_receipt receipt;

	if (service == NULL || record == NULL || out == NULL ||
	    service->receipt_count >= M240_MAX_RECEIPTS)
		return M240_ERR_FULL;
	memset(&receipt, 0, sizeof(receipt));
	receipt.receipt_id = service->next_receipt_id++;
	receipt.objective_id = record->request.objective_id;
	receipt.tenant_id = record->request.tenant_id;
	receipt.trace_id = record->request.trace_id;
	receipt.task_generation = record->request.task_generation;
	receipt.session_generation = record->request.session_generation;
	receipt.receipt_sequence = ++service->receipt_sequence;
	receipt.observed_at_ns = observed_at_ns;
	receipt.state = record->state;
	receipt.status = status;
	receipt.remaining = record->remaining;
	memcpy(receipt.request_digest, record->request_digest, M240_DIGEST_SIZE);
	if (digest_usage(record, receipt.usage_digest) != M240_OK ||
	    digest_receipt(&receipt, receipt.receipt_digest) != M240_OK)
		return M240_ERR_TAMPER;
	service->receipts[service->receipt_count++] = receipt;
	record->receipt = receipt;
	*out = receipt;
	return M240_OK;
}

int m240_init(struct m240_service *service, const struct m240_policy *policy)
{
	if (service == NULL || policy == NULL || policy->current_time_ns == 0U ||
	    budget_is_zero(&policy->maximum))
		return M240_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->next_receipt_id = 1U;
	return M240_OK;
}

int m240_admit(struct m240_service *service, const struct m240_request *request,
	       struct m240_receipt *out)
{
	struct m240_record *record;
	int result;

	if (service == NULL || request == NULL || out == NULL)
		return M240_ERR_ARGUMENT;
	if (service->record_count >= M240_MAX_RECORDS ||
	    service->receipt_count >= M240_MAX_RECEIPTS)
		return M240_ERR_FULL;
	if (find_record_const(service, request->objective_id) != NULL)
		return M240_ERR_DUPLICATE;
	result = m240_authority_check(request, &service->policy);
	if (result != M240_OK)
		return result;
	result = policy_match(request, &service->policy);
	if (result != M240_OK)
		return result;
	record = &service->records[service->record_count];
	memset(record, 0, sizeof(*record));
	record->request = *request;
	record->remaining = request->requested;
	record->state = M240_STATE_ADMITTED;
	if (digest_request(request, record->request_digest) != M240_OK)
		return M240_ERR_TAMPER;
	++service->record_count;
	return append_receipt(service, record, M240_OK,
			      service->policy.current_time_ns, out);
}

int m240_consume(struct m240_service *service, uint64_t objective_id,
		 uint64_t task_generation, uint64_t session_generation,
		 const struct m240_budget *usage, uint64_t observed_at_ns,
		 struct m240_receipt *out)
{
	struct m240_record *record;

	if (service == NULL || usage == NULL || out == NULL || objective_id == 0U ||
	    observed_at_ns == 0U || budget_is_zero(usage))
		return M240_ERR_ARGUMENT;
	record = find_record(service, objective_id);
	if (record == NULL)
		return M240_ERR_NOT_FOUND;
	if (!generation_match(&record->request, task_generation, session_generation))
		return M240_ERR_GENERATION;
	if (observed_at_ns > record->request.deadline_ns)
		return M240_ERR_DEADLINE;
	if (record->state != M240_STATE_ADMITTED &&
	    record->state != M240_STATE_ACTIVE)
		return M240_ERR_STATE;
	if (budget_exceeds(usage, &record->remaining) ||
	    budget_add_overflows(&record->consumed, usage))
		return M240_ERR_BUDGET;
	budget_subtract(&record->remaining, usage);
	record->consumed.cpu_ns += usage->cpu_ns;
	record->consumed.memory_bytes += usage->memory_bytes;
	record->consumed.gpu_ns += usage->gpu_ns;
	record->consumed.npu_ns += usage->npu_ns;
	record->consumed.network_bytes += usage->network_bytes;
	record->consumed.storage_bytes += usage->storage_bytes;
	record->consumed.cost_micro += usage->cost_micro;
	record->consumed.energy_uj += usage->energy_uj;
	record->state = budget_is_zero(&record->remaining) ?
		M240_STATE_EXHAUSTED : M240_STATE_ACTIVE;
	return append_receipt(service, record, M240_OK, observed_at_ns, out);
}

int m240_complete(struct m240_service *service, uint64_t objective_id,
		  uint64_t task_generation, uint64_t session_generation,
		  uint64_t observed_at_ns, struct m240_receipt *out)
{
	struct m240_record *record;

	if (service == NULL || out == NULL || objective_id == 0U ||
	    observed_at_ns == 0U)
		return M240_ERR_ARGUMENT;
	record = find_record(service, objective_id);
	if (record == NULL)
		return M240_ERR_NOT_FOUND;
	if (!generation_match(&record->request, task_generation, session_generation))
		return M240_ERR_GENERATION;
	if (observed_at_ns > record->request.deadline_ns)
		return M240_ERR_DEADLINE;
	if (record->state != M240_STATE_ADMITTED &&
	    record->state != M240_STATE_ACTIVE &&
	    record->state != M240_STATE_EXHAUSTED)
		return M240_ERR_STATE;
	record->state = M240_STATE_COMPLETED;
	return append_receipt(service, record, M240_OK, observed_at_ns, out);
}

int m240_cancel(struct m240_service *service, uint64_t objective_id,
		uint64_t task_generation, uint64_t session_generation,
		uint64_t observed_at_ns, struct m240_receipt *out)
{
	struct m240_record *record;

	if (service == NULL || out == NULL || objective_id == 0U ||
	    observed_at_ns == 0U)
		return M240_ERR_ARGUMENT;
	record = find_record(service, objective_id);
	if (record == NULL)
		return M240_ERR_NOT_FOUND;
	if (!generation_match(&record->request, task_generation, session_generation))
		return M240_ERR_GENERATION;
	if (record->state == M240_STATE_COMPLETED ||
	    record->state == M240_STATE_CANCELLED)
		return M240_ERR_STATE;
	record->state = M240_STATE_CANCELLED;
	return append_receipt(service, record, M240_OK, observed_at_ns, out);
}

int m240_query(const struct m240_service *service, uint64_t objective_id,
	      struct m240_record *out)
{
	const struct m240_record *record;

	if (service == NULL || out == NULL || objective_id == 0U)
		return M240_ERR_ARGUMENT;
	record = find_record_const(service, objective_id);
	if (record == NULL)
		return M240_ERR_NOT_FOUND;
	*out = *record;
	return M240_OK;
}

int m240_verify_receipt(const struct m240_receipt *receipt)
{
	uint8_t digest[M240_DIGEST_SIZE];

	if (receipt == NULL || receipt->receipt_id == 0U ||
	    receipt->objective_id == 0U || receipt->tenant_id == 0U ||
	    receipt->trace_id == 0U || receipt->task_generation == 0U ||
	    receipt->session_generation == 0U || receipt->receipt_sequence == 0U ||
	    receipt->observed_at_ns == 0U || receipt->state > M240_STATE_TAMPERED ||
	    is_zero_digest(receipt->request_digest) ||
	    is_zero_digest(receipt->usage_digest))
		return M240_ERR_ARGUMENT;
	if (digest_receipt(receipt, digest) != M240_OK ||
	    memcmp(digest, receipt->receipt_digest, M240_DIGEST_SIZE) != 0)
		return M240_ERR_TAMPER;
	return M240_OK;
}
