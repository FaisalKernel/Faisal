#include "faisal_result_verify.h"

#include <openssl/evp.h>
#include <string.h>

static int fsv_hash_parts(const void *const *parts, const size_t *lengths,
			  size_t count, uint8_t output[FSV_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int length = 0U;

	if (parts == NULL || lengths == NULL || output == NULL || count == 0U)
		return FSV_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FSV_ERR_FULL;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto error;
	for (i = 0U; i < count; ++i) {
		if (parts[i] == NULL && lengths[i] != 0U)
			goto error;
		if (EVP_DigestUpdate(ctx, parts[i], lengths[i]) != 1)
			goto error;
	}
	if (EVP_DigestFinal_ex(ctx, output, &length) != 1 ||
	    length != FSV_DIGEST_SIZE)
		goto error;
	EVP_MD_CTX_free(ctx);
	return FSV_OK;
error:
	EVP_MD_CTX_free(ctx);
	return FSV_ERR_ARGUMENT;
}

static void fsv_hash_u64(uint8_t *buffer, size_t *offset, uint64_t value)
{
	memcpy(buffer + *offset, &value, sizeof(value));
	*offset += sizeof(value);
}

static int fsv_is_zero(const uint8_t digest[FSV_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < FSV_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 0;
	}
	return 1;
}

static int fsv_has_terminator(const char *text, size_t capacity)
{
	size_t i;

	if (text == NULL)
		return 0;
	for (i = 0U; i < capacity; ++i) {
		if (text[i] == '\0')
			return 1;
	}
	return 0;
}

static size_t fsv_text_length(const char *text, size_t capacity)
{
	size_t i = 0U;

	while (i < capacity && text[i] != '\0')
		++i;
	return i;
}

static struct fsv_tool_contract *fsv_find_contract(
	struct fsv_service *service, uint64_t tool_id)
{
	size_t i;

	for (i = 0U; i < service->contract_count; ++i) {
		if (service->contracts[i].tool_id == tool_id)
			return &service->contracts[i];
	}
	return NULL;
}

static struct fsv_record *fsv_find_record(struct fsv_service *service,
					  uint64_t result_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.result_id == result_id)
			return &service->records[i];
	}
	return NULL;
}

static const struct fsv_record *fsv_find_record_const(
	const struct fsv_service *service, uint64_t result_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.result_id == result_id)
			return &service->records[i];
	}
	return NULL;
}

static int fsv_digest_validation(const struct fsv_result_request *request,
				const struct fsv_tool_contract *contract,
				uint8_t output[FSV_DIGEST_SIZE])
{
	uint8_t canonical[8U * 16U + FSV_DIGEST_SIZE * 6U];
	size_t offset = 0U;
	const void *parts[1];
	size_t lengths[1];

	if (request == NULL || contract == NULL || output == NULL)
		return FSV_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	fsv_hash_u64(canonical, &offset, request->tool_id);
	fsv_hash_u64(canonical, &offset, request->tool_call_id);
	fsv_hash_u64(canonical, &offset, request->objective_id);
	fsv_hash_u64(canonical, &offset, request->trace_id);
	fsv_hash_u64(canonical, &offset, request->task_generation);
	fsv_hash_u64(canonical, &offset, request->registry_generation);
	fsv_hash_u64(canonical, &offset, request->schema_generation);
	fsv_hash_u64(canonical, &offset, request->session_generation);
	fsv_hash_u64(canonical, &offset, request->expected_world_generation);
	memcpy(canonical + offset, request->schema_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, contract->implementation_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->provenance_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->validator_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->artifact_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->payload_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	parts[0] = canonical;
	lengths[0] = offset;
	return fsv_hash_parts(parts, lengths, 1U, output);
}

static int fsv_digest_receipt(const struct fsv_receipt *receipt,
				      uint8_t output[FSV_DIGEST_SIZE])
{
	uint8_t canonical[8U * 6U + 4U * 2U + FSV_DIGEST_SIZE * 3U];
	size_t offset = 0U;
	const void *parts[1];
	size_t lengths[1];

	if (receipt == NULL || output == NULL)
		return FSV_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	fsv_hash_u64(canonical, &offset, receipt->receipt_id);
	fsv_hash_u64(canonical, &offset, receipt->result_id);
	fsv_hash_u64(canonical, &offset, receipt->tool_id);
	fsv_hash_u64(canonical, &offset, receipt->tool_call_id);
	fsv_hash_u64(canonical, &offset, receipt->receipt_sequence);
	fsv_hash_u64(canonical, &offset, receipt->world_generation);
	memcpy(canonical + offset, &receipt->decision, sizeof(receipt->decision));
	offset += sizeof(receipt->decision);
	memcpy(canonical + offset, &receipt->state, sizeof(receipt->state));
	offset += sizeof(receipt->state);
	memcpy(canonical + offset, receipt->request_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, receipt->payload_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, receipt->validation_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	parts[0] = canonical;
	lengths[0] = offset;
	return fsv_hash_parts(parts, lengths, 1U, output);
}

static int fsv_digest_request_internal(const struct fsv_result_request *request,
					       uint8_t output[FSV_DIGEST_SIZE])
{
	uint8_t canonical[8U * 15U + 4U * 7U + FSV_DIGEST_SIZE * 7U + FSV_MAX_TOOL_CALL];
	size_t offset = 0U;
	const void *parts[1];
	size_t lengths[1];
	size_t text_length;

	if (request == NULL || output == NULL)
		return FSV_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	fsv_hash_u64(canonical, &offset, request->result_id);
	fsv_hash_u64(canonical, &offset, request->tool_id);
	fsv_hash_u64(canonical, &offset, request->tool_call_id);
	fsv_hash_u64(canonical, &offset, request->objective_id);
	fsv_hash_u64(canonical, &offset, request->trace_id);
	fsv_hash_u64(canonical, &offset, request->agent_id);
	fsv_hash_u64(canonical, &offset, request->tenant_id);
	fsv_hash_u64(canonical, &offset, request->task_generation);
	fsv_hash_u64(canonical, &offset, request->registry_generation);
	fsv_hash_u64(canonical, &offset, request->schema_generation);
	fsv_hash_u64(canonical, &offset, request->session_generation);
	fsv_hash_u64(canonical, &offset, request->expected_world_generation);
	fsv_hash_u64(canonical, &offset, request->request_sequence);
	fsv_hash_u64(canonical, &offset, request->nonce);
	fsv_hash_u64(canonical, &offset, request->issued_at_ns);
	fsv_hash_u64(canonical, &offset, request->observed_at_ns);
	memcpy(canonical + offset, &request->deadline_ns, sizeof(request->deadline_ns));
	offset += sizeof(request->deadline_ns);
	memcpy(canonical + offset, &request->result_code, sizeof(request->result_code));
	offset += sizeof(request->result_code);
	memcpy(canonical + offset, &request->schema_valid, sizeof(request->schema_valid));
	offset += sizeof(request->schema_valid);
	memcpy(canonical + offset, &request->is_error, sizeof(request->is_error));
	offset += sizeof(request->is_error);
	memcpy(canonical + offset, &request->output_kind, sizeof(request->output_kind));
	offset += sizeof(request->output_kind);
	memcpy(canonical + offset, &request->artifact_count, sizeof(request->artifact_count));
	offset += sizeof(request->artifact_count);
	memcpy(canonical + offset, &request->validator_id, sizeof(request->validator_id));
	offset += sizeof(request->validator_id);
	memcpy(canonical + offset, &request->flags, sizeof(request->flags));
	offset += sizeof(request->flags);
	memcpy(canonical + offset, request->input_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->arguments_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->schema_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->payload_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->provenance_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->validator_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	memcpy(canonical + offset, request->artifact_digest, FSV_DIGEST_SIZE);
	offset += FSV_DIGEST_SIZE;
	text_length = fsv_text_length(request->tool_call, sizeof(request->tool_call));
	memcpy(canonical + offset, request->tool_call, text_length);
	offset += text_length;
	parts[0] = canonical;
	lengths[0] = offset;
	return fsv_hash_parts(parts, lengths, 1U, output);
}

static int fsv_policy_match(const struct fsv_result_request *request,
				    const struct fsv_policy *policy,
				    const struct fsv_tool_contract *contract)
{
	uint64_t age;
	uint64_t latency;

	if (request == NULL || policy == NULL || contract == NULL)
		return FSV_ERR_ARGUMENT;
	if ((request->flags & ~FSV_FLAGS_ALL) != 0U ||
	    request->tool_id == 0U || request->tool_call_id == 0U ||
	    request->objective_id == 0U || request->trace_id == 0U ||
	    request->agent_id == 0U || request->tenant_id == 0U ||
	    request->task_generation == 0U || request->registry_generation == 0U ||
	    request->schema_generation == 0U || request->session_generation == 0U ||
	    request->request_sequence == 0U || request->nonce == 0U ||
	    request->issued_at_ns == 0U || request->observed_at_ns == 0U ||
	    request->deadline_ns == 0U ||
	    !fsv_has_terminator(request->tool_call, sizeof(request->tool_call)))
		return FSV_ERR_ARGUMENT;
	if (request->observed_at_ns < request->issued_at_ns ||
	    policy->now_ns < request->observed_at_ns ||
	    policy->now_ns > request->deadline_ns)
		return FSV_ERR_EXPIRED;
	age = policy->now_ns - request->observed_at_ns;
	latency = request->observed_at_ns - request->issued_at_ns;
	if ((policy->max_age_ns != 0U && age > policy->max_age_ns) ||
	    (policy->max_latency_ns != 0U && latency > policy->max_latency_ns))
		return FSV_ERR_EXPIRED;
	if ((policy->expected_tool_id != 0U &&
	     request->tool_id != policy->expected_tool_id) ||
	    (policy->expected_tool_call_id != 0U &&
	     request->tool_call_id != policy->expected_tool_call_id) ||
	    (policy->expected_objective_id != 0U &&
	     request->objective_id != policy->expected_objective_id) ||
	    (policy->expected_trace_id != 0U &&
	     request->trace_id != policy->expected_trace_id) ||
	    (policy->expected_agent_id != 0U &&
	     request->agent_id != policy->expected_agent_id) ||
	    (policy->expected_tenant_id != 0U &&
	     request->tenant_id != policy->expected_tenant_id) ||
	    (policy->expected_task_generation != 0U &&
	     request->task_generation != policy->expected_task_generation) ||
	    (policy->expected_registry_generation != 0U &&
	     request->registry_generation != policy->expected_registry_generation) ||
	    (policy->expected_schema_generation != 0U &&
	     request->schema_generation != policy->expected_schema_generation) ||
	    (policy->expected_session_generation != 0U &&
	     request->session_generation != policy->expected_session_generation) ||
	    (policy->expected_output_kind != 0U &&
	     request->output_kind != policy->expected_output_kind) ||
	    (policy->expected_validator_id != 0U &&
	     request->validator_id != policy->expected_validator_id))
		return FSV_ERR_GENERATION;
	if (!contract->active || request->registry_generation != contract->registry_generation ||
	    request->schema_generation != contract->schema_generation ||
	    request->output_kind != contract->output_kind ||
	    memcmp(request->schema_digest, contract->schema_digest,
		    FSV_DIGEST_SIZE) != 0)
		return FSV_ERR_SCHEMA;
	if (policy->require_schema && !request->schema_valid)
		return FSV_ERR_SCHEMA;
	if (policy->require_provenance && fsv_is_zero(request->provenance_digest))
		return FSV_ERR_PROVENANCE;
	if (policy->require_validator &&
	    (request->validator_id == 0U || fsv_is_zero(request->validator_digest)))
		return FSV_ERR_PROVENANCE;
	if (policy->require_artifact &&
	    (!(request->flags & FSV_FLAG_ARTIFACT_PRESENT) ||
	     request->artifact_count == 0U || fsv_is_zero(request->artifact_digest)))
		return FSV_ERR_ARTIFACT;
	if (fsv_is_zero(request->input_digest) ||
	    fsv_is_zero(request->arguments_digest) ||
	    fsv_is_zero(request->payload_digest))
		return FSV_ERR_ARGUMENT;
	if (request->is_error || request->result_code != 0U ||
	    (request->flags & FSV_FLAG_PROVIDER_ERROR))
		return FSV_ERR_PROVIDER;
	if ((request->flags & FSV_FLAG_PROMOTION_REQUEST) &&
	    (!policy->authority_granted || !policy->independent_verifier))
		return FSV_ERR_AUTHORITY;
	return FSV_OK;
}

static int fsv_make_receipt(struct fsv_service *service,
				    const struct fsv_result_request *request,
				    const struct fsv_tool_contract *contract,
				    const struct fsv_policy *policy,
				    uint32_t decision, uint32_t state,
				    struct fsv_receipt *out)
{
	uint8_t request_digest[FSV_DIGEST_SIZE];
	uint8_t validation_digest[FSV_DIGEST_SIZE];
	int result;

	if (service == NULL || request == NULL || contract == NULL ||
	    policy == NULL || out == NULL)
		return FSV_ERR_ARGUMENT;
	if (service->next_receipt_id == 0U)
		service->next_receipt_id = 1U;
	if (fsv_digest_request_internal(request, request_digest) != FSV_OK)
		return FSV_ERR_ARGUMENT;
	if (fsv_digest_validation(request, contract, validation_digest) != FSV_OK)
		return FSV_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->receipt_id = service->next_receipt_id++;
	out->result_id = request->result_id;
	out->tool_id = request->tool_id;
	out->tool_call_id = request->tool_call_id;
	out->receipt_sequence = ++service->receipt_sequence;
	out->world_generation = policy->expected_world_generation;
	out->decision = decision;
	out->state = state;
	memcpy(out->request_digest, request_digest, FSV_DIGEST_SIZE);
	memcpy(out->payload_digest, request->payload_digest, FSV_DIGEST_SIZE);
	memcpy(out->validation_digest, validation_digest, FSV_DIGEST_SIZE);
	result = fsv_digest_receipt(out, out->receipt_digest);
	if (result != FSV_OK)
		return result;
	return FSV_OK;
}

int fsv_init(struct fsv_service *service)
{
	if (service == NULL)
		return FSV_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->next_result_id = 1U;
	service->next_receipt_id = 1U;
	return FSV_OK;
}

int fsv_register_tool(struct fsv_service *service,
			     const struct fsv_tool_contract *contract,
			     uint64_t *out_tool_id)
{
	struct fsv_tool_contract copy;
	size_t i;

	if (service == NULL || contract == NULL || service->contract_count >= FSV_MAX_CONTRACTS ||
	    !fsv_has_terminator(contract->name, sizeof(contract->name)) ||
	    contract->registry_generation == 0U || contract->schema_generation == 0U ||
	    contract->output_kind == 0U || fsv_is_zero(contract->schema_digest) ||
	    fsv_is_zero(contract->implementation_digest))
		return FSV_ERR_ARGUMENT;
	for (i = 0U; i < service->contract_count; ++i) {
		if (service->contracts[i].tool_id == contract->tool_id && contract->tool_id != 0U)
			return FSV_ERR_CONFLICT;
		if (strcmp(service->contracts[i].name, contract->name) == 0)
			return FSV_ERR_CONFLICT;
	}
	copy = *contract;
	if (copy.tool_id == 0U)
		copy.tool_id = (uint64_t)service->contract_count + 1U;
	copy.active = 1U;
	service->contracts[service->contract_count++] = copy;
	if (out_tool_id != NULL)
		*out_tool_id = copy.tool_id;
	return FSV_OK;
}

int fsv_admit_result(struct fsv_service *service,
			     const struct fsv_result_request *request,
			     const struct fsv_policy *policy, struct fsv_receipt *out)
{
	struct fsv_record *record;
	struct fsv_result_request copy;
	struct fsv_tool_contract *contract;
	struct fsv_receipt receipt;
	uint64_t result_id;
	size_t i;
	int result;

	if (service == NULL || request == NULL || policy == NULL || out == NULL)
		return FSV_ERR_ARGUMENT;
	contract = fsv_find_contract(service, request->tool_id);
	if (contract == NULL)
		return FSV_ERR_NOT_FOUND;
	result = fsv_policy_match(request, policy, contract);
	if (result != FSV_OK)
		return result;
	if (request->request_sequence <= service->last_request_sequence)
		return FSV_ERR_REPLAY;
	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.tool_call_id == request->tool_call_id ||
		    service->records[i].request.nonce == request->nonce)
			return FSV_ERR_REPLAY;
	}
	if (service->record_count >= FSV_MAX_RECORDS)
		return FSV_ERR_FULL;
	copy = *request;
	result_id = copy.result_id;
	if (result_id == 0U)
		result_id = service->next_result_id++;
	else if (result_id >= service->next_result_id)
		service->next_result_id = result_id + 1U;
	if (fsv_find_record(service, result_id) != NULL)
		return FSV_ERR_CONFLICT;
	copy.result_id = result_id;
	result = fsv_make_receipt(service, &copy, contract, policy,
				  FSV_DECISION_VERIFIED, FSV_STATE_VERIFIED,
				  &receipt);
	if (result != FSV_OK)
		return result;
	record = &service->records[service->record_count++];
	memset(record, 0, sizeof(*record));
	record->request = copy;
	record->receipt = receipt;
	record->state = FSV_STATE_VERIFIED;
	service->last_request_sequence = request->request_sequence;
	*out = receipt;
	return FSV_OK;
}

int fsv_promote_result(struct fsv_service *service, uint64_t result_id,
			       const struct fsv_policy *policy,
			       struct fsv_receipt *out)
{
	struct fsv_record *record;
	struct fsv_tool_contract *contract;
	struct fsv_receipt receipt;
	int result;

	if (service == NULL || policy == NULL || out == NULL || result_id == 0U)
		return FSV_ERR_ARGUMENT;
	record = fsv_find_record(service, result_id);
	if (record == NULL)
		return FSV_ERR_NOT_FOUND;
	if (record->state != FSV_STATE_VERIFIED)
		return FSV_ERR_STATE;
	contract = fsv_find_contract(service, record->request.tool_id);
	if (contract == NULL)
		return FSV_ERR_NOT_FOUND;
	result = fsv_policy_match(&record->request, policy, contract);
	if (result != FSV_OK)
		return result;
	if (!policy->authority_granted || !policy->independent_verifier ||
	    !(record->request.flags & FSV_FLAG_PROMOTION_REQUEST))
		return FSV_ERR_AUTHORITY;
	if (policy->expected_world_generation != 0U &&
	    record->request.expected_world_generation != policy->expected_world_generation)
		return FSV_ERR_WORLD;
	result = fsv_make_receipt(service, &record->request, contract, policy,
				  FSV_DECISION_PROMOTED, FSV_STATE_PROMOTED,
				  &receipt);
	if (result != FSV_OK)
		return result;
	record->receipt = receipt;
	record->state = FSV_STATE_PROMOTED;
	*out = receipt;
	return FSV_OK;
}

int fsv_query_result(const struct fsv_service *service, uint64_t result_id,
			    struct fsv_record *out)
{
	const struct fsv_record *record;

	if (service == NULL || out == NULL || result_id == 0U)
		return FSV_ERR_ARGUMENT;
	record = fsv_find_record_const(service, result_id);
	if (record == NULL)
		return FSV_ERR_NOT_FOUND;
	*out = *record;
	return FSV_OK;
}

int fsv_verify_receipt(const struct fsv_service *service,
			       const struct fsv_receipt *receipt)
{
	const struct fsv_record *record;
	struct fsv_receipt canonical;
	uint8_t digest[FSV_DIGEST_SIZE];

	if (service == NULL || receipt == NULL || receipt->receipt_id == 0U)
		return FSV_ERR_ARGUMENT;
	record = fsv_find_record_const(service, receipt->result_id);
	if (record == NULL || record->receipt.receipt_id != receipt->receipt_id ||
	    memcmp(record->receipt.receipt_digest, receipt->receipt_digest,
		   FSV_DIGEST_SIZE) != 0)
		return FSV_ERR_TAMPER;
	canonical = *receipt;
	memset(canonical.receipt_digest, 0, FSV_DIGEST_SIZE);
	if (fsv_digest_receipt(&canonical, digest) != FSV_OK ||
	    memcmp(digest, receipt->receipt_digest, FSV_DIGEST_SIZE) != 0)
		return FSV_ERR_TAMPER;
	return FSV_OK;
}

int fsv_digest_request(const struct fsv_result_request *request,
			       uint8_t digest[FSV_DIGEST_SIZE])
{
	return fsv_digest_request_internal(request, digest);
}
