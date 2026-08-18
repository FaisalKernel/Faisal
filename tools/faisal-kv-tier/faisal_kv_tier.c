#include "faisal_kv_tier.h"

#include <openssl/evp.h>
#include <string.h>

static int rkv_hash(const void *const *parts, const size_t *lengths,
			 size_t count, uint8_t output[RKV_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int length = 0U;

	if (parts == NULL || lengths == NULL || output == NULL || count == 0U)
		return RKV_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return RKV_ERR_FULL;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto error;
	for (i = 0U; i < count; ++i) {
		if (parts[i] == NULL && lengths[i] != 0U)
			goto error;
		if (EVP_DigestUpdate(ctx, parts[i], lengths[i]) != 1)
			goto error;
	}
	if (EVP_DigestFinal_ex(ctx, output, &length) != 1 ||
	    length != RKV_DIGEST_SIZE)
		goto error;
	EVP_MD_CTX_free(ctx);
	return RKV_OK;
error:
	EVP_MD_CTX_free(ctx);
	return RKV_ERR_ARGUMENT;
}

static void put64(uint8_t *buf, size_t *off, uint64_t value)
{
	memcpy(buf + *off, &value, sizeof(value));
	*off += sizeof(value);
}

static void put32(uint8_t *buf, size_t *off, uint32_t value)
{
	memcpy(buf + *off, &value, sizeof(value));
	*off += sizeof(value);
}

static int is_zero(const uint8_t digest[RKV_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < RKV_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 0;
	}
	return 1;
}

static int valid_tier(uint32_t tier)
{
	return tier >= RKV_TIER_HBM && tier <= RKV_TIER_NETWORK;
}

int rkv_digest_request(const struct rkv_request *request,
			      uint8_t digest[RKV_DIGEST_SIZE])
{
	uint8_t canonical[8U * 19U + 4U * 4U + RKV_DIGEST_SIZE * 3U];
	const void *parts[1];
	size_t lengths[1];
	size_t offset = 0U;

	if (request == NULL || digest == NULL)
		return RKV_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	put64(canonical, &offset, request->cache_id);
	put64(canonical, &offset, request->model_id);
	put64(canonical, &offset, request->objective_id);
	put64(canonical, &offset, request->trace_id);
	put64(canonical, &offset, request->agent_id);
	put64(canonical, &offset, request->tenant_id);
	put64(canonical, &offset, request->task_generation);
	put64(canonical, &offset, request->session_generation);
	put64(canonical, &offset, request->world_generation);
	put64(canonical, &offset, request->model_generation);
	put64(canonical, &offset, request->request_sequence);
	put64(canonical, &offset, request->issued_at_ns);
	put64(canonical, &offset, request->observed_at_ns);
	put64(canonical, &offset, request->deadline_ns);
	put64(canonical, &offset, request->bytes);
	put64(canonical, &offset, request->page_count);
	put64(canonical, &offset, request->locality_domain);
	put64(canonical, &offset, request->bandwidth_bytes_s);
	put64(canonical, &offset, request->latency_ns);
	put32(canonical, &offset, request->source_tier);
	put32(canonical, &offset, request->target_tier);
	put32(canonical, &offset, request->pressure_ppm);
	put32(canonical, &offset, request->flags);
	memcpy(canonical + offset, request->content_digest, RKV_DIGEST_SIZE);
	offset += RKV_DIGEST_SIZE;
	memcpy(canonical + offset, request->metadata_digest, RKV_DIGEST_SIZE);
	offset += RKV_DIGEST_SIZE;
	memcpy(canonical + offset, request->provenance_digest, RKV_DIGEST_SIZE);
	offset += RKV_DIGEST_SIZE;
	parts[0] = canonical;
	lengths[0] = offset;
	return rkv_hash(parts, lengths, 1U, digest);
}

static int digest_receipt(const struct rkv_receipt *receipt,
			  uint8_t digest[RKV_DIGEST_SIZE])
{
	uint8_t canonical[8U * 4U + 4U * 3U + RKV_DIGEST_SIZE * 2U];
	const void *parts[1];
	size_t lengths[1];
	size_t offset = 0U;

	if (receipt == NULL || digest == NULL)
		return RKV_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	put64(canonical, &offset, receipt->receipt_id);
	put64(canonical, &offset, receipt->cache_id);
	put64(canonical, &offset, receipt->receipt_sequence);
	put64(canonical, &offset, receipt->observed_generation);
	put32(canonical, &offset, receipt->state);
	put32(canonical, &offset, receipt->source_tier);
	put32(canonical, &offset, receipt->target_tier);
	memcpy(canonical + offset, receipt->request_digest, RKV_DIGEST_SIZE);
	offset += RKV_DIGEST_SIZE;
	memcpy(canonical + offset, receipt->transition_digest, RKV_DIGEST_SIZE);
	offset += RKV_DIGEST_SIZE;
	parts[0] = canonical;
	lengths[0] = offset;
	return rkv_hash(parts, lengths, 1U, digest);
}

static struct rkv_record *find_record(struct rkv_service *service,
					uint64_t cache_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.cache_id == cache_id)
			return &service->records[i];
	}
	return NULL;
}

static const struct rkv_record *find_record_const(const struct rkv_service *service,
						  uint64_t cache_id)
{
	size_t i;

	for (i = 0U; i < service->record_count; ++i) {
		if (service->records[i].request.cache_id == cache_id)
			return &service->records[i];
	}
	return NULL;
}

static int policy_match(const struct rkv_request *request,
				const struct rkv_policy *policy)
{
	uint64_t age;
	uint64_t latency;

	if (request == NULL || policy == NULL)
		return RKV_ERR_ARGUMENT;
	if (request->cache_id == 0U || request->model_id == 0U ||
	    request->objective_id == 0U || request->trace_id == 0U ||
	    request->agent_id == 0U || request->tenant_id == 0U ||
	    request->task_generation == 0U || request->session_generation == 0U ||
	    request->world_generation == 0U || request->model_generation == 0U ||
	    request->request_sequence == 0U || request->issued_at_ns == 0U ||
	    request->observed_at_ns < request->issued_at_ns ||
	    request->deadline_ns < request->observed_at_ns ||
	    request->bytes == 0U || request->page_count == 0U ||
	    request->locality_domain == 0U || request->bandwidth_bytes_s == 0U ||
	    request->latency_ns == 0U || request->pressure_ppm > 1000000U ||
	    !valid_tier(request->source_tier) || !valid_tier(request->target_tier) ||
	    (request->flags & ~RKV_FLAGS_ALL) != 0U ||
	    is_zero(request->content_digest) || is_zero(request->metadata_digest) ||
	    is_zero(request->provenance_digest))
		return RKV_ERR_ARGUMENT;
	if (policy->now_ns < request->observed_at_ns ||
	    policy->now_ns > request->deadline_ns)
		return RKV_ERR_EXPIRED;
	age = policy->now_ns - request->observed_at_ns;
	latency = request->observed_at_ns - request->issued_at_ns;
	if ((policy->max_age_ns != 0U && age > policy->max_age_ns) ||
	    (policy->max_latency_ns != 0U && latency > policy->max_latency_ns))
		return RKV_ERR_EXPIRED;
	if ((policy->expected_model_id != 0U && request->model_id != policy->expected_model_id) ||
	    (policy->expected_objective_id != 0U && request->objective_id != policy->expected_objective_id) ||
	    (policy->expected_trace_id != 0U && request->trace_id != policy->expected_trace_id) ||
	    (policy->expected_agent_id != 0U && request->agent_id != policy->expected_agent_id) ||
	    (policy->expected_tenant_id != 0U && request->tenant_id != policy->expected_tenant_id) ||
	    (policy->expected_task_generation != 0U && request->task_generation != policy->expected_task_generation) ||
	    (policy->expected_session_generation != 0U && request->session_generation != policy->expected_session_generation) ||
	    (policy->expected_world_generation != 0U && request->world_generation != policy->expected_world_generation) ||
	    (policy->expected_model_generation != 0U && request->model_generation != policy->expected_model_generation) ||
	    (policy->expected_sequence != 0U && request->request_sequence != policy->expected_sequence))
		return RKV_ERR_GENERATION;
	if (policy->allowed_tier_mask != 0U &&
	    (!(policy->allowed_tier_mask & RKV_TIER_MASK(request->source_tier)) ||
	     !(policy->allowed_tier_mask & RKV_TIER_MASK(request->target_tier))))
		return RKV_ERR_POLICY;
	if (policy->require_provenance &&
	    (!(request->flags & RKV_FLAG_VERIFIED) ||
	     is_zero(request->provenance_digest)))
		return RKV_ERR_POLICY;
	return RKV_OK;
}

int rkv_verify_receipt(const struct rkv_receipt *receipt)
{
	uint8_t digest[RKV_DIGEST_SIZE];

	if (receipt == NULL || receipt->receipt_id == 0U || receipt->cache_id == 0U ||
	    receipt->receipt_sequence == 0U || !valid_tier(receipt->source_tier) ||
	    !valid_tier(receipt->target_tier) || is_zero(receipt->request_digest))
		return RKV_ERR_ARGUMENT;
	if (digest_receipt(receipt, digest) != RKV_OK ||
	    memcmp(digest, receipt->receipt_digest, RKV_DIGEST_SIZE) != 0)
		return RKV_ERR_TAMPER;
	return RKV_OK;
}

int rkv_init(struct rkv_service *service)
{
	if (service == NULL)
		return RKV_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->next_cache_id = 1U;
	service->next_receipt_id = 1U;
	return RKV_OK;
}

int rkv_admit(struct rkv_service *service, const struct rkv_request *request,
		      const struct rkv_policy *policy, struct rkv_receipt *out)
{
	struct rkv_record *record;
	struct rkv_request candidate;
	uint8_t request_digest[RKV_DIGEST_SIZE];
	int result;

	if (service == NULL || request == NULL || policy == NULL || out == NULL)
		return RKV_ERR_ARGUMENT;
	if (service->record_count >= RKV_MAX_RECORDS)
		return RKV_ERR_FULL;
	candidate = *request;
	if (candidate.cache_id == 0U)
		candidate.cache_id = service->next_cache_id;
	if (candidate.request_sequence == 0U)
		candidate.request_sequence = service->record_count + 1U;
	if (find_record_const(service, candidate.cache_id) != NULL)
		return RKV_ERR_REPLAY;
	result = policy_match(&candidate, policy);
	if (result != RKV_OK)
		return result;
	if (rkv_digest_request(&candidate, request_digest) != RKV_OK)
		return RKV_ERR_TAMPER;
	record = &service->records[service->record_count++];
	memset(record, 0, sizeof(*record));
	record->request = candidate;
	record->state = RKV_STATE_RESIDENT;
	record->receipt.receipt_id = service->next_receipt_id++;
	record->receipt.cache_id = candidate.cache_id;
	record->receipt.receipt_sequence = ++service->receipt_sequence;
	record->receipt.observed_generation = candidate.model_generation;
	record->receipt.state = record->state;
	record->receipt.source_tier = candidate.source_tier;
	record->receipt.target_tier = candidate.target_tier;
	memcpy(record->receipt.request_digest, request_digest, RKV_DIGEST_SIZE);
	memset(record->receipt.transition_digest, 0xA5, RKV_DIGEST_SIZE);
	if (digest_receipt(&record->receipt, record->receipt.receipt_digest) != RKV_OK)
		return RKV_ERR_TAMPER;
	if (candidate.cache_id >= service->next_cache_id)
		service->next_cache_id = candidate.cache_id + 1U;
	*out = record->receipt;
	return RKV_OK;
}

int rkv_transition(struct rkv_service *service, uint64_t cache_id,
			   uint32_t target_tier, uint64_t observed_generation,
			   uint64_t observed_at_ns, uint64_t bytes_moved,
			   const uint8_t transfer_digest[RKV_DIGEST_SIZE],
			   const struct rkv_policy *policy, struct rkv_receipt *out)
{
	struct rkv_record *record;
	struct rkv_receipt receipt;
	uint64_t old_tier;

	if (service == NULL || cache_id == 0U || !valid_tier(target_tier) ||
	    observed_generation == 0U || observed_at_ns == 0U || bytes_moved == 0U ||
	    transfer_digest == NULL || policy == NULL || out == NULL)
		return RKV_ERR_ARGUMENT;
	if (!policy->authority_granted)
		return RKV_ERR_AUTHORITY;
	if (policy->expected_model_generation != 0U &&
	    observed_generation != policy->expected_model_generation)
		return RKV_ERR_GENERATION;
	if (policy->allowed_tier_mask != 0U &&
	    !(policy->allowed_tier_mask & RKV_TIER_MASK(target_tier)))
		return RKV_ERR_POLICY;
	if (policy->now_ns < observed_at_ns)
		return RKV_ERR_EXPIRED;
	record = find_record(service, cache_id);
	if (record == NULL)
		return RKV_ERR_NOT_FOUND;
	if (record->state != RKV_STATE_RESIDENT && record->state != RKV_STATE_MIGRATING)
		return RKV_ERR_STATE;
	if (record->request.model_generation != observed_generation)
		return RKV_ERR_GENERATION;
	if (policy->expected_sequence != 0U &&
	    record->request.request_sequence != policy->expected_sequence)
		return RKV_ERR_GENERATION;
	if (bytes_moved > record->request.bytes)
		return RKV_ERR_CAPACITY;
	if (is_zero(transfer_digest))
		return RKV_ERR_ARGUMENT;
	old_tier = record->request.target_tier;
	record->state = RKV_STATE_MIGRATING;
	record->request.source_tier = (uint32_t)old_tier;
	record->request.target_tier = target_tier;
	record->request.observed_at_ns = observed_at_ns;
	record->request.request_sequence++;
	memset(&receipt, 0, sizeof(receipt));
	receipt.receipt_id = service->next_receipt_id++;
	receipt.cache_id = cache_id;
	receipt.receipt_sequence = ++service->receipt_sequence;
	receipt.observed_generation = observed_generation;
	receipt.state = RKV_STATE_RESIDENT;
	receipt.source_tier = (uint32_t)old_tier;
	receipt.target_tier = target_tier;
	if (rkv_digest_request(&record->request, receipt.request_digest) != RKV_OK)
		return RKV_ERR_TAMPER;
	memcpy(receipt.transition_digest, transfer_digest, RKV_DIGEST_SIZE);
	if (digest_receipt(&receipt, receipt.receipt_digest) != RKV_OK)
		return RKV_ERR_TAMPER;
	record->state = RKV_STATE_RESIDENT;
	record->receipt = receipt;
	*out = receipt;
	return RKV_OK;
}

int rkv_query(const struct rkv_service *service, uint64_t cache_id,
		      struct rkv_record *out)
{
	const struct rkv_record *record;

	if (service == NULL || cache_id == 0U || out == NULL)
		return RKV_ERR_ARGUMENT;
	record = find_record_const(service, cache_id);
	if (record == NULL)
		return RKV_ERR_NOT_FOUND;
	*out = *record;
	return RKV_OK;
}
