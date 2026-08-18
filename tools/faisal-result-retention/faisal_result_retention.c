#include "faisal_result_retention.h"

#include <openssl/evp.h>
#include <string.h>

static int rdr_hash_parts(const void *const *parts, const size_t *lengths,
			  size_t count, uint8_t output[RDR_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	size_t i;
	unsigned int length = 0U;

	if (parts == NULL || lengths == NULL || output == NULL || count == 0U)
		return RDR_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return RDR_ERR_FULL;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto error;
	for (i = 0U; i < count; ++i) {
		if (parts[i] == NULL && lengths[i] != 0U)
			goto error;
		if (EVP_DigestUpdate(ctx, parts[i], lengths[i]) != 1)
			goto error;
	}
	if (EVP_DigestFinal_ex(ctx, output, &length) != 1 ||
	    length != RDR_DIGEST_SIZE)
		goto error;
	EVP_MD_CTX_free(ctx);
	return RDR_OK;
error:
	EVP_MD_CTX_free(ctx);
	return RDR_ERR_ARGUMENT;
}

static void rdr_put_u64(uint8_t *buffer, size_t *offset, uint64_t value)
{
	memcpy(buffer + *offset, &value, sizeof(value));
	*offset += sizeof(value);
}

static void rdr_put_u32(uint8_t *buffer, size_t *offset, uint32_t value)
{
	memcpy(buffer + *offset, &value, sizeof(value));
	*offset += sizeof(value);
}

static int rdr_is_zero(const uint8_t digest[RDR_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < RDR_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 0;
	}
	return 1;
}

static int rdr_event_kind_valid(uint32_t kind)
{
	return kind == RDR_EVENT_RESULT || kind == RDR_EVENT_COMMIT ||
	       kind == RDR_EVENT_DISCARD;
}

static int rdr_digest_chain(const uint8_t previous[RDR_DIGEST_SIZE],
				const uint8_t event_digest[RDR_DIGEST_SIZE],
				uint8_t output[RDR_DIGEST_SIZE])
{
	const void *parts[2];
	const size_t lengths[2] = { RDR_DIGEST_SIZE, RDR_DIGEST_SIZE };

	if (previous == NULL || event_digest == NULL || output == NULL)
		return RDR_ERR_ARGUMENT;
	parts[0] = previous;
	parts[1] = event_digest;
	return rdr_hash_parts(parts, lengths, 2U, output);
}

int rdr_digest_event(const struct rdr_event *event,
			     uint8_t digest[RDR_DIGEST_SIZE])
{
	uint8_t canonical[8U * 15U + 4U * 2U + RDR_DIGEST_SIZE * 5U];
	size_t offset = 0U;
	const void *parts[1];
	size_t lengths[1] = { 0U };

	if (event == NULL || digest == NULL)
		return RDR_ERR_ARGUMENT;
	memset(canonical, 0, sizeof(canonical));
	rdr_put_u64(canonical, &offset, event->event_id);
	rdr_put_u64(canonical, &offset, event->sequence);
	rdr_put_u64(canonical, &offset, event->result_id);
	rdr_put_u64(canonical, &offset, event->receipt_id);
	rdr_put_u64(canonical, &offset, event->tool_id);
	rdr_put_u64(canonical, &offset, event->tool_call_id);
	rdr_put_u64(canonical, &offset, event->objective_id);
	rdr_put_u64(canonical, &offset, event->trace_id);
	rdr_put_u64(canonical, &offset, event->agent_id);
	rdr_put_u64(canonical, &offset, event->tenant_id);
	rdr_put_u64(canonical, &offset, event->task_generation);
	rdr_put_u64(canonical, &offset, event->session_generation);
	rdr_put_u64(canonical, &offset, event->world_generation);
	rdr_put_u64(canonical, &offset, event->event_at_ns);
	rdr_put_u64(canonical, &offset, event->expires_at_ns);
	rdr_put_u32(canonical, &offset, event->event_kind);
	rdr_put_u32(canonical, &offset, event->flags);
	memcpy(canonical + offset, event->result_digest, RDR_DIGEST_SIZE);
	offset += RDR_DIGEST_SIZE;
	memcpy(canonical + offset, event->payload_digest, RDR_DIGEST_SIZE);
	offset += RDR_DIGEST_SIZE;
	memcpy(canonical + offset, event->provenance_digest, RDR_DIGEST_SIZE);
	offset += RDR_DIGEST_SIZE;
	memcpy(canonical + offset, event->transition_digest, RDR_DIGEST_SIZE);
	offset += RDR_DIGEST_SIZE;
	memcpy(canonical + offset, event->previous_chain_digest, RDR_DIGEST_SIZE);
	offset += RDR_DIGEST_SIZE;
	parts[0] = canonical;
	lengths[0] = offset;
	return rdr_hash_parts(parts, lengths, 1U, digest);
}

static struct rdr_projection *rdr_find_projection(struct rdr_service *service,
						 uint64_t result_id)
{
	size_t i;

	for (i = 0U; i < service->projection_count; ++i) {
		if (service->projections[i].result_id == result_id)
			return &service->projections[i];
	}
	return NULL;
}

static const struct rdr_projection *rdr_find_projection_const(
		const struct rdr_service *service, uint64_t result_id)
{
	size_t i;

	for (i = 0U; i < service->projection_count; ++i) {
		if (service->projections[i].result_id == result_id)
			return &service->projections[i];
	}
	return NULL;
}

static int rdr_policy_match(const struct rdr_event *event,
				const struct rdr_policy *policy)
{
	uint64_t age;

	if (event == NULL || policy == NULL)
		return RDR_ERR_ARGUMENT;
	if (!rdr_event_kind_valid(event->event_kind) ||
	    (event->flags & ~RDR_FLAGS_ALL) != 0U ||
	    event->event_id == 0U || event->sequence == 0U ||
	    event->result_id == 0U || event->objective_id == 0U ||
	    event->trace_id == 0U || event->agent_id == 0U ||
	    event->tenant_id == 0U || event->task_generation == 0U ||
	    event->session_generation == 0U || event->world_generation == 0U ||
	    event->event_at_ns == 0U || event->expires_at_ns == 0U ||
	    event->event_at_ns > event->expires_at_ns)
		return RDR_ERR_ARGUMENT;
	if (policy->now_ns < event->event_at_ns ||
	    policy->now_ns > event->expires_at_ns)
		return RDR_ERR_EXPIRED;
	age = policy->now_ns - event->event_at_ns;
	if (policy->max_age_ns != 0U && age > policy->max_age_ns)
		return RDR_ERR_EXPIRED;
	if ((policy->expected_objective_id != 0U &&
	     event->objective_id != policy->expected_objective_id) ||
	    (policy->expected_trace_id != 0U &&
	     event->trace_id != policy->expected_trace_id) ||
	    (policy->expected_agent_id != 0U &&
	     event->agent_id != policy->expected_agent_id) ||
	    (policy->expected_tenant_id != 0U &&
	     event->tenant_id != policy->expected_tenant_id) ||
	    (policy->expected_task_generation != 0U &&
	     event->task_generation != policy->expected_task_generation) ||
	    (policy->expected_session_generation != 0U &&
	     event->session_generation != policy->expected_session_generation) ||
	    (policy->expected_world_generation != 0U &&
	     event->world_generation != policy->expected_world_generation) ||
	    (policy->expected_next_sequence != 0U &&
	     event->sequence != policy->expected_next_sequence))
		return RDR_ERR_GENERATION;
	if (policy->require_verified && !(event->flags & RDR_FLAG_VERIFIED))
		return RDR_ERR_POLICY;
	if (event->event_kind != RDR_EVENT_RESULT &&
	    rdr_is_zero(event->transition_digest))
		return RDR_ERR_ARGUMENT;
	if (rdr_is_zero(event->result_digest) ||
	    rdr_is_zero(event->payload_digest) ||
	    rdr_is_zero(event->provenance_digest))
		return RDR_ERR_ARGUMENT;
	return RDR_OK;
}

int rdr_verify_event(const struct rdr_event *event,
			const uint8_t previous_chain[RDR_DIGEST_SIZE])
{
	uint8_t event_digest[RDR_DIGEST_SIZE];
	uint8_t chain_digest[RDR_DIGEST_SIZE];

	if (event == NULL || previous_chain == NULL)
		return RDR_ERR_ARGUMENT;
	if (rdr_policy_match(event, &(struct rdr_policy){
		.now_ns = event->event_at_ns,
		.require_verified = 0U
	}) != RDR_OK)
		return RDR_ERR_ARGUMENT;
	if (memcmp(event->previous_chain_digest, previous_chain,
		   RDR_DIGEST_SIZE) != 0)
		return RDR_ERR_TAMPER;
	if (rdr_digest_event(event, event_digest) != RDR_OK ||
	    memcmp(event->event_digest, event_digest, RDR_DIGEST_SIZE) != 0)
		return RDR_ERR_TAMPER;
	if (rdr_digest_chain(previous_chain, event_digest, chain_digest) != RDR_OK ||
	    memcmp(event->chain_digest, chain_digest, RDR_DIGEST_SIZE) != 0)
		return RDR_ERR_TAMPER;
	return RDR_OK;
}

static int rdr_event_id_used(const struct rdr_service *service,
				     uint64_t event_id)
{
	size_t i;

	for (i = 0U; i < service->event_count; ++i) {
		if (service->events[i].event_id == event_id)
			return 1;
	}
	return 0;
}

static int rdr_result_id_used(const struct rdr_service *service,
				      uint64_t result_id)
{
	return rdr_find_projection_const(service, result_id) != NULL;
}

static int rdr_install_projection(struct rdr_service *service,
					 const struct rdr_event *event)
{
	struct rdr_projection *projection;

	if (service->projection_count >= RDR_MAX_PROJECTIONS)
		return RDR_ERR_FULL;
	if (rdr_result_id_used(service, event->result_id))
		return RDR_ERR_REPLAY;
	projection = &service->projections[service->projection_count++];
	memset(projection, 0, sizeof(*projection));
	projection->result_id = event->result_id;
	projection->receipt_id = event->receipt_id;
	projection->last_sequence = event->sequence;
	projection->task_generation = event->task_generation;
	projection->session_generation = event->session_generation;
	projection->world_generation = event->world_generation;
	projection->state = RDR_STATE_RETAINED;
	memcpy(projection->result_digest, event->result_digest, RDR_DIGEST_SIZE);
	memcpy(projection->payload_digest, event->payload_digest, RDR_DIGEST_SIZE);
	memcpy(projection->provenance_digest, event->provenance_digest,
	       RDR_DIGEST_SIZE);
	return RDR_OK;
}

static int rdr_apply_transition(struct rdr_service *service,
					const struct rdr_event *event)
{
	struct rdr_projection *projection;

	projection = rdr_find_projection(service, event->result_id);
	if (projection == NULL)
		return RDR_ERR_NOT_FOUND;
	if (event->event_kind == RDR_EVENT_COMMIT) {
		if (projection->state != RDR_STATE_RETAINED ||
		    !(event->flags & RDR_FLAG_AUTHORITY) ||
		    !(event->flags & RDR_FLAG_INDEPENDENT_VERIFIER))
			return RDR_ERR_AUTHORITY;
		projection->state = RDR_STATE_COMMITTED;
	} else if (event->event_kind == RDR_EVENT_DISCARD) {
		if (projection->state != RDR_STATE_RETAINED)
			return RDR_ERR_STATE;
		projection->state = RDR_STATE_DISCARDED;
	} else {
		return RDR_ERR_STATE;
	}
	projection->last_sequence = event->sequence;
	projection->replay_count++;
	return RDR_OK;
}

static int rdr_append_internal(struct rdr_service *service,
				       struct rdr_event *event)
{
	uint8_t previous[RDR_DIGEST_SIZE];
	int result;

	if (service == NULL || event == NULL)
		return RDR_ERR_ARGUMENT;
	if (service->event_count >= RDR_MAX_EVENTS)
		return RDR_ERR_FULL;
	if (event->sequence != service->next_sequence ||
	    rdr_event_id_used(service, event->event_id))
		return RDR_ERR_SEQUENCE;
	memcpy(previous, service->tail_chain_digest, RDR_DIGEST_SIZE);
	memcpy(event->previous_chain_digest, previous, RDR_DIGEST_SIZE);
	if (rdr_digest_event(event, event->event_digest) != RDR_OK ||
	    rdr_digest_chain(previous, event->event_digest,
			     event->chain_digest) != RDR_OK)
		return RDR_ERR_TAMPER;
	service->events[service->event_count++] = *event;
	memcpy(service->tail_chain_digest, event->chain_digest, RDR_DIGEST_SIZE);
	service->next_sequence++;
	service->next_event_id = event->event_id + 1U;
	result = event->event_kind == RDR_EVENT_RESULT ?
		rdr_install_projection(service, event) :
		rdr_apply_transition(service, event);
	if (result != RDR_OK) {
		service->event_count--;
		if (event->event_kind == RDR_EVENT_RESULT && service->projection_count != 0U)
			service->projection_count--;
		service->next_sequence--;
		memset(service->tail_chain_digest, 0, RDR_DIGEST_SIZE);
		if (service->event_count != 0U)
			memcpy(service->tail_chain_digest,
			       service->events[service->event_count - 1U].chain_digest,
			       RDR_DIGEST_SIZE);
		service->next_event_id = 1U;
		if (service->event_count != 0U)
			service->next_event_id =
			service->events[service->event_count - 1U].event_id + 1U;
		return result;
	}
	return RDR_OK;
}

static void rdr_allocate_ids(struct rdr_service *service,
				      struct rdr_event *event)
{
	if (event->event_id == 0U)
		event->event_id = service->next_event_id == 0U ? 1U :
			service->next_event_id;
	if (event->sequence == 0U)
		event->sequence = service->next_sequence;
}

int rdr_init(struct rdr_service *service)
{
	if (service == NULL)
		return RDR_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->next_event_id = 1U;
	service->next_sequence = 1U;
	return RDR_OK;
}

int rdr_append_result(struct rdr_service *service,
			      const struct rdr_event *event,
			      const struct rdr_policy *policy,
			      struct rdr_event *out)
{
	struct rdr_event candidate;
	int result;

	if (service == NULL || event == NULL || policy == NULL || out == NULL)
		return RDR_ERR_ARGUMENT;
	candidate = *event;
	rdr_allocate_ids(service, &candidate);
	if (candidate.event_kind != RDR_EVENT_RESULT)
		return RDR_ERR_STATE;
	result = rdr_policy_match(&candidate, policy);
	if (result != RDR_OK)
		return result;
	if (policy->require_verified && !(candidate.flags & RDR_FLAG_VERIFIED))
		return RDR_ERR_POLICY;
	if (rdr_append_internal(service, &candidate) != RDR_OK)
		return RDR_ERR_SEQUENCE;
	*out = candidate;
	return RDR_OK;
}

int rdr_append_transition(struct rdr_service *service, uint64_t result_id,
				  uint32_t event_kind,
				  const uint8_t transition_digest[RDR_DIGEST_SIZE],
				  const struct rdr_policy *policy,
				  struct rdr_event *out)
{
	const struct rdr_projection *projection;
	struct rdr_event candidate;
	int result;

	if (service == NULL || result_id == 0U || transition_digest == NULL ||
	    policy == NULL || out == NULL)
		return RDR_ERR_ARGUMENT;
	if (event_kind != RDR_EVENT_COMMIT && event_kind != RDR_EVENT_DISCARD)
		return RDR_ERR_STATE;
	projection = rdr_find_projection_const(service, result_id);
	if (projection == NULL)
		return RDR_ERR_NOT_FOUND;
	memset(&candidate, 0, sizeof(candidate));
	candidate.result_id = projection->result_id;
	candidate.receipt_id = projection->receipt_id;
	candidate.objective_id = policy->expected_objective_id;
	candidate.trace_id = policy->expected_trace_id;
	candidate.agent_id = policy->expected_agent_id;
	candidate.tenant_id = policy->expected_tenant_id;
	candidate.task_generation = projection->task_generation;
	candidate.session_generation = projection->session_generation;
	candidate.world_generation = projection->world_generation;
	candidate.event_at_ns = policy->now_ns;
	candidate.expires_at_ns = policy->now_ns + (policy->max_age_ns == 0U ? 1U :
		policy->max_age_ns);
	candidate.event_kind = event_kind;
	candidate.flags = RDR_FLAG_VERIFIED;
	if (event_kind == RDR_EVENT_COMMIT) {
		if (!policy->authority_granted || !policy->independent_verifier)
			return RDR_ERR_AUTHORITY;
		candidate.flags |= RDR_FLAG_AUTHORITY | RDR_FLAG_INDEPENDENT_VERIFIER;
	}
	memcpy(candidate.result_digest, projection->result_digest, RDR_DIGEST_SIZE);
	memcpy(candidate.payload_digest, projection->payload_digest, RDR_DIGEST_SIZE);
	memcpy(candidate.provenance_digest, projection->provenance_digest,
	       RDR_DIGEST_SIZE);
	memcpy(candidate.transition_digest, transition_digest, RDR_DIGEST_SIZE);
	rdr_allocate_ids(service, &candidate);
	result = rdr_policy_match(&candidate, policy);
	if (result != RDR_OK)
		return result;
	result = rdr_append_internal(service, &candidate);
	if (result != RDR_OK)
		return result;
	*out = candidate;
	return RDR_OK;
}

int rdr_recover(struct rdr_service *service, const struct rdr_event *events,
			size_t event_count,
			const uint8_t expected_tail[RDR_DIGEST_SIZE])
{
	size_t i;
	uint8_t previous[RDR_DIGEST_SIZE];

	if (service == NULL || (events == NULL && event_count != 0U) ||
	    event_count > RDR_MAX_EVENTS)
		return RDR_ERR_ARGUMENT;
	if (rdr_init(service) != RDR_OK)
		return RDR_ERR_ARGUMENT;
	memset(previous, 0, sizeof(previous));
	for (i = 0U; i < event_count; ++i) {
		const struct rdr_event *event = &events[i];
		int result;

		if (event->sequence != i + 1U)
			return RDR_ERR_SEQUENCE;
		result = rdr_verify_event(event, previous);
		if (result != RDR_OK)
			return result;
		if (event->event_kind == RDR_EVENT_RESULT)
			result = rdr_install_projection(service, event);
		else
			result = rdr_apply_transition(service, event);
		if (result != RDR_OK)
			return result;
		if (service->event_count >= RDR_MAX_EVENTS)
			return RDR_ERR_FULL;
		service->events[service->event_count++] = *event;
		memcpy(previous, event->chain_digest, RDR_DIGEST_SIZE);
	}
	memcpy(service->tail_chain_digest, previous, RDR_DIGEST_SIZE);
	service->next_sequence = event_count + 1U;
	service->next_event_id = 1U;
	for (i = 0U; i < event_count; ++i) {
		if (service->events[i].event_id >= service->next_event_id)
			service->next_event_id = service->events[i].event_id + 1U;
	}
	if (expected_tail != NULL && !rdr_is_zero(expected_tail) &&
	    memcmp(expected_tail, service->tail_chain_digest, RDR_DIGEST_SIZE) != 0)
		return RDR_ERR_TAMPER;
	return RDR_OK;
}

int rdr_replay_since(const struct rdr_service *service,
			     const struct rdr_replay_cursor *cursor,
			     struct rdr_event *out, size_t capacity, size_t *out_count)
{
	size_t i;
	size_t count = 0U;

	if (service == NULL || cursor == NULL || out == NULL || out_count == NULL ||
	    capacity == 0U || cursor->max_events == 0U)
		return RDR_ERR_ARGUMENT;
	for (i = 0U; i < service->event_count; ++i) {
		const struct rdr_event *event = &service->events[i];

		if (event->sequence <= cursor->after_sequence)
			continue;
		if ((cursor->expected_task_generation != 0U &&
		     event->task_generation != cursor->expected_task_generation) ||
		    (cursor->expected_session_generation != 0U &&
		     event->session_generation != cursor->expected_session_generation) ||
		    (cursor->expected_world_generation != 0U &&
		     event->world_generation != cursor->expected_world_generation))
			return RDR_ERR_GENERATION;
		if (count >= capacity || count >= cursor->max_events)
			return RDR_ERR_FULL;
		out[count++] = *event;
	}
	*out_count = count;
	return RDR_OK;
}

int rdr_query(const struct rdr_service *service, uint64_t result_id,
		      struct rdr_projection *out)
{
	const struct rdr_projection *projection;

	if (service == NULL || result_id == 0U || out == NULL)
		return RDR_ERR_ARGUMENT;
	projection = rdr_find_projection_const(service, result_id);
	if (projection == NULL)
		return RDR_ERR_NOT_FOUND;
	*out = *projection;
	return RDR_OK;
}
