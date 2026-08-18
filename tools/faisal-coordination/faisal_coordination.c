#include "faisal_coordination.h"

#include <openssl/evp.h>

#include <string.h>

struct mac_hash {
	EVP_MD_CTX *ctx;
};

static int mac_hash_init(struct mac_hash *hash)
{
	if (hash == NULL)
		return MAC_ERR_ARGUMENT;
	hash->ctx = EVP_MD_CTX_new();
	if (hash->ctx == NULL ||
	    EVP_DigestInit_ex(hash->ctx, EVP_sha256(), NULL) != 1) {
		if (hash->ctx != NULL)
			EVP_MD_CTX_free(hash->ctx);
		hash->ctx = NULL;
		return MAC_ERR_ARGUMENT;
	}
	return MAC_OK;
}

static void mac_hash_u32(struct mac_hash *hash, uint32_t value)
{
	uint8_t bytes[4];

	bytes[0] = (uint8_t)(value >> 24);
	bytes[1] = (uint8_t)(value >> 16);
	bytes[2] = (uint8_t)(value >> 8);
	bytes[3] = (uint8_t)value;
	(void)EVP_DigestUpdate(hash->ctx, bytes, sizeof(bytes));
}

static void mac_hash_i32(struct mac_hash *hash, int32_t value)
{
	mac_hash_u32(hash, (uint32_t)value);
}

static void mac_hash_u64(struct mac_hash *hash, uint64_t value)
{
	uint8_t bytes[8];
	unsigned int i;

	for (i = 0; i < sizeof(bytes); ++i)
		bytes[i] = (uint8_t)(value >> (56U - (i * 8U)));
	(void)EVP_DigestUpdate(hash->ctx, bytes, sizeof(bytes));
}

static void mac_hash_bytes(struct mac_hash *hash, const void *data, size_t size)
{
	if (size != 0U)
		(void)EVP_DigestUpdate(hash->ctx, data, size);
}

static void mac_hash_text(struct mac_hash *hash, const char *text, size_t max)
{
	size_t length;

	length = 0U;
	while (length < max && text[length] != '\0')
		++length;
	mac_hash_u64(hash, length);
	mac_hash_bytes(hash, text, length);
}

static int mac_hash_final(struct mac_hash *hash, uint8_t output[MAC_DIGEST_SIZE])
{
	unsigned int length = 0U;
	int result;

	if (hash == NULL || hash->ctx == NULL || output == NULL)
		return MAC_ERR_ARGUMENT;
	result = EVP_DigestFinal_ex(hash->ctx, output, &length);
	EVP_MD_CTX_free(hash->ctx);
	hash->ctx = NULL;
	if (result != 1 || length != MAC_DIGEST_SIZE)
		return MAC_ERR_ARGUMENT;
	return MAC_OK;
}

static int mac_digest_delegation(const struct mac_delegation *request,
				 uint8_t output[MAC_DIGEST_SIZE])
{
	struct mac_hash hash;
	uint32_t i;

	if (request == NULL || output == NULL ||
	    request->participant_count > MAC_MAX_PARTICIPANTS)
		return MAC_ERR_ARGUMENT;
	if (mac_hash_init(&hash) != MAC_OK)
		return MAC_ERR_ARGUMENT;
	mac_hash_u64(&hash, request->delegation_id);
	mac_hash_u64(&hash, request->objective_id);
	mac_hash_u64(&hash, request->parent_agent_id);
	mac_hash_u64(&hash, request->target_agent_id);
	mac_hash_u64(&hash, request->trace_id);
	mac_hash_u64(&hash, request->parent_generation);
	mac_hash_u64(&hash, request->target_generation);
	mac_hash_u64(&hash, request->coordinator_generation);
	mac_hash_u64(&hash, request->message_sequence);
	mac_hash_u64(&hash, request->created_at_ns);
	mac_hash_u64(&hash, request->deadline_ns);
	mac_hash_u64(&hash, request->lease_until_ns);
	mac_hash_u64(&hash, request->cpu_budget_ns);
	mac_hash_u64(&hash, request->memory_budget_bytes);
	mac_hash_u64(&hash, request->cost_budget_micro);
	mac_hash_u64(&hash, request->required_capability_mask);
	mac_hash_u32(&hash, request->participant_count);
	mac_hash_u32(&hash, request->quorum_required);
	mac_hash_u32(&hash, request->evidence_required);
	mac_hash_u32(&hash, request->flags);
	for (i = 0U; i < request->participant_count; ++i)
		mac_hash_u64(&hash, request->participant_ids[i]);
	mac_hash_bytes(&hash, request->objective_digest,
		       sizeof(request->objective_digest));
	mac_hash_bytes(&hash, request->context_digest,
		       sizeof(request->context_digest));
	mac_hash_text(&hash, request->message, sizeof(request->message));
	return mac_hash_final(&hash, output);
}

static void mac_hash_vote(struct mac_hash *hash, const struct mac_vote *vote)
{
	mac_hash_u64(hash, vote->delegation_id);
	mac_hash_u64(hash, vote->agent_id);
	mac_hash_u64(hash, vote->agent_generation);
	mac_hash_u64(hash, vote->vote_sequence);
	mac_hash_u64(hash, vote->coordinator_generation);
	mac_hash_u32(hash, vote->decision);
	mac_hash_u32(hash, vote->evidence_count);
	mac_hash_u32(hash, vote->challenge_reason);
	mac_hash_bytes(hash, vote->evidence_digest,
		       sizeof(vote->evidence_digest));
	mac_hash_bytes(hash, vote->rationale_digest,
		       sizeof(vote->rationale_digest));
}

static int mac_digest_votes(const struct mac_delegation_state *state,
			    uint8_t output[MAC_DIGEST_SIZE])
{
	struct mac_hash hash;
	uint32_t i;

	if (state == NULL || output == NULL || state->vote_count > MAC_MAX_PARTICIPANTS)
		return MAC_ERR_ARGUMENT;
	if (mac_hash_init(&hash) != MAC_OK)
		return MAC_ERR_ARGUMENT;
	mac_hash_u32(&hash, state->vote_count);
	for (i = 0U; i < state->vote_count; ++i)
		mac_hash_vote(&hash, &state->votes[i]);
	return mac_hash_final(&hash, output);
}

static int mac_digest_receipt(const struct mac_receipt *receipt,
			      uint8_t output[MAC_DIGEST_SIZE])
{
	struct mac_hash hash;

	if (receipt == NULL || output == NULL)
		return MAC_ERR_ARGUMENT;
	if (mac_hash_init(&hash) != MAC_OK)
		return MAC_ERR_ARGUMENT;
	mac_hash_u64(&hash, receipt->receipt_id);
	mac_hash_u64(&hash, receipt->delegation_id);
	mac_hash_u64(&hash, receipt->objective_id);
	mac_hash_u64(&hash, receipt->coordinator_generation);
	mac_hash_u64(&hash, receipt->receipt_sequence);
	mac_hash_u32(&hash, receipt->decision);
	mac_hash_i32(&hash, receipt->status);
	mac_hash_u32(&hash, receipt->approvals);
	mac_hash_u32(&hash, receipt->rejections);
	mac_hash_u32(&hash, receipt->challenges);
	mac_hash_u32(&hash, receipt->evidence_count);
	mac_hash_bytes(&hash, receipt->delegation_digest,
		       sizeof(receipt->delegation_digest));
	mac_hash_bytes(&hash, receipt->votes_digest,
		       sizeof(receipt->votes_digest));
	return mac_hash_final(&hash, output);
}

static int mac_digest_equal(const uint8_t left[MAC_DIGEST_SIZE],
			    const uint8_t right[MAC_DIGEST_SIZE])
{
	return memcmp(left, right, MAC_DIGEST_SIZE) == 0;
}

static int mac_digest_nonzero(const uint8_t digest[MAC_DIGEST_SIZE])
{
	uint32_t i;

	for (i = 0U; i < MAC_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 1;
	}
	return 0;
}

static const struct mac_agent *mac_find_agent_const(
		const struct mac_service *service, uint64_t agent_id)
{
	size_t i;

	for (i = 0U; i < service->agent_count; ++i) {
		if (service->agents[i].agent_id == agent_id)
			return &service->agents[i];
	}
	return NULL;
}

static struct mac_delegation_state *mac_find_delegation(
		struct mac_service *service, uint64_t delegation_id)
{
	size_t i;

	for (i = 0U; i < service->delegation_count; ++i) {
		if (service->delegations[i].request.delegation_id == delegation_id)
			return &service->delegations[i];
	}
	return NULL;
}

static const struct mac_delegation_state *mac_find_delegation_const(
		const struct mac_service *service, uint64_t delegation_id)
{
	size_t i;

	for (i = 0U; i < service->delegation_count; ++i) {
		if (service->delegations[i].request.delegation_id == delegation_id)
			return &service->delegations[i];
	}
	return NULL;
}

static int mac_is_participant(const struct mac_delegation *request,
			       uint64_t agent_id)
{
	uint32_t i;

	for (i = 0U; i < request->participant_count; ++i) {
		if (request->participant_ids[i] == agent_id)
			return 1;
	}
	return 0;
}

static int mac_has_capability(const struct mac_service *service,
			       uint64_t agent_id,
			       uint64_t required_mask,
			       uint32_t minimum_confidence_ppm)
{
	uint64_t available = 0U;
	size_t i;

	for (i = 0U; i < service->capability_count; ++i) {
		const struct mac_capability *capability = &service->capabilities[i];
		if (capability->owner_agent_id != agent_id || !capability->active ||
		    capability->confidence_ppm < minimum_confidence_ppm ||
		    capability->capability_class >= 64U)
			continue;
		available |= 1ULL << capability->capability_class;
	}
	return (available & required_mask) == required_mask;
}

static int mac_validate_policy_request(const struct mac_service *service,
				       const struct mac_delegation *request)
{
	const struct mac_agent *parent;
	const struct mac_agent *target;
	uint32_t i;

	if (request->participant_count == 0U ||
	    request->participant_count > MAC_MAX_PARTICIPANTS ||
	    request->quorum_required == 0U ||
	    request->quorum_required > request->participant_count ||
	    request->evidence_required > MAC_MAX_EVIDENCE ||
	    request->message[MAC_MAX_MESSAGE - 1U] != '\0')
		return MAC_ERR_ARGUMENT;
	if (request->coordinator_generation != service->policy.coordinator_generation ||
	    request->created_at_ns > service->policy.current_time_ns ||
	    request->deadline_ns <= service->policy.current_time_ns ||
	    request->lease_until_ns <= request->created_at_ns ||
	    request->lease_until_ns > request->deadline_ns ||
	    request->lease_until_ns - request->created_at_ns > service->policy.max_lease_ns)
		return MAC_ERR_STALE;
	if (request->cpu_budget_ns > service->policy.max_cpu_budget_ns ||
	    request->memory_budget_bytes > service->policy.max_memory_budget_bytes ||
	    request->cost_budget_micro > service->policy.max_cost_micro)
		return MAC_ERR_BUDGET;
	parent = mac_find_agent_const(service, request->parent_agent_id);
	target = mac_find_agent_const(service, request->target_agent_id);
	if (parent == NULL || target == NULL || !parent->active || !target->active)
		return MAC_ERR_NOT_FOUND;
	if (request->parent_generation != parent->agent_generation ||
	    request->target_generation != target->agent_generation)
		return MAC_ERR_STALE;
	if (!mac_has_capability(service, request->target_agent_id,
				request->required_capability_mask,
				service->policy.minimum_capability_confidence_ppm))
		return MAC_ERR_CAPABILITY;
	for (i = 0U; i < request->participant_count; ++i) {
		const struct mac_agent *participant;
		uint32_t j;
		if (request->participant_ids[i] == 0U)
			return MAC_ERR_ARGUMENT;
		participant = mac_find_agent_const(service, request->participant_ids[i]);
		if (participant == NULL || !participant->active)
			return MAC_ERR_NOT_FOUND;
		for (j = 0U; j < i; ++j) {
			if (request->participant_ids[j] == request->participant_ids[i])
				return MAC_ERR_DUPLICATE;
		}
	}
	if (!mac_is_participant(request, request->target_agent_id))
		return MAC_ERR_POLICY;
	return MAC_OK;
}

static int mac_make_receipt(struct mac_service *service,
			    struct mac_delegation_state *state,
			    int32_t status,
			    struct mac_receipt *out)
{
	struct mac_receipt receipt;

	if (service->receipt_count >= MAC_MAX_RECEIPTS)
		return MAC_ERR_FULL;
	memset(&receipt, 0, sizeof(receipt));
	receipt.receipt_id = service->next_receipt_id++;
	receipt.delegation_id = state->request.delegation_id;
	receipt.objective_id = state->request.objective_id;
	receipt.coordinator_generation = service->policy.coordinator_generation;
	receipt.receipt_sequence = state->vote_count + state->evidence_count + 1U;
	receipt.decision = state->decision;
	receipt.status = status;
	receipt.approvals = state->approval_count;
	receipt.rejections = state->rejection_count;
	receipt.challenges = state->challenge_count;
	receipt.evidence_count = state->evidence_count;
	if (mac_digest_delegation(&state->request, receipt.delegation_digest) != MAC_OK ||
	    mac_digest_votes(state, receipt.votes_digest) != MAC_OK ||
	    mac_digest_receipt(&receipt, receipt.receipt_digest) != MAC_OK)
		return MAC_ERR_ARGUMENT;
	service->receipts[service->receipt_count++] = receipt;
	state->receipt = receipt;
	if (out != NULL)
		*out = receipt;
	return MAC_OK;
}

int mac_init(struct mac_service *service, const struct mac_policy *policy)
{
	if (service == NULL || policy == NULL || policy->coordinator_generation == 0U ||
	    policy->current_time_ns == 0U || policy->max_lease_ns == 0U ||
	    policy->max_cpu_budget_ns == 0U || policy->max_memory_budget_bytes == 0U)
		return MAC_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	if (service->policy.max_lease_ns > MAC_MAX_LEASE_NS)
		service->policy.max_lease_ns = MAC_MAX_LEASE_NS;
	if (service->policy.max_delegations == 0U ||
	    service->policy.max_delegations > MAC_MAX_DELEGATIONS)
		service->policy.max_delegations = MAC_MAX_DELEGATIONS;
	service->next_agent_id = 1U;
	service->next_capability_id = 1U;
	service->next_delegation_id = 1U;
	service->next_receipt_id = 1U;
	return MAC_OK;
}

int mac_register_agent(struct mac_service *service,
		       const struct mac_agent *agent,
		       uint64_t *out_agent_id)
{
	struct mac_agent copy;
	size_t i;

	if (service == NULL || agent == NULL || service->agent_count >= MAC_MAX_AGENTS ||
	    agent->agent_generation == 0U ||
	    !mac_digest_nonzero(agent->identity_digest))
		return MAC_ERR_ARGUMENT;
	for (i = 0U; i < service->agent_count; ++i) {
		if (service->agents[i].agent_id == agent->agent_id ||
		    mac_digest_equal(service->agents[i].identity_digest,
				     agent->identity_digest))
			return MAC_ERR_DUPLICATE;
	}
	copy = *agent;
	if (copy.agent_id == 0U)
		copy.agent_id = service->next_agent_id++;
	else if (copy.agent_id >= service->next_agent_id)
		service->next_agent_id = copy.agent_id + 1U;
	copy.active = 1U;
	service->agents[service->agent_count++] = copy;
	if (out_agent_id != NULL)
		*out_agent_id = copy.agent_id;
	return MAC_OK;
}

int mac_register_capability(struct mac_service *service,
			    const struct mac_capability *capability,
			    uint64_t *out_capability_id)
{
	struct mac_capability copy;
	size_t i;

	if (service == NULL || capability == NULL ||
	    service->capability_count >= MAC_MAX_CAPABILITIES ||
	    capability->capability_class >= 64U || capability->confidence_ppm > MAC_PPM_SCALE ||
	    !mac_digest_nonzero(capability->capability_digest) ||
	    mac_find_agent_const(service, capability->owner_agent_id) == NULL)
		return MAC_ERR_ARGUMENT;
	for (i = 0U; i < service->capability_count; ++i) {
		if (service->capabilities[i].capability_id == capability->capability_id ||
		    mac_digest_equal(service->capabilities[i].capability_digest,
				     capability->capability_digest))
			return MAC_ERR_DUPLICATE;
	}
	copy = *capability;
	if (copy.capability_id == 0U)
		copy.capability_id = service->next_capability_id++;
	else if (copy.capability_id >= service->next_capability_id)
		service->next_capability_id = copy.capability_id + 1U;
	copy.active = 1U;
	service->capabilities[service->capability_count++] = copy;
	if (out_capability_id != NULL)
		*out_capability_id = copy.capability_id;
	return MAC_OK;
}

int mac_negotiate_capability(const struct mac_service *service,
			     uint64_t agent_id,
			     uint64_t required_capability_mask,
			     uint32_t minimum_confidence_ppm)
{
	if (service == NULL || minimum_confidence_ppm > MAC_PPM_SCALE ||
	    mac_find_agent_const(service, agent_id) == NULL)
		return MAC_ERR_ARGUMENT;
	if (!mac_has_capability(service, agent_id, required_capability_mask,
				minimum_confidence_ppm))
		return MAC_ERR_CAPABILITY;
	return MAC_OK;
}

int mac_admit_delegation(struct mac_service *service,
			 const struct mac_delegation *request,
			 struct mac_receipt *out)
{
	struct mac_delegation_state *state;
	struct mac_delegation copy;

	if (service == NULL || request == NULL ||
	    service->delegation_count >= service->policy.max_delegations)
		return MAC_ERR_FULL;
	if (request->delegation_id != 0U &&
	    mac_find_delegation(service, request->delegation_id) != NULL)
		return MAC_ERR_DUPLICATE;
	copy = *request;
	if (copy.delegation_id == 0U)
		copy.delegation_id = service->next_delegation_id++;
	else if (copy.delegation_id >= service->next_delegation_id)
		service->next_delegation_id = copy.delegation_id + 1U;
	{
		int validation = mac_validate_policy_request(service, &copy);
		if (validation != MAC_OK)
			return validation;
	}
	state = &service->delegations[service->delegation_count++];
	memset(state, 0, sizeof(*state));
	state->request = copy;
	if (mac_digest_delegation(&state->request, state->request_digest) != MAC_OK)
		return MAC_ERR_ARGUMENT;
	state->decision = MAC_DECISION_ADMITTED;
	state->status = MAC_OK;
	return mac_make_receipt(service, state, MAC_OK, out);
}

int mac_add_evidence(struct mac_service *service,
			    uint64_t delegation_id,
			    const struct mac_evidence *evidence)
{
	struct mac_delegation_state *state;
	uint32_t i;

	if (service == NULL || evidence == NULL)
		return MAC_ERR_ARGUMENT;
	state = mac_find_delegation(service, delegation_id);
	if (state == NULL)
		return MAC_ERR_NOT_FOUND;
	if (state->decision == MAC_DECISION_COMMITTED ||
	    state->decision == MAC_DECISION_REJECTED ||
	    state->decision == MAC_DECISION_CHALLENGED)
		return MAC_ERR_STATE;
	if (evidence->delegation_id != delegation_id || evidence->agent_id == 0U ||
	    evidence->sequence == 0U || evidence->observed_at_ns > service->policy.current_time_ns ||
	    evidence->verified == 0U ||
	    !mac_digest_nonzero(evidence->evidence_digest) ||
	    !mac_digest_nonzero(evidence->provenance_digest) ||
	    !mac_is_participant(&state->request, evidence->agent_id))
		return MAC_ERR_POLICY;
	if (state->evidence_count >= MAC_MAX_EVIDENCE)
		return MAC_ERR_FULL;
	for (i = 0U; i < state->evidence_count; ++i) {
		if (state->evidence[i].agent_id == evidence->agent_id &&
		    state->evidence[i].sequence == evidence->sequence)
			return MAC_ERR_REPLAY;
	}
	state->evidence[state->evidence_count++] = *evidence;
	state->decision = MAC_DECISION_VOTING;
	return MAC_OK;
}

int mac_vote(struct mac_service *service,
		     uint64_t delegation_id,
		     const struct mac_vote *vote,
		     struct mac_receipt *out)
{
	struct mac_delegation_state *state;
	const struct mac_agent *agent;
	uint32_t i;

	if (service == NULL || vote == NULL)
		return MAC_ERR_ARGUMENT;
	state = mac_find_delegation(service, delegation_id);
	if (state == NULL)
		return MAC_ERR_NOT_FOUND;
	if (state->decision == MAC_DECISION_COMMITTED ||
	    state->decision == MAC_DECISION_REJECTED ||
	    state->decision == MAC_DECISION_CHALLENGED)
		return MAC_ERR_STATE;
	if (vote->delegation_id != delegation_id || vote->vote_sequence == 0U ||
	    vote->coordinator_generation != service->policy.coordinator_generation ||
	    !mac_is_participant(&state->request, vote->agent_id))
		return MAC_ERR_STALE;
	agent = mac_find_agent_const(service, vote->agent_id);
	if (agent == NULL || !agent->active || agent->agent_generation != vote->agent_generation)
		return MAC_ERR_STALE;
	if (vote->decision != MAC_VOTE_APPROVE && vote->decision != MAC_VOTE_REJECT &&
	    vote->decision != MAC_VOTE_CHALLENGE)
		return MAC_ERR_ARGUMENT;
	if (vote->evidence_count > state->evidence_count)
		return MAC_ERR_POLICY;
	for (i = 0U; i < state->vote_count; ++i) {
		if (state->votes[i].agent_id == vote->agent_id)
			return MAC_ERR_REPLAY;
	}
	if (state->vote_count >= MAC_MAX_PARTICIPANTS)
		return MAC_ERR_FULL;
	state->votes[state->vote_count++] = *vote;
	if (vote->decision == MAC_VOTE_APPROVE)
		state->approval_count++;
	else if (vote->decision == MAC_VOTE_REJECT)
		state->rejection_count++;
	else
		state->challenge_count++;
	if (vote->decision == MAC_VOTE_CHALLENGE) {
		state->decision = MAC_DECISION_CHALLENGED;
		state->status = MAC_ERR_CONFLICT;
		return mac_make_receipt(service, state, MAC_ERR_CONFLICT, out);
	}
	state->decision = MAC_DECISION_VOTING;
	if (state->approval_count +
	    (state->request.participant_count - state->vote_count) <
	    state->request.quorum_required) {
		state->decision = MAC_DECISION_REJECTED;
		state->status = MAC_ERR_QUORUM;
		return mac_make_receipt(service, state, MAC_ERR_QUORUM, out);
	}
	state->status = MAC_OK;
	return mac_make_receipt(service, state, MAC_OK, out);
}

int mac_authority_check(const struct mac_delegation *request)
{
	if (request == NULL)
		return MAC_ERR_ARGUMENT;
	if ((request->flags & MAC_FLAG_AUTHORITY_GRANTED) == 0U)
		return MAC_ERR_AUTHORITY;
	return MAC_OK;
}

int mac_commit(struct mac_service *service,
	       uint64_t delegation_id,
	       struct mac_receipt *out)
{
	struct mac_delegation_state *state;
	int result;

	if (service == NULL)
		return MAC_ERR_ARGUMENT;
	state = mac_find_delegation(service, delegation_id);
	if (state == NULL)
		return MAC_ERR_NOT_FOUND;
	if (state->decision == MAC_DECISION_CHALLENGED ||
	    state->decision == MAC_DECISION_REJECTED)
		return MAC_ERR_STATE;
	if (state->request.coordinator_generation != service->policy.coordinator_generation ||
	    state->request.deadline_ns <= service->policy.current_time_ns)
		return MAC_ERR_STALE;
	if (state->approval_count < state->request.quorum_required)
		return MAC_ERR_QUORUM;
	if (state->rejection_count != 0U || state->challenge_count != 0U)
		return MAC_ERR_CONFLICT;
	if (service->policy.require_evidence_for_commit &&
	    state->evidence_count < state->request.evidence_required)
		return MAC_ERR_POLICY;
	result = mac_authority_check(&state->request);
	if (result != MAC_OK)
		return result;
	state->decision = MAC_DECISION_COMMITTED;
	state->status = MAC_OK;
	return mac_make_receipt(service, state, MAC_OK, out);
}

int mac_verify_receipt(const struct mac_service *service,
			       const struct mac_receipt *receipt)
{
	const struct mac_delegation_state *state;
	struct mac_receipt expected;
	uint8_t digest[MAC_DIGEST_SIZE];
	size_t i;

	if (service == NULL || receipt == NULL)
		return MAC_ERR_ARGUMENT;
	state = mac_find_delegation_const(service, receipt->delegation_id);
	if (state == NULL)
		return MAC_ERR_NOT_FOUND;
	for (i = 0U; i < service->receipt_count; ++i) {
		if (service->receipts[i].receipt_id == receipt->receipt_id)
			break;
	}
	if (i == service->receipt_count ||
	    !mac_digest_equal(service->receipts[i].receipt_digest,
			      receipt->receipt_digest))
		return MAC_ERR_TAMPER;
	expected = *receipt;
	memset(expected.receipt_digest, 0, sizeof(expected.receipt_digest));
	if (mac_digest_receipt(&expected, digest) != MAC_OK ||
	    !mac_digest_equal(digest, receipt->receipt_digest) ||
	    !mac_digest_equal(receipt->delegation_digest, state->request_digest))
		return MAC_ERR_TAMPER;
	return MAC_OK;
}

int mac_query_receipt(const struct mac_service *service,
			      uint64_t delegation_id,
			      struct mac_receipt *out)
{
	size_t i;
	const struct mac_receipt *latest = NULL;

	if (service == NULL || out == NULL)
		return MAC_ERR_ARGUMENT;
	for (i = 0U; i < service->receipt_count; ++i) {
		if (service->receipts[i].delegation_id == delegation_id)
			latest = &service->receipts[i];
	}
	if (latest == NULL)
		return MAC_ERR_NOT_FOUND;
	*out = *latest;
	return MAC_OK;
}
