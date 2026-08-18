#include "faisal_model_action.h"
#include <openssl/sha.h>
#include <string.h>

static int digest_present(const uint8_t digest[FMA_DIGEST_SIZE])
{
	uint32_t i;
	for (i = 0; i < FMA_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static int text_present(const char *text, size_t size)
{
	size_t i;
	if (!text || !size)
		return 0;
	for (i = 0; i < size; i++) {
		if (text[i] == '\0')
			return i != 0;
	}
	return 0;
}

static int provider_allowed(uint32_t mask, uint32_t provider)
{
	if (!provider || provider > 31U)
		return 0;
	return (mask & (1U << (provider - 1U))) != 0U;
}

static int action_allowed(uint32_t mask, uint32_t action)
{
	if (!action || action > 31U)
		return 0;
	return (mask & (1U << (action - 1U))) != 0U;
}

static void decision_reset(struct fma_decision *decision,
	const struct fma_action_envelope *envelope)
{
	memset(decision, 0, sizeof(*decision));
	decision->state = FMA_STATE_REJECTED;
	if (envelope)
		decision->request_id = envelope->request_id;
}

int fma_init(struct fma_verifier *verifier)
{
	if (!verifier)
		return FMA_ERR_ARGUMENT;
	memset(verifier, 0, sizeof(*verifier));
	return FMA_OK;
}

int fma_digest(const struct fma_action_envelope *envelope,
	uint8_t digest[FMA_DIGEST_SIZE])
{
	struct fma_action_envelope copy;
	if (!envelope || !digest)
		return FMA_ERR_ARGUMENT;
	copy = *envelope;
	memset(&copy.reserved0, 0,
		sizeof(copy.reserved0) + sizeof(copy.reserved1) + sizeof(copy.reserved2));
	SHA256((const unsigned char *)&copy, sizeof(copy), digest);
	return FMA_OK;
}

int fma_admit(struct fma_verifier *verifier,
	const struct fma_action_envelope *envelope,
	const struct fma_policy *policy,
	struct fma_decision *decision)
{
	uint8_t digest[FMA_DIGEST_SIZE];
	if (!verifier || !envelope || !policy || !decision)
		return FMA_ERR_ARGUMENT;
	decision_reset(decision, envelope);
	if (envelope->abi_version != FMA_ABI_VERSION) {
		decision->violation_mask |= FMA_VIOLATION_ABI;
		return FMA_ERR_POLICY;
	}
	if (!envelope->request_id || !envelope->agent_id || !envelope->objective_id ||
		!envelope->tenant_id || !envelope->issued_at_ns || !envelope->expires_at_ns ||
		envelope->issued_at_ns > policy->now_ns) {
		decision->violation_mask |= FMA_VIOLATION_IDENTITY;
		return FMA_ERR_POLICY;
	}
	if (envelope->agent_id != policy->expected_agent_id ||
		envelope->objective_id != policy->expected_objective_id ||
		envelope->tenant_id != policy->expected_tenant_id ||
		envelope->tool_id != policy->expected_tool_id ||
		envelope->registry_generation != policy->expected_registry_generation ||
		envelope->revocation_generation != policy->expected_revocation_generation ||
		envelope->authority_lease_id != policy->expected_authority_lease_id) {
		decision->violation_mask |= FMA_VIOLATION_IDENTITY;
		return FMA_ERR_POLICY;
	}
	if (envelope->expires_at_ns <= policy->now_ns ||
		envelope->expires_at_ns < envelope->issued_at_ns ||
		(policy->max_ttl_ns &&
		 envelope->expires_at_ns - envelope->issued_at_ns > policy->max_ttl_ns)) {
		decision->violation_mask |= FMA_VIOLATION_EXPIRY;
		return FMA_ERR_EXPIRED;
	}
	if (!provider_allowed(policy->allowed_provider_mask, envelope->provider_kind)) {
		decision->violation_mask |= FMA_VIOLATION_PROVIDER;
		return FMA_ERR_PROVIDER;
	}
	if (!action_allowed(policy->allowed_action_mask, envelope->action_kind) ||
		envelope->action_kind == FMA_ACTION_REFUSAL) {
		decision->violation_mask |= envelope->action_kind == FMA_ACTION_REFUSAL ?
			FMA_VIOLATION_REFUSAL : FMA_VIOLATION_ACTION;
		return FMA_ERR_POLICY;
	}
	if (!text_present(envelope->provider, sizeof(envelope->provider)) ||
		!text_present(envelope->model, sizeof(envelope->model)) ||
		(envelope->action_kind == FMA_ACTION_TOOL &&
			!text_present(envelope->tool, sizeof(envelope->tool)))) {
		decision->violation_mask |= FMA_VIOLATION_IDENTITY;
		return FMA_ERR_POLICY;
	}
	if ((policy->require_schema && !envelope->schema_valid) ||
		!envelope->schema_valid || !digest_present(envelope->schema_digest) ||
		!digest_present(envelope->arguments_digest)) {
		decision->violation_mask |= FMA_VIOLATION_SCHEMA;
		return FMA_ERR_SCHEMA;
	}
	if ((policy->require_provenance &&
		(!digest_present(envelope->input_digest) ||
		 !digest_present(envelope->model_provenance_digest))) ||
		!digest_present(envelope->input_digest) ||
		!digest_present(envelope->model_provenance_digest)) {
		decision->violation_mask |= FMA_VIOLATION_PROVENANCE;
		return FMA_ERR_POLICY;
	}
	if (!policy->authority_granted || envelope->authority_source == FMA_AUTH_MODEL ||
		envelope->authority_source == FMA_AUTH_NONE) {
		decision->violation_mask |= FMA_VIOLATION_AUTHORITY;
		return FMA_ERR_AUTHORITY;
	}
	if (envelope->request_sequence <= verifier->last_sequence ||
		envelope->nonce <= verifier->last_nonce) {
		decision->violation_mask |= FMA_VIOLATION_REPLAY;
		return FMA_ERR_REPLAY;
	}
	if (fma_digest(envelope, digest) != FMA_OK)
		return FMA_ERR_ARGUMENT;
	verifier->last_sequence = envelope->request_sequence;
	verifier->last_nonce = envelope->nonce;
	verifier->active_request_id = envelope->request_id;
	memcpy(verifier->active_envelope_digest, digest, sizeof(digest));
	verifier->active_state = FMA_STATE_ADMITTED;
	decision->state = FMA_STATE_ADMITTED;
	decision->admitted_sequence = envelope->request_sequence;
	decision->nonce = envelope->nonce;
	memcpy(decision->envelope_digest, digest, sizeof(digest));
	return FMA_OK;
}

int fma_complete(struct fma_verifier *verifier,
	const struct fma_action_envelope *envelope,
	const struct fma_decision *decision,
	const struct fma_completion *completion)
{
	uint8_t digest[FMA_DIGEST_SIZE];
	if (!verifier || !envelope || !decision || !completion)
		return FMA_ERR_ARGUMENT;
	if (verifier->active_state != FMA_STATE_ADMITTED ||
		decision->state != FMA_STATE_ADMITTED ||
		completion->request_id != verifier->active_request_id ||
		envelope->request_id != verifier->active_request_id ||
		!completion->verifier_authorized) {
		verifier->active_state = FMA_STATE_FAILED;
		return FMA_ERR_AUTHORITY;
	}
	if (fma_digest(envelope, digest) != FMA_OK ||
		memcmp(digest, verifier->active_envelope_digest, sizeof(digest)) != 0 ||
		memcmp(digest, decision->envelope_digest, sizeof(digest)) != 0) {
		verifier->active_state = FMA_STATE_FAILED;
		return FMA_ERR_TAMPER;
	}
	if (!completion->observed_at_ns || completion->observed_at_ns < envelope->issued_at_ns ||
		completion->observed_at_ns > envelope->expires_at_ns ||
		(completion->result_code == 0 && !digest_present(completion->result_digest))) {
		verifier->active_state = FMA_STATE_FAILED;
		return FMA_ERR_STATE;
	}
	verifier->active_state = completion->result_code == 0 ?
		FMA_STATE_COMPLETED : FMA_STATE_FAILED;
	return completion->result_code == 0 ? FMA_OK : FMA_ERR_STATE;
}

int fma_query(const struct fma_verifier *verifier,
	struct fma_decision *decision)
{
	if (!verifier || !decision)
		return FMA_ERR_ARGUMENT;
	memset(decision, 0, sizeof(*decision));
	decision->state = verifier->active_state;
	decision->request_id = verifier->active_request_id;
	decision->admitted_sequence = verifier->last_sequence;
	decision->nonce = verifier->last_nonce;
	memcpy(decision->envelope_digest, verifier->active_envelope_digest,
		FMA_DIGEST_SIZE);
	return FMA_OK;
}
