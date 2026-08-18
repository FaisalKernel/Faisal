#include "faisal_recovery_decision.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static void hash_u32(EVP_MD_CTX *ctx, uint32_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_u64(EVP_MD_CTX *ctx, uint64_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_digest(EVP_MD_CTX *ctx, const uint8_t digest[FRD_DIGEST_SIZE])
{
	(void)EVP_DigestUpdate(ctx, digest, FRD_DIGEST_SIZE);
}

static int digest_decision(const struct frd_input *input,
			   const struct frd_decision *decision,
			   uint8_t out[FRD_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;

	if (!input || !decision || !out || !input->request_sequence)
		return FRD_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FRD_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return FRD_ERR_CORRUPT;
	}
	hash_u64(ctx, input->request_sequence);
	hash_u64(ctx, input->now_ns);
	hash_u64(ctx, input->objective_id);
	hash_u64(ctx, input->agent_id);
	hash_u64(ctx, input->worker_id);
	hash_u64(ctx, input->trace_id);
	hash_u64(ctx, input->span_id);
	hash_u64(ctx, input->parent_span_id);
	hash_u64(ctx, input->generation);
	hash_u64(ctx, input->action_id);
	hash_u64(ctx, input->deadline_ns);
	hash_u64(ctx, input->backoff_base_ns);
	hash_u32(ctx, input->requested_action);
	hash_u32(ctx, input->flags);
	hash_u32(ctx, input->attempt);
	hash_u32(ctx, input->max_attempts);
	hash_u32(ctx, input->failure_class);
	hash_u32(ctx, input->severity);
	hash_digest(ctx, input->observation_digest);
	hash_digest(ctx, input->diagnosis_digest);
	hash_digest(ctx, input->candidate_digest);
	hash_digest(ctx, input->checkpoint_digest);
	hash_u64(ctx, decision->request_sequence);
	hash_u64(ctx, decision->decision_sequence);
	hash_u64(ctx, decision->objective_id);
	hash_u64(ctx, decision->trace_id);
	hash_u64(ctx, decision->generation);
	hash_u64(ctx, decision->action_id);
	hash_u64(ctx, decision->next_attempt_ns);
	hash_u32(ctx, decision->action);
	hash_u32(ctx, decision->status);
	hash_u32(ctx, decision->attempt);
	hash_u32(ctx, decision->retry_count);
	if (EVP_DigestFinal_ex(ctx, out, &length) != 1 || length != FRD_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FRD_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FRD_OK;
}

static uint64_t backoff_ns(const struct frd_service *service,
			   const struct frd_input *input)
{
	uint64_t value;
	uint32_t shift;

	if (!input->backoff_base_ns || input->attempt <= 1)
		return input->backoff_base_ns;
	shift = input->attempt - 1;
	if (shift >= 63 || input->backoff_base_ns > UINT64_MAX / (1ULL << shift))
		return service->policy.max_backoff_ns;
	value = input->backoff_base_ns * (1ULL << shift);
	if (value > service->policy.max_backoff_ns)
		value = service->policy.max_backoff_ns;
	return value;
}

static int required_evidence(const struct frd_service *service,
			     const struct frd_input *input, uint32_t action)
{
	uint32_t required = FRD_FLAG_TRACE_BOUND | FRD_FLAG_GENERATION_BOUND |
			    FRD_FLAG_OBSERVATION | FRD_FLAG_DIAGNOSIS;

	if ((action & (FRD_ACTION_RETRY | FRD_ACTION_REROUTE |
		      FRD_ACTION_REPLAN | FRD_ACTION_ROLLBACK |
		      FRD_ACTION_COMPENSATE)) != 0)
		required |= FRD_FLAG_CHECKPOINT;
	if ((action & (FRD_ACTION_REROUTE | FRD_ACTION_REPLAN |
		      FRD_ACTION_ROLLBACK)) != 0)
		required |= FRD_FLAG_CANDIDATE;
	if ((action & (FRD_ACTION_ROLLBACK | FRD_ACTION_COMPENSATE)) != 0)
		required |= FRD_FLAG_AUTHORITY | FRD_FLAG_COMPENSATION;
	if (service->policy.require_canary_for_candidate &&
	    (action & (FRD_ACTION_REROUTE | FRD_ACTION_REPLAN |
		       FRD_ACTION_ROLLBACK)) != 0)
		required |= FRD_FLAG_CANARY_PASSED;
	if ((input->flags & required) != required)
		return FRD_ERR_POLICY;
	if (service->policy.require_checkpoint_for_recovery &&
	    (input->flags & FRD_FLAG_CHECKPOINT) == 0)
		return FRD_ERR_POLICY;
	if (service->policy.require_operator_irreversible &&
	    (input->flags & FRD_FLAG_AUTHORITY) == 0 &&
	    (action & (FRD_ACTION_ROLLBACK | FRD_ACTION_COMPENSATE)) != 0)
		return FRD_ERR_AUTHORITY;
	if (service->policy.require_compensation_irreversible &&
	    (input->flags & FRD_FLAG_COMPENSATION) == 0 &&
	    (action & (FRD_ACTION_ROLLBACK | FRD_ACTION_COMPENSATE)) != 0)
		return FRD_ERR_POLICY;
	return FRD_OK;
}

int frd_init(struct frd_service *service, const struct frd_policy *policy)
{
	if (!service || !policy || !policy->allowed_actions ||
	    !policy->max_attempts || !policy->max_backoff_ns)
		return FRD_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->next_decision_sequence = 1;
	return FRD_OK;
}

int frd_decide(struct frd_service *service, const struct frd_input *input,
	       struct frd_decision *out)
{
	struct frd_decision decision;
	uint64_t delay;
	uint64_t next_time;
	uint32_t action;
	int rc;

	if (!service || !input || !out || !input->request_sequence ||
	    !input->objective_id || !input->trace_id || !input->generation ||
	    !input->action_id || !input->deadline_ns ||
	    service->decision_count >= FRD_MAX_DECISIONS)
		return FRD_ERR_ARGUMENT;
	if (input->request_sequence <= service->last_request_sequence)
		return FRD_ERR_REPLAY;
	if (input->now_ns > input->deadline_ns)
		return FRD_ERR_DEADLINE;
	if (!input->attempt || input->attempt > service->policy.max_attempts ||
	    input->attempt > input->max_attempts)
		return FRD_ERR_RETRY_LIMIT;
	action = input->requested_action & service->policy.allowed_actions;
	if (!action || (input->requested_action & ~FRD_ACTION_ALL) != 0)
		return FRD_ERR_POLICY;
	if ((input->flags & FRD_FLAG_MODEL_PROPOSAL) &&
	    (input->flags & FRD_FLAG_AUTHORITY) == 0 &&
	    (action & (FRD_ACTION_ROLLBACK | FRD_ACTION_COMPENSATE)) != 0)
		return FRD_ERR_AUTHORITY;
	if ((action & FRD_ACTION_RETRY) &&
	    (input->flags & (FRD_FLAG_IDEMPOTENT | FRD_FLAG_CHECKPOINT)) == 0)
		return FRD_ERR_POLICY;
	rc = required_evidence(service, input, action);
	if (rc != FRD_OK)
		return rc;
	memset(&decision, 0, sizeof(decision));
	decision.request_sequence = input->request_sequence;
	decision.decision_sequence = service->next_decision_sequence++;
	decision.objective_id = input->objective_id;
	decision.trace_id = input->trace_id;
	decision.generation = input->generation;
	decision.action_id = input->action_id;
	decision.action = action;
	decision.status = FRD_DECISION_ACCEPTED;
	decision.attempt = input->attempt;
	decision.retry_count = input->attempt - 1;
	delay = (action & (FRD_ACTION_RETRY | FRD_ACTION_REROUTE |
			  FRD_ACTION_REPLAN)) ? backoff_ns(service, input) : 0;
	if (UINT64_MAX - input->now_ns < delay)
		next_time = UINT64_MAX;
	else
		next_time = input->now_ns + delay;
	if (next_time > input->deadline_ns)
		return FRD_ERR_DEADLINE;
	decision.next_attempt_ns = next_time;
	if (snprintf(decision.reason, sizeof(decision.reason),
		     "accepted action=0x%x attempt=%u trace=%llu generation=%llu delay_ns=%llu",
		     action, input->attempt, (unsigned long long)input->trace_id,
		     (unsigned long long)input->generation,
		     (unsigned long long)delay) < 0)
		return FRD_ERR_CORRUPT;
	if (digest_decision(input, &decision, decision.receipt_digest) != FRD_OK)
		return FRD_ERR_CORRUPT;
	service->decisions[service->decision_count++] = decision;
	service->last_request_sequence = input->request_sequence;
	*out = decision;
	return FRD_OK;
}

int frd_verify(const struct frd_service *service, const struct frd_input *input,
	      const struct frd_decision *decision, uint64_t current_generation)
{
	uint8_t digest[FRD_DIGEST_SIZE];

	if (!service || !input || !decision || !current_generation)
		return FRD_ERR_ARGUMENT;
	if (decision->status != FRD_DECISION_ACCEPTED ||
	    decision->request_sequence != input->request_sequence ||
	    decision->generation != current_generation)
		return FRD_ERR_STALE;
	if (digest_decision(input, decision, digest) != FRD_OK)
		return FRD_ERR_CORRUPT;
	if (memcmp(digest, decision->receipt_digest, FRD_DIGEST_SIZE) != 0)
		return FRD_ERR_CORRUPT;
	return FRD_OK;
}

int frd_get(const struct frd_service *service, uint64_t decision_sequence,
	    struct frd_decision *out)
{
	size_t i;

	if (!service || !out || !decision_sequence)
		return FRD_ERR_ARGUMENT;
	for (i = 0; i < service->decision_count; i++) {
		if (service->decisions[i].decision_sequence == decision_sequence) {
			*out = service->decisions[i];
			return FRD_OK;
		}
	}
	return FRD_ERR_NOT_FOUND;
}
