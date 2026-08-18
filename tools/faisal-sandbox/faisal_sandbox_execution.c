#include "faisal_sandbox_execution.h"
#include <openssl/sha.h>
#include <string.h>

static int digest_present(const uint8_t digest[FSE_DIGEST_SIZE])
{
	uint32_t i;
	for (i = 0; i < FSE_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static int text_present(const char *text, size_t size)
{
	size_t i;
	if (!text || !size)
		return 0;
	for (i = 0; i < size; i++)
		if (text[i] == '\0')
			return i != 0;
	return 0;
}

static int state_active(uint32_t state)
{
	return state == FSE_STATE_ADMITTED || state == FSE_STATE_RUNNING ||
		state == FSE_STATE_CHECKPOINTED;
}

static int fse_digest_checkpoint(const struct fse_checkpoint *checkpoint,
	uint8_t digest[FSE_DIGEST_SIZE])
{
	struct fse_checkpoint copy;
	if (!checkpoint || !digest)
		return FSE_ERR_ARGUMENT;
	copy = *checkpoint;
	memset(copy.checkpoint_digest, 0, sizeof(copy.checkpoint_digest));
	SHA256((const unsigned char *)&copy, sizeof(copy), digest);
	return FSE_OK;
}

static void decision_reset(struct fse_decision *decision,
	const struct fse_request *request)
{
	memset(decision, 0, sizeof(*decision));
	decision->state = FSE_STATE_REJECTED;
	if (request)
		decision->request_id = request->request_id;
}

int fse_init(struct fse_verifier *verifier)
{
	if (!verifier)
		return FSE_ERR_ARGUMENT;
	memset(verifier, 0, sizeof(*verifier));
	return FSE_OK;
}

int fse_digest_request(const struct fse_request *request,
	uint8_t digest[FSE_DIGEST_SIZE])
{
	struct fse_request copy;
	if (!request || !digest)
		return FSE_ERR_ARGUMENT;
	copy = *request;
	memset(&copy.reserved0, 0, sizeof(copy.reserved0));
	SHA256((const unsigned char *)&copy, sizeof(copy), digest);
	return FSE_OK;
}

int fse_admit(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_policy *policy,
	struct fse_decision *decision)
{
	uint8_t digest[FSE_DIGEST_SIZE];
	if (!verifier || !request || !policy || !decision)
		return FSE_ERR_ARGUMENT;
	decision_reset(decision, request);
	if (request->abi_version != FSE_ABI_VERSION) {
		decision->violation_mask |= FSE_VIOLATION_ABI;
		return FSE_ERR_POLICY;
	}
	if (!request->request_id || !request->sandbox_id || !request->agent_id ||
		!request->objective_id || !request->tenant_id || !request->sandbox_generation ||
		!request->request_sequence || !request->nonce) {
		decision->violation_mask |= FSE_VIOLATION_IDENTITY;
		return FSE_ERR_POLICY;
	}
	if (request->sandbox_id != policy->expected_sandbox_id ||
		request->agent_id != policy->expected_agent_id ||
		request->objective_id != policy->expected_objective_id ||
		request->tenant_id != policy->expected_tenant_id ||
		request->authority_lease_id != policy->expected_authority_lease_id) {
		decision->violation_mask |= FSE_VIOLATION_IDENTITY;
		return FSE_ERR_POLICY;
	}
	if (request->sandbox_generation != policy->expected_generation) {
		decision->violation_mask |= FSE_VIOLATION_GENERATION;
		return FSE_ERR_GENERATION;
	}
	if (!request->capability_mask ||
		(request->capability_mask & ~policy->allowed_capability_mask)) {
		decision->violation_mask |= FSE_VIOLATION_CAPABILITY;
		return FSE_ERR_CAPABILITY;
	}
	if (!request->cpu_budget_ns || !request->memory_budget_bytes ||
		!request->io_budget_bytes || !request->fuel_budget ||
		(request->cpu_budget_ns > policy->max_cpu_budget_ns) ||
		(request->memory_budget_bytes > policy->max_memory_budget_bytes) ||
		(request->io_budget_bytes > policy->max_io_budget_bytes) ||
		(request->fuel_budget > policy->max_fuel_budget)) {
		decision->violation_mask |= FSE_VIOLATION_RESOURCE;
		return FSE_ERR_RESOURCE;
	}
	if (request->deadline_ns <= policy->now_ns ||
		request->deadline_ns - policy->now_ns > policy->max_runtime_ns) {
		decision->violation_mask |= FSE_VIOLATION_DEADLINE;
		return FSE_ERR_DEADLINE;
	}
	if (!policy->authority_granted) {
		decision->violation_mask |= FSE_VIOLATION_AUTHORITY;
		return FSE_ERR_AUTHORITY;
	}
	if (!digest_present(request->input_digest) ||
		!digest_present(request->program_digest) ||
		!digest_present(request->imports_digest)) {
		decision->violation_mask |= FSE_VIOLATION_PROVENANCE;
		return FSE_ERR_POLICY;
	}
	if ((policy->require_provider_handle &&
		!text_present(request->provider_handle, sizeof(request->provider_handle))) ||
		(policy->require_stream_cursor &&
		!text_present(request->stream_cursor, sizeof(request->stream_cursor))) ||
		!text_present(request->provider, sizeof(request->provider))) {
		decision->violation_mask |= FSE_VIOLATION_IDENTITY;
		return FSE_ERR_POLICY;
	}
	if (request->request_sequence <= verifier->last_sequence ||
		request->nonce <= verifier->last_nonce) {
		decision->violation_mask |= FSE_VIOLATION_REPLAY;
		return FSE_ERR_REPLAY;
	}
	if (fse_digest_request(request, digest) != FSE_OK)
		return FSE_ERR_ARGUMENT;
	verifier->last_sequence = request->request_sequence;
	verifier->last_nonce = request->nonce;
	verifier->active_request_id = request->request_id;
	verifier->active_generation = request->sandbox_generation;
	verifier->active_deadline_ns = request->deadline_ns;
	verifier->fuel_budget = request->fuel_budget;
	verifier->consumed_fuel = 0;
	verifier->checkpoint_sequence = request->checkpoint_sequence;
	verifier->active_state = FSE_STATE_ADMITTED;
	verifier->violation_mask = 0;
	memcpy(verifier->request_digest, digest, sizeof(digest));
	memset(verifier->checkpoint_digest, 0, sizeof(verifier->checkpoint_digest));
	decision->state = FSE_STATE_ADMITTED;
	decision->admitted_sequence = request->request_sequence;
	decision->checkpoint_sequence = request->checkpoint_sequence;
	memcpy(decision->request_digest, digest, sizeof(digest));
	return FSE_OK;
}

int fse_start(struct fse_verifier *verifier, uint64_t now_ns)
{
	if (!verifier || verifier->active_state != FSE_STATE_ADMITTED)
		return FSE_ERR_STATE;
	if (now_ns > verifier->active_deadline_ns) {
		verifier->violation_mask |= FSE_VIOLATION_DEADLINE;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_DEADLINE;
	}
	verifier->active_state = FSE_STATE_RUNNING;
	return FSE_OK;
}

int fse_consume_fuel(struct fse_verifier *verifier, uint64_t amount,
	uint64_t now_ns)
{
	if (!verifier || !amount)
		return FSE_ERR_ARGUMENT;
	if (verifier->active_state != FSE_STATE_RUNNING) {
		if (verifier->active_state == FSE_STATE_CANCELLED)
			return FSE_ERR_CANCELLED;
		return FSE_ERR_STATE;
	}
	if (now_ns > verifier->active_deadline_ns) {
		verifier->violation_mask |= FSE_VIOLATION_DEADLINE;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_DEADLINE;
	}
	if (amount > verifier->fuel_budget - verifier->consumed_fuel) {
		verifier->violation_mask |= FSE_VIOLATION_FUEL;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_FUEL;
	}
	verifier->consumed_fuel += amount;
	return FSE_OK;
}

int fse_checkpoint(struct fse_verifier *verifier,
	const struct fse_request *request,
	uint64_t checkpoint_sequence,
	uint64_t observed_ns,
	const uint8_t state_digest[FSE_DIGEST_SIZE],
	struct fse_checkpoint *checkpoint)
{
	struct fse_checkpoint copy;
	uint8_t request_digest[FSE_DIGEST_SIZE];
	if (!verifier || !request || !state_digest || !checkpoint ||
		!digest_present(state_digest))
		return FSE_ERR_ARGUMENT;
	if (verifier->active_state != FSE_STATE_RUNNING &&
		verifier->active_state != FSE_STATE_CHECKPOINTED)
		return FSE_ERR_STATE;
	if (request->request_id != verifier->active_request_id ||
		request->sandbox_generation != verifier->active_generation ||
		fse_digest_request(request, request_digest) != FSE_OK ||
		memcmp(request_digest, verifier->request_digest, sizeof(request_digest)) != 0) {
		verifier->violation_mask |= FSE_VIOLATION_TAMPER;
		return FSE_ERR_TAMPER;
	}
	if (!checkpoint_sequence || checkpoint_sequence <= verifier->checkpoint_sequence) {
		verifier->violation_mask |= FSE_VIOLATION_CHECKPOINT;
		return FSE_ERR_CHECKPOINT;
	}
	if (observed_ns > verifier->active_deadline_ns) {
		verifier->violation_mask |= FSE_VIOLATION_DEADLINE;
		return FSE_ERR_DEADLINE;
	}
	memset(&copy, 0, sizeof(copy));
	copy.request_id = request->request_id;
	copy.checkpoint_sequence = checkpoint_sequence;
	copy.observed_ns = observed_ns;
	copy.remaining_fuel = verifier->fuel_budget - verifier->consumed_fuel;
	memcpy(copy.state_digest, state_digest, sizeof(copy.state_digest));
	memcpy(copy.request_digest, verifier->request_digest, sizeof(copy.request_digest));
	if (fse_digest_checkpoint(&copy, verifier->checkpoint_digest) != FSE_OK)
		return FSE_ERR_ARGUMENT;
	memcpy(copy.checkpoint_digest, verifier->checkpoint_digest,
		sizeof(copy.checkpoint_digest));
	verifier->checkpoint_sequence = checkpoint_sequence;
	verifier->active_state = FSE_STATE_CHECKPOINTED;
	*checkpoint = copy;
	return FSE_OK;
}

int fse_resume(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_checkpoint *checkpoint,
	uint64_t now_ns)
{
	uint8_t request_digest[FSE_DIGEST_SIZE];
	uint8_t checkpoint_digest[FSE_DIGEST_SIZE];
	if (!verifier || !request || !checkpoint ||
		!digest_present(checkpoint->state_digest))
		return FSE_ERR_ARGUMENT;
	if (verifier->active_state != FSE_STATE_CHECKPOINTED ||
		request->request_id != verifier->active_request_id ||
		request->sandbox_generation != verifier->active_generation ||
		checkpoint->checkpoint_sequence != verifier->checkpoint_sequence ||
		fse_digest_request(request, request_digest) != FSE_OK ||
		memcmp(request_digest, verifier->request_digest, sizeof(request_digest)) != 0 ||
		memcmp(checkpoint->request_digest, verifier->request_digest,
			FSE_DIGEST_SIZE) != 0 ||
		fse_digest_checkpoint(checkpoint, checkpoint_digest) != FSE_OK ||
		memcmp(checkpoint_digest, verifier->checkpoint_digest,
			FSE_DIGEST_SIZE) != 0 ||
		!digest_present(checkpoint->checkpoint_digest) ||
		memcmp(checkpoint->checkpoint_digest, verifier->checkpoint_digest,
			FSE_DIGEST_SIZE) != 0) {
		verifier->violation_mask |= FSE_VIOLATION_CHECKPOINT;
		return FSE_ERR_CHECKPOINT;
	}
	if (now_ns > verifier->active_deadline_ns) {
		verifier->violation_mask |= FSE_VIOLATION_DEADLINE;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_DEADLINE;
	}
	if (checkpoint->remaining_fuel > verifier->fuel_budget ||
		checkpoint->remaining_fuel + verifier->consumed_fuel < verifier->consumed_fuel) {
		verifier->violation_mask |= FSE_VIOLATION_FUEL;
		return FSE_ERR_FUEL;
	}
	verifier->consumed_fuel = verifier->fuel_budget - checkpoint->remaining_fuel;
	verifier->active_state = FSE_STATE_RUNNING;
	return FSE_OK;
}

int fse_cancel(struct fse_verifier *verifier)
{
	if (!verifier || !state_active(verifier->active_state))
		return FSE_ERR_STATE;
	verifier->violation_mask |= FSE_VIOLATION_CANCEL;
	verifier->active_state = FSE_STATE_CANCELLED;
	return FSE_OK;
}

int fse_complete(struct fse_verifier *verifier,
	const struct fse_request *request,
	const struct fse_completion *completion)
{
	uint8_t digest[FSE_DIGEST_SIZE];
	if (!verifier || !request || !completion)
		return FSE_ERR_ARGUMENT;
	if (!state_active(verifier->active_state) ||
		request->request_id != verifier->active_request_id ||
		request->sandbox_generation != verifier->active_generation ||
		!completion->authority_verified) {
		verifier->violation_mask |= FSE_VIOLATION_AUTHORITY;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_AUTHORITY;
	}
	if (fse_digest_request(request, digest) != FSE_OK ||
		memcmp(digest, verifier->request_digest, sizeof(digest)) != 0) {
		verifier->violation_mask |= FSE_VIOLATION_TAMPER;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_TAMPER;
	}
	if (completion->observed_ns > verifier->active_deadline_ns) {
		verifier->violation_mask |= FSE_VIOLATION_DEADLINE;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_DEADLINE;
	}
	if (completion->consumed_cpu_ns > request->cpu_budget_ns ||
		completion->consumed_memory_bytes > request->memory_budget_bytes ||
		completion->consumed_io_bytes > request->io_budget_bytes ||
		completion->consumed_fuel > request->fuel_budget) {
		verifier->violation_mask |= FSE_VIOLATION_RESOURCE;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_RESOURCE;
	}
	if (!completion->result_code && !digest_present(completion->result_digest)) {
		verifier->violation_mask |= FSE_VIOLATION_TAMPER;
		verifier->active_state = FSE_STATE_FAILED;
		return FSE_ERR_TAMPER;
	}
	verifier->active_state = completion->result_code ? FSE_STATE_FAILED : FSE_STATE_COMPLETED;
	return completion->result_code ? FSE_ERR_STATE : FSE_OK;
}

int fse_query(const struct fse_verifier *verifier,
	struct fse_decision *decision)
{
	if (!verifier || !decision)
		return FSE_ERR_ARGUMENT;
	memset(decision, 0, sizeof(*decision));
	decision->state = verifier->active_state;
	decision->violation_mask = verifier->violation_mask;
	decision->request_id = verifier->active_request_id;
	decision->admitted_sequence = verifier->last_sequence;
	decision->checkpoint_sequence = verifier->checkpoint_sequence;
	decision->consumed_fuel = verifier->consumed_fuel;
	memcpy(decision->request_digest, verifier->request_digest,
		FSE_DIGEST_SIZE);
	memcpy(decision->checkpoint_digest, verifier->checkpoint_digest,
		FSE_DIGEST_SIZE);
	return FSE_OK;
}
