#include "../../faisal-model-action/faisal_model_action.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FMA_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static struct fma_policy policy(void)
{
	struct fma_policy p;
	memset(&p, 0, sizeof(p));
	p.now_ns = 1000;
	p.expected_agent_id = 7;
	p.expected_objective_id = 8;
	p.expected_tenant_id = 9;
	p.expected_tool_id = 10;
	p.expected_registry_generation = 11;
	p.expected_revocation_generation = 12;
	p.expected_authority_lease_id = 13;
	p.max_ttl_ns = 500;
	p.allowed_provider_mask = (1U << (FMA_PROVIDER_OPENAI - 1U)) |
		(1U << (FMA_PROVIDER_ANTHROPIC - 1U)) |
		(1U << (FMA_PROVIDER_GEMINI - 1U)) |
		(1U << (FMA_PROVIDER_QWEN - 1U)) |
		(1U << (FMA_PROVIDER_LOCAL - 1U));
	p.allowed_action_mask = (1U << (FMA_ACTION_TOOL - 1U)) |
		(1U << (FMA_ACTION_STRUCTURED_RESPONSE - 1U));
	p.authority_granted = 1;
	p.require_schema = 1;
	p.require_provenance = 1;
	return p;
}

static struct fma_action_envelope envelope(uint32_t provider, uint64_t sequence)
{
	struct fma_action_envelope e;
	uint32_t i;
	memset(&e, 0, sizeof(e));
	e.abi_version = FMA_ABI_VERSION;
	e.action_kind = FMA_ACTION_TOOL;
	e.provider_kind = provider;
	e.schema_valid = 1;
	e.authority_source = FMA_AUTH_KERNEL;
	e.request_id = 100 + sequence;
	e.agent_id = 7;
	e.objective_id = 8;
	e.tenant_id = 9;
	e.tool_id = 10;
	e.registry_generation = 11;
	e.revocation_generation = 12;
	e.authority_lease_id = 13;
	e.request_sequence = sequence;
	e.nonce = sequence + 1000;
	e.issued_at_ns = 1000;
	e.expires_at_ns = 1400;
	e.confidence_ppm = 950000;
	snprintf(e.provider, sizeof(e.provider), "provider-%u", provider);
	snprintf(e.model, sizeof(e.model), "model-%u", provider);
	snprintf(e.tool, sizeof(e.tool), "read_authorized_state");
	for (i = 0; i < FMA_DIGEST_SIZE; i++) {
		e.input_digest[i] = (uint8_t)(i + 1);
		e.schema_digest[i] = (uint8_t)(i + 2);
		e.arguments_digest[i] = (uint8_t)(i + 3);
		e.model_provenance_digest[i] = (uint8_t)(i + 4);
	}
	return e;
}

int main(void)
{
	struct fma_verifier verifier;
	struct fma_policy p = policy();
	struct fma_action_envelope e;
	struct fma_decision d, q;
	struct fma_completion c;
	uint8_t result_digest[FMA_DIGEST_SIZE] = {0};
	int rc;

	if (fma_init(&verifier) != FMA_OK)
		return fail("init", -1);
	e = envelope(FMA_PROVIDER_OPENAI, 1);
	if (fma_admit(&verifier, &e, &p, &d) != FMA_OK ||
		d.state != FMA_STATE_ADMITTED || !d.envelope_digest[0])
		return fail("OpenAI structured tool admission", -1);
	printf("FMA_OPENAI_TOOL_ADMISSION_OK\n");
	c.request_id = e.request_id;
	c.observed_at_ns = 1100;
	c.result_code = 0;
	c.verifier_authorized = 1;
	result_digest[0] = 0xA5;
	memcpy(c.result_digest, result_digest, sizeof(c.result_digest));
	if (fma_complete(&verifier, &e, &d, &c) != FMA_OK ||
		fma_query(&verifier, &q) != FMA_OK || q.state != FMA_STATE_COMPLETED)
		return fail("authorized completion", -1);
	printf("FMA_AUTHORIZED_COMPLETION_OK\n");

	e = envelope(FMA_PROVIDER_ANTHROPIC, 2);
	e.authority_source = FMA_AUTH_MODEL;
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_AUTHORITY ||
		!(d.violation_mask & FMA_VIOLATION_AUTHORITY))
		return fail("model authority rejection", -1);
	printf("FMA_MODEL_OUTPUT_NOT_AUTHORITY_OK\n");

	e = envelope(FMA_PROVIDER_GEMINI, 3);
	e.schema_valid = 0;
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_SCHEMA ||
		!(d.violation_mask & FMA_VIOLATION_SCHEMA))
		return fail("schema rejection", -1);
	printf("FMA_SCHEMA_REJECT_OK\n");

	e = envelope(FMA_PROVIDER_QWEN, 4);
	e.model_refusal = 1;
	e.action_kind = FMA_ACTION_REFUSAL;
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_POLICY ||
		!(d.violation_mask & FMA_VIOLATION_REFUSAL))
		return fail("refusal rejection", -1);
	printf("FMA_REFUSAL_REJECT_OK\n");

	e = envelope(FMA_PROVIDER_LOCAL, 5);
	e.provider_kind = 31;
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_PROVIDER ||
		!(d.violation_mask & FMA_VIOLATION_PROVIDER))
		return fail("provider rejection", -1);
	printf("FMA_PROVIDER_REJECT_OK\n");

	e = envelope(FMA_PROVIDER_OPENAI, 1);
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_REPLAY ||
		!(d.violation_mask & FMA_VIOLATION_REPLAY))
		return fail("replay rejection", -1);
	printf("FMA_REPLAY_REJECT_OK\n");

	e = envelope(FMA_PROVIDER_OPENAI, 6);
	e.expires_at_ns = 1601;
	if (fma_admit(&verifier, &e, &p, &d) != FMA_ERR_EXPIRED ||
		!(d.violation_mask & FMA_VIOLATION_EXPIRY))
		return fail("ttl rejection", -1);
	printf("FMA_TTL_REJECT_OK\n");

	e = envelope(FMA_PROVIDER_OPENAI, 7);
	if (fma_admit(&verifier, &e, &p, &d) != FMA_OK)
		return fail("tamper admission", -1);
	e.tool_id++;
	c.request_id = e.request_id;
	c.observed_at_ns = 1100;
	c.result_code = 0;
	c.verifier_authorized = 1;
	memcpy(c.result_digest, result_digest, sizeof(c.result_digest));
	rc = fma_complete(&verifier, &e, &d, &c);
	if (rc != FMA_ERR_TAMPER)
		return fail("tamper completion rejection", rc);
	printf("FMA_TAMPER_REJECT_OK\n");
	printf("FMA_SELFTEST_EXIT=0\n");
	return 0;
}
