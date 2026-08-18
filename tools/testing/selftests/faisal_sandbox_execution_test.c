#include "../../faisal-sandbox/faisal_sandbox_execution.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FSE_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static struct fse_request request(uint64_t sequence)
{
	struct fse_request r;
	uint32_t i;
	memset(&r, 0, sizeof(r));
	r.abi_version = FSE_ABI_VERSION;
	r.request_id = 100 + sequence;
	r.sandbox_id = 200;
	r.agent_id = 300;
	r.objective_id = 400;
	r.tenant_id = 500;
	r.sandbox_generation = 7;
	r.capability_mask = (1ULL << 0) | (1ULL << 2);
	r.cpu_budget_ns = 10000;
	r.memory_budget_bytes = 1ULL << 20;
	r.io_budget_bytes = 1ULL << 16;
	r.fuel_budget = 1000;
	r.deadline_ns = 5000;
	r.authority_lease_id = 600;
	r.request_sequence = sequence;
	r.nonce = sequence + 1000;
	r.checkpoint_sequence = 0;
	snprintf(r.provider, sizeof(r.provider), "wasmtime");
	snprintf(r.provider_handle, sizeof(r.provider_handle), "vm-handle-%llu",
		(unsigned long long)sequence);
	snprintf(r.stream_cursor, sizeof(r.stream_cursor), "cursor-%llu",
		(unsigned long long)sequence);
	for (i = 0; i < FSE_DIGEST_SIZE; i++) {
		r.input_digest[i] = (uint8_t)(i + 1);
		r.program_digest[i] = (uint8_t)(i + 2);
		r.imports_digest[i] = (uint8_t)(i + 3);
	}
	return r;
}

static struct fse_policy policy(void)
{
	struct fse_policy p;
	memset(&p, 0, sizeof(p));
	p.now_ns = 1000;
	p.expected_sandbox_id = 200;
	p.expected_agent_id = 300;
	p.expected_objective_id = 400;
	p.expected_tenant_id = 500;
	p.expected_generation = 7;
	p.allowed_capability_mask = (1ULL << 0) | (1ULL << 1) | (1ULL << 2);
	p.max_cpu_budget_ns = 20000;
	p.max_memory_budget_bytes = 2ULL << 20;
	p.max_io_budget_bytes = 1ULL << 17;
	p.max_fuel_budget = 2000;
	p.max_runtime_ns = 5000;
	p.expected_authority_lease_id = 600;
	p.authority_granted = 1;
	p.require_provider_handle = 1;
	p.require_stream_cursor = 1;
	return p;
}

int main(void)
{
	struct fse_verifier verifier;
	struct fse_request r;
	struct fse_policy p = policy();
	struct fse_decision d;
	struct fse_checkpoint cp;
	struct fse_completion completion;
	uint8_t state_digest[FSE_DIGEST_SIZE] = {0};
	uint8_t result_digest[FSE_DIGEST_SIZE] = {0};
	int rc;

	state_digest[0] = 0x11;
	result_digest[0] = 0x22;
	if (fse_init(&verifier) != FSE_OK)
		return fail("init", -1);
	r = request(1);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		d.state != FSE_STATE_ADMITTED)
		return fail("admission", -1);
	printf("FSE_CAPABILITY_RESOURCE_ADMISSION_OK\n");
	if (fse_start(&verifier, 1100) != FSE_OK ||
		fse_consume_fuel(&verifier, 300, 1200) != FSE_OK)
		return fail("start/fuel", -1);
	printf("FSE_FUEL_DEADLINE_EXECUTION_OK\n");
	if (fse_checkpoint(&verifier, &r, 1, 1300, state_digest, &cp) != FSE_OK)
		return fail("checkpoint", -1);
	printf("FSE_CHECKPOINT_DIGEST_BINDING_OK\n");
	if (fse_resume(&verifier, &r, &cp, 1400) != FSE_OK ||
		fse_consume_fuel(&verifier, 200, 1500) != FSE_OK)
		return fail("resume", -1);
	printf("FSE_RESUME_CURSOR_OK\n");
	memset(&completion, 0, sizeof(completion));
	completion.request_id = r.request_id;
	completion.observed_ns = 1600;
	completion.consumed_cpu_ns = 8000;
	completion.consumed_memory_bytes = 4096;
	completion.consumed_io_bytes = 1024;
	completion.consumed_fuel = 500;
	completion.authority_verified = 1;
	memcpy(completion.result_digest, result_digest, sizeof(result_digest));
	if (fse_complete(&verifier, &r, &completion) != FSE_OK)
		return fail("completion", -1);
	printf("FSE_AUTHORIZED_COMPLETION_OK\n");

	r = request(2);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		fse_start(&verifier, 1100) != FSE_OK)
		return fail("cancel admission", -1);
	if (fse_cancel(&verifier) != FSE_OK ||
		fse_consume_fuel(&verifier, 1, 1200) != FSE_ERR_CANCELLED)
		return fail("cancel enforcement", -1);
	printf("FSE_CANCELLATION_ENFORCED_OK\n");

	r = request(3);
	r.capability_mask |= (1ULL << 12);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_ERR_CAPABILITY ||
		!(d.violation_mask & FSE_VIOLATION_CAPABILITY))
		return fail("capability rejection", -1);
	printf("FSE_CAPABILITY_REJECT_OK\n");

	r = request(4);
	r.sandbox_generation = 8;
	if (fse_admit(&verifier, &r, &p, &d) != FSE_ERR_GENERATION ||
		!(d.violation_mask & FSE_VIOLATION_GENERATION))
		return fail("generation rejection", -1);
	printf("FSE_GENERATION_REJECT_OK\n");

	r = request(5);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		fse_start(&verifier, 1100) != FSE_OK ||
		fse_consume_fuel(&verifier, 999, 1200) != FSE_OK)
		return fail("fuel boundary admission", -1);
	if (fse_consume_fuel(&verifier, 2, 1300) != FSE_ERR_FUEL)
		return fail("fuel overrun", -1);
	printf("FSE_FUEL_OVERRUN_REJECT_OK\n");

	r = request(6);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		fse_start(&verifier, 1100) != FSE_OK)
		return fail("tamper admission", -1);
	r.objective_id++;
	memset(&completion, 0, sizeof(completion));
	completion.request_id = r.request_id;
	completion.observed_ns = 1200;
	completion.authority_verified = 1;
	memcpy(completion.result_digest, result_digest, sizeof(result_digest));
	rc = fse_complete(&verifier, &r, &completion);
	if (rc != FSE_ERR_TAMPER)
		return fail("tamper rejection", rc);
	printf("FSE_TAMPER_REJECT_OK\n");

	r = request(7);
	r.deadline_ns = 1000;
	if (fse_admit(&verifier, &r, &p, &d) != FSE_ERR_DEADLINE ||
		!(d.violation_mask & FSE_VIOLATION_DEADLINE))
		return fail("deadline admission rejection", -1);
	printf("FSE_DEADLINE_REJECT_OK\n");

	r = request(8);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		fse_start(&verifier, 1100) != FSE_OK ||
		fse_checkpoint(&verifier, &r, 1, 1200, state_digest, &cp) != FSE_OK)
		return fail("checkpoint fault fixture", -1);
	cp.state_digest[0] ^= 0x80;
	if (fse_resume(&verifier, &r, &cp, 1300) != FSE_ERR_CHECKPOINT)
		return fail("checkpoint tamper rejection", -1);
	printf("FSE_CHECKPOINT_TAMPER_REJECT_OK\n");

	r = request(9);
	if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
		fse_start(&verifier, 1100) != FSE_OK)
		return fail("authority fault fixture", -1);
	memset(&completion, 0, sizeof(completion));
	completion.request_id = r.request_id;
	completion.observed_ns = 1200;
	completion.authority_verified = 0;
	memcpy(completion.result_digest, result_digest, sizeof(result_digest));
	if (fse_complete(&verifier, &r, &completion) != FSE_ERR_AUTHORITY)
		return fail("unauthorized completion rejection", -1);
	printf("FSE_AUTHORITY_REJECT_OK\n");

	printf("FSE_SELFTEST_EXIT=0\n");
	return 0;
}
