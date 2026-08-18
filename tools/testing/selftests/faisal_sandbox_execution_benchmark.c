#define _GNU_SOURCE
#include "../../faisal-sandbox/faisal_sandbox_execution.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FSE_BENCH_ROUNDS 100000U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct fse_request request(uint64_t sequence)
{
	struct fse_request r;
	uint32_t i;
	memset(&r, 0, sizeof(r));
	r.abi_version = FSE_ABI_VERSION;
	r.request_id = sequence + 100;
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
	snprintf(r.provider_handle, sizeof(r.provider_handle), "handle-%llu", (unsigned long long)sequence);
	snprintf(r.stream_cursor, sizeof(r.stream_cursor), "cursor-%llu", (unsigned long long)sequence);
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
	struct fse_policy p = policy();
	struct fse_request r;
	struct fse_decision d;
	struct fse_checkpoint cp;
	struct fse_completion completion;
	uint8_t state_digest[FSE_DIGEST_SIZE] = {1};
	uint8_t result_digest[FSE_DIGEST_SIZE] = {2};
	uint64_t start, elapsed;
	unsigned int i;

	if (fse_init(&verifier) != FSE_OK)
		return 1;
	start = now_ns();
	for (i = 0; i < FSE_BENCH_ROUNDS; i++) {
		r = request((uint64_t)i + 1);
		if (fse_admit(&verifier, &r, &p, &d) != FSE_OK ||
			fse_start(&verifier, 1100) != FSE_OK ||
			fse_consume_fuel(&verifier, 100, 1200) != FSE_OK ||
			fse_checkpoint(&verifier, &r, 1, 1300, state_digest, &cp) != FSE_OK ||
			fse_resume(&verifier, &r, &cp, 1400) != FSE_OK ||
			fse_consume_fuel(&verifier, 100, 1500) != FSE_OK)
			return 2;
		memset(&completion, 0, sizeof(completion));
		completion.request_id = r.request_id;
		completion.observed_ns = 1600;
		completion.consumed_cpu_ns = 8000;
		completion.consumed_memory_bytes = 4096;
		completion.consumed_io_bytes = 1024;
		completion.consumed_fuel = 200;
		completion.authority_verified = 1;
		memcpy(completion.result_digest, result_digest, sizeof(result_digest));
		if (fse_complete(&verifier, &r, &completion) != FSE_OK)
			return 3;
	}
	elapsed = now_ns() - start;
	printf("FSE_BENCH rounds=%u admitted=%u checkpointed=%u resumed=%u completed=%u total_ns=%llu ns_per_round=%llu\n",
		FSE_BENCH_ROUNDS, FSE_BENCH_ROUNDS, FSE_BENCH_ROUNDS,
		FSE_BENCH_ROUNDS, FSE_BENCH_ROUNDS,
		(unsigned long long)elapsed,
		(unsigned long long)(elapsed / FSE_BENCH_ROUNDS));
	printf("FSE_BENCH_SCOPE=local_userspace_policy_fixture_not_wasm_or_microvm_or_provider_latency\n");
	return 0;
}
