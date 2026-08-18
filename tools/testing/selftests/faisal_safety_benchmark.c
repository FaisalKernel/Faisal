#include "../../faisal-safety/faisal_safety.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ROUNDS 512U

static uint64_t now_ns(void)
{
	struct timespec value;

	if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
		return 0U;
	return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void digest(uint8_t output[FSA_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FSA_DIGEST_SIZE);
}

static struct fsa_policy make_policy(void)
{
	struct fsa_policy value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FSA_ABI_VERSION;
	value.flags = FSA_FLAG_FAIL_CLOSED | FSA_FLAG_REQUIRE_IDENTITY |
		FSA_FLAG_REQUIRE_CAPABILITY | FSA_FLAG_REQUIRE_RESOURCE |
		FSA_FLAG_REQUIRE_PROVENANCE | FSA_FLAG_REQUIRE_ATTESTATION;
	value.max_risk_ppm = 200000U;
	value.max_anomaly_ppm = 100000U;
	value.max_decision_age_ns = 1000U;
	value.max_token_ttl_ns = 1000U;
	value.generation = 1U;
	digest(value.policy_digest, 0xA1U);
	snprintf(value.name, sizeof(value.name), "benchmark-policy");
	return value;
}

static struct fsa_request make_request(void)
{
	struct fsa_request value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FSA_ABI_VERSION;
	value.attestation_state = FSA_ATTESTATION_TRUSTED;
	value.workload_id = 1U;
	value.tenant_id = 1U;
	value.agent_id = 1U;
	value.generation = 1U;
	value.policy_generation = 1U;
	value.submitted_at_ns = 900U;
	value.deadline_ns = 10000U;
	value.requested_capabilities = FSA_CAP_EXECUTE | FSA_CAP_NETWORK;
	value.granted_capabilities = value.requested_capabilities;
	value.cpu_budget_ns = 1000000U;
	value.memory_limit_bytes = 1U << 20;
	value.network_limit_bytes = 1U << 20;
	value.storage_limit_bytes = 1U << 20;
	value.risk_ppm = 100000U;
	value.anomaly_ppm = 10000U;
	value.provenance_verified = 1U;
	value.artifact_verified = 1U;
	digest(value.identity_digest, 0xB1U);
	digest(value.provenance_digest, 0xB2U);
	digest(value.artifact_digest, 0xB3U);
	digest(value.attestation_digest, 0xB4U);
	return value;
}

int main(void)
{
	char path[128];
	struct fsa_service service;
	struct fsa_policy policy = make_policy();
	struct fsa_request request = make_request();
	struct fsa_decision decision;
	uint64_t durable_start;
	uint64_t durable_end;
	uint64_t static_start;
	uint64_t static_end;
	uint64_t checksum = 0U;
	unsigned int i;

	snprintf(path, sizeof(path), "/tmp/faisal-safety-benchmark-%ld.journal", (long)getpid());
	unlink(path);
	if (fsa_open(&service, path, &policy) != FSA_OK)
		return 1;
	durable_start = now_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		request.workload_id = (uint64_t)i + 1U;
		if (fsa_evaluate(&service, &request, &decision) != FSA_OK ||
		    decision.action != FSA_ACTION_ALLOW) {
			fsa_close(&service);
			unlink(path);
			return 1;
		}
		checksum ^= decision.decision_id;
	}
	durable_end = now_ns();
	static_start = now_ns();
	for (i = 0U; i < ROUNDS; ++i) {
		int allow = request.abi_version == FSA_ABI_VERSION &&
			request.attestation_state == FSA_ATTESTATION_TRUSTED &&
			request.granted_capabilities == request.requested_capabilities &&
			request.provenance_verified && request.artifact_verified &&
			request.risk_ppm <= policy.max_risk_ppm &&
			request.anomaly_ppm <= policy.max_anomaly_ppm;
		checksum ^= (uint64_t)allow;
	}
	static_end = now_ns();
	fsa_close(&service);
	unlink(path);
	printf("M246_SAFETY_BENCHMARK_EXIT=0 rounds=%u durable_decision_ns=%llu durable_ns_per_decision=%.2f static_elapsed_ns=%llu static_ns_per_check=%.2f checksum=%llu\n",
	       ROUNDS, (unsigned long long)(durable_end - durable_start),
	       (double)(durable_end - durable_start) / (double)ROUNDS,
	       (unsigned long long)(static_end - static_start),
	       (double)(static_end - static_start) / (double)ROUNDS,
	       (unsigned long long)checksum);
	return 0;
}
