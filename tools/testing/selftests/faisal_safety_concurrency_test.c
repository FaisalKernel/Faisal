#include "../../faisal-safety/faisal_safety.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define READERS 4U
#define READ_ROUNDS 256U
#define WRITE_ROUNDS 256U

struct context {
	struct fsa_service *service;
	struct fsa_request request;
	uint64_t incident_id;
	atomic_int failures;
};

static void digest(uint8_t output[FSA_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FSA_DIGEST_SIZE);
}

static struct fsa_policy policy(void)
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
	snprintf(value.name, sizeof(value.name), "concurrency-policy");
	return value;
}

static struct fsa_request request(void)
{
	struct fsa_request value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FSA_ABI_VERSION;
	value.attestation_state = FSA_ATTESTATION_TRUSTED;
	value.workload_id = 1U;
	value.tenant_id = 1U;
	value.agent_id = 2U;
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

static void *reader(void *opaque)
{
	struct context *context = opaque;
	unsigned int i;

	for (i = 0U; i < READ_ROUNDS; ++i) {
		struct fsa_attestation attestation;
		struct fsa_incident incident;
		if (fsa_query_attestation(context->service, &attestation) != FSA_OK ||
		    fsa_query_incident(context->service, context->incident_id, &incident) != FSA_OK ||
		    incident.incident_id != context->incident_id)
			atomic_fetch_add(&context->failures, 1);
	}
	return NULL;
}

static void *writer(void *opaque)
{
	struct context *context = opaque;
	unsigned int i;

	for (i = 0U; i < WRITE_ROUNDS; ++i) {
		struct fsa_decision decision;
		struct fsa_request request_value = context->request;
		request_value.workload_id = (uint64_t)i + 10U;
		if (fsa_evaluate(context->service, &request_value, &decision) != FSA_OK ||
		    decision.action != FSA_ACTION_ALLOW)
			atomic_fetch_add(&context->failures, 1);
	}
	return NULL;
}

int main(void)
{
	char path[128];
	struct fsa_service service;
	struct fsa_policy configured = policy();
	struct fsa_request request_value = request();
	struct fsa_incident incident;
	struct context context;
	pthread_t readers[READERS];
	pthread_t writer_thread;
	uint8_t evidence[FSA_DIGEST_SIZE];
	unsigned int i;
	int failures;

	digest(evidence, 0xC1U);
	snprintf(path, sizeof(path), "/tmp/faisal-safety-concurrency-%ld.journal", (long)getpid());
	unlink(path);
	if (fsa_open(&service, path, &configured) != FSA_OK ||
	    fsa_open_incident(&service, request_value.workload_id, request_value.agent_id,
			      request_value.generation, 1000U, 20U,
			      FSA_ACTION_QUARANTINE, FSA_VIOLATION_ANOMALY,
			      "concurrency incident", &incident) != FSA_OK)
		return 1;
	context.service = &service;
	context.request = request_value;
	context.incident_id = incident.incident_id;
	atomic_init(&context.failures, 0);
	if (pthread_create(&writer_thread, NULL, writer, &context) != 0)
		return 1;
	for (i = 0U; i < READERS; ++i)
		if (pthread_create(&readers[i], NULL, reader, &context) != 0)
			return 1;
	if (pthread_join(writer_thread, NULL) != 0)
		return 1;
	for (i = 0U; i < READERS; ++i)
		if (pthread_join(readers[i], NULL) != 0)
			return 1;
	failures = atomic_load(&context.failures);
	fsa_close(&service);
	unlink(path);
	printf("M246_SAFETY_CONCURRENCY_EXIT=%d readers=%u read_rounds=%u writer_rounds=%u failures=%d\n",
	       failures == 0 ? 0 : 1, READERS, READ_ROUNDS, WRITE_ROUNDS, failures);
	return failures == 0 ? 0 : 1;
}
