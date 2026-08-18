#include "../../faisal-platform/faisal_platform.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define READERS 4U
#define WORKLOADS 32U
#define READ_ROUNDS 256U

struct context {
	struct fpl_service *service;
	atomic_int failures;
};

static void digest(uint8_t out[FPL_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FPL_DIGEST_SIZE);
}

static struct fpl_policy policy(void)
{
	struct fpl_policy value;

	memset(&value, 0, sizeof(value));
	value.current_time_ns = 1000U;
	value.max_intent_age_ns = 10000U;
	value.flags = FPL_REQUIRE_AUTHORITY | FPL_REQUIRE_LINEAGE |
		FPL_REQUIRE_TOPOLOGY | FPL_FAIL_CLOSED;
	value.max_workloads = FPL_MAX_WORKLOADS;
	value.max_recovery_attempts = 3U;
	digest(value.authority_digest, 0xA1U);
	return value;
}

static struct fpl_intent request(uint64_t id)
{
	struct fpl_intent value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FPL_ABI_VERSION;
	value.provider_kind = FPL_PROVIDER_KUBERAY;
	value.workload_id = id;
	value.tenant_id = 1U;
	value.agent_id = id + 100U;
	value.objective_id = id + 200U;
	value.created_at_ns = 900U;
	value.deadline_ns = 9000U;
	value.required_cpu_millis = 10U;
	value.required_memory_bytes = 1ULL << 20;
	value.required_network_mbps = 1U;
	value.required_storage_bytes = 1ULL << 20;
	value.required_accelerator_mask = 1U;
	value.required_accelerator_count = 1U;
	value.required_capability_mask = FLE_CAP_INFERENCE;
	value.replicas = 1U;
	value.gang_size = 1U;
	value.authorized = 1U;
	value.allow_recovery = 1U;
	snprintf(value.tenant, sizeof(value.tenant), "tenant");
	snprintf(value.model_id, sizeof(value.model_id), "model");
	snprintf(value.objective, sizeof(value.objective), "objective");
	snprintf(value.zone, sizeof(value.zone), "zone");
	snprintf(value.rack, sizeof(value.rack), "rack");
	snprintf(value.fabric, sizeof(value.fabric), "fabric");
	digest(value.lineage_digest, 0xB1U);
	digest(value.policy_digest, 0xB2U);
	digest(value.provider_claim_digest, 0xB3U);
	return value;
}

static void *reader(void *opaque)
{
	struct context *context = opaque;
	unsigned int i;

	for (i = 0U; i < READ_ROUNDS; ++i) {
		struct fpl_workload workload;
		uint64_t id = (uint64_t)(i % WORKLOADS) + 1U;
		if (fpl_query(context->service, id, &workload) != FPL_OK ||
		    workload.intent.workload_id != id)
			atomic_fetch_add(&context->failures, 1);
	}
	return NULL;
}

static void *writer(void *opaque)
{
	struct context *context = opaque;
	struct fpl_node node;
	unsigned int i;

	memset(&node, 0, sizeof(node));
	node.node_id = 1U;
	node.generation = 1U;
	node.total_cpu_millis = 1000000U;
	node.free_cpu_millis = 1000000U - WORKLOADS * 10U;
	node.total_memory_bytes = 1ULL << 40;
	node.free_memory_bytes = node.total_memory_bytes - WORKLOADS * (1ULL << 20);
	node.total_network_mbps = 1000000U;
	node.free_network_mbps = node.total_network_mbps - WORKLOADS;
	node.total_storage_bytes = 1ULL << 50;
	node.free_storage_bytes = node.total_storage_bytes - WORKLOADS * (1ULL << 20);
	node.accelerator_mask = 1U;
	node.accelerator_count = 8U;
	node.capability_mask = FLE_CAP_INFERENCE;
	node.provider_mask = 1U;
	node.health_ppm = 1000000U;
	node.state = FPL_NODE_READY;
	snprintf(node.provider, sizeof(node.provider), "kuberay");
	snprintf(node.zone, sizeof(node.zone), "zone");
	snprintf(node.rack, sizeof(node.rack), "rack");
	snprintf(node.fabric, sizeof(node.fabric), "fabric");
	digest(node.attestation_digest, 0xC1U);
	for (i = 0U; i < READ_ROUNDS; ++i)
		if (fpl_heartbeat(context->service, &node) != FPL_OK)
			atomic_fetch_add(&context->failures, 1);
	return NULL;
}

int main(void)
{
	char path[128];
	struct fpl_service service;
	struct fpl_policy configured = policy();
	struct fpl_node node;
	struct context context;
	pthread_t readers[READERS];
	pthread_t writer_thread;
	unsigned int i;
	int result;

	memset(&node, 0, sizeof(node));
	node.node_id = 1U;
	node.generation = 1U;
	node.total_cpu_millis = 1000000U;
	node.free_cpu_millis = node.total_cpu_millis;
	node.total_memory_bytes = 1ULL << 40;
	node.free_memory_bytes = node.total_memory_bytes;
	node.total_network_mbps = 1000000U;
	node.free_network_mbps = node.total_network_mbps;
	node.total_storage_bytes = 1ULL << 50;
	node.free_storage_bytes = node.total_storage_bytes;
	node.accelerator_mask = 1U;
	node.accelerator_count = 8U;
	node.capability_mask = FLE_CAP_INFERENCE;
	node.provider_mask = 1U;
	node.health_ppm = 1000000U;
	node.state = FPL_NODE_READY;
	snprintf(node.provider, sizeof(node.provider), "kuberay");
	snprintf(node.zone, sizeof(node.zone), "zone");
	snprintf(node.rack, sizeof(node.rack), "rack");
	snprintf(node.fabric, sizeof(node.fabric), "fabric");
	digest(node.attestation_digest, 0xC1U);
	snprintf(path, sizeof(path), "/tmp/faisal-platform-concurrency-%ld.journal", (long)getpid());
	unlink(path);
	if (fpl_open(&service, path, &configured) != FPL_OK ||
	    fpl_add_node(&service, &node) != FPL_OK)
		return 1;
	for (i = 0U; i < WORKLOADS; ++i) {
		struct fpl_intent value = request((uint64_t)i + 1U);
		struct fpl_workload workload;
		if (fpl_submit(&service, &value, &workload) != FPL_OK ||
		    fpl_place(&service, value.workload_id, &workload) != FPL_OK)
			return 1;
	}
	context.service = &service;
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
	result = atomic_load(&context.failures);
	fpl_close(&service);
	unlink(path);
	printf("M245_PLATFORM_CONCURRENCY_EXIT=%d readers=%u workloads=%u read_rounds=%u writer_rounds=%u failures=%d\n",
	       result == 0 ? 0 : 1, READERS, WORKLOADS, READ_ROUNDS,
	       READ_ROUNDS, result);
	return result == 0 ? 0 : 1;
}
