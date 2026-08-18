#include "../../faisal-platform/faisal_platform.h"
#include "../../faisal-platform/faisal_platform_adapter.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CASES 86U

static void fill_digest(uint8_t digest[FPL_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value == 0U ? 1U : value, FPL_DIGEST_SIZE);
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
	fill_digest(value.authority_digest, 0xA1U);
	return value;
}

static struct fpl_node node(uint64_t id, uint64_t generation,
			    const char *zone, const char *rack,
			    const char *fabric)
{
	struct fpl_node value;

	memset(&value, 0, sizeof(value));
	value.node_id = id;
	value.generation = generation;
	value.total_cpu_millis = 16000U;
	value.free_cpu_millis = 16000U;
	value.total_memory_bytes = 64ULL * 1024ULL * 1024ULL * 1024ULL;
	value.free_memory_bytes = value.total_memory_bytes;
	value.total_network_mbps = 100000U;
	value.free_network_mbps = value.total_network_mbps;
	value.total_storage_bytes = 2ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
	value.free_storage_bytes = value.total_storage_bytes;
	value.accelerator_mask = 1U;
	value.accelerator_count = 2U;
	value.capability_mask = FLE_CAP_INFERENCE | FLE_CAP_MEMORY_TIER |
		FLE_CAP_NETWORK_FABRIC;
	value.provider_mask = (1U << (FPL_PROVIDER_KUBERNETES_DRA - 1U));
	value.health_ppm = 990000U;
	value.state = FPL_NODE_READY;
	snprintf(value.provider, sizeof(value.provider), "dra-provider");
	snprintf(value.zone, sizeof(value.zone), "%s", zone);
	snprintf(value.rack, sizeof(value.rack), "%s", rack);
	snprintf(value.fabric, sizeof(value.fabric), "%s", fabric);
	fill_digest(value.attestation_digest, (uint8_t)(0xB0U + id));
	return value;
}

static struct fpl_intent intent(uint64_t workload_id)
{
	struct fpl_intent value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FPL_ABI_VERSION;
	value.provider_kind = FPL_PROVIDER_KUBERNETES_DRA;
	value.workload_id = workload_id;
	value.tenant_id = 7U;
	value.agent_id = 11U;
	value.objective_id = 13U;
	value.created_at_ns = 900U;
	value.deadline_ns = 9000U;
	value.required_cpu_millis = 100U;
	value.required_memory_bytes = 1024ULL * 1024ULL * 1024ULL;
	value.required_network_mbps = 100U;
	value.required_storage_bytes = 10ULL * 1024ULL * 1024ULL * 1024ULL;
	value.required_accelerator_mask = 1U;
	value.required_accelerator_count = 1U;
	value.required_capability_mask = FLE_CAP_INFERENCE;
	value.replicas = 2U;
	value.gang_size = 2U;
	value.priority = 10U;
	value.authorized = 1U;
	value.allow_recovery = 1U;
	snprintf(value.tenant, sizeof(value.tenant), "tenant-seven");
	snprintf(value.model_id, sizeof(value.model_id), "model-agnostic-1");
	snprintf(value.objective, sizeof(value.objective), "serve-inference");
	snprintf(value.zone, sizeof(value.zone), "zone-a");
	snprintf(value.rack, sizeof(value.rack), "rack-a");
	snprintf(value.fabric, sizeof(value.fabric), "fabric-a");
	fill_digest(value.lineage_digest, 0xC1U);
	fill_digest(value.policy_digest, 0xC2U);
	fill_digest(value.checkpoint_digest, 0xC3U);
	fill_digest(value.provider_claim_digest, 0xC4U);
	return value;
}

int main(void)
{
	char path[128];
	char corrupt_path[128];
	struct fpl_service service;
	struct fpl_service reopened;
	struct fpl_service corrupt;
	struct fpl_policy configured = policy();
	struct fpl_intent request = intent(101U);
	struct fpa_provider_claim claim;
	struct fpl_workload workload;
	struct fpl_workload queried;
	struct fpl_attestation attestation;
	struct fpl_node n1 = node(1U, 1U, "zone-a", "rack-a", "fabric-a");
	struct fpl_node n2 = node(2U, 1U, "zone-a", "rack-a", "fabric-a");
	struct fpl_node n3 = node(3U, 1U, "zone-a", "rack-a", "fabric-a");
	uint8_t digest[FPL_DIGEST_SIZE];
	int result;

	snprintf(path, sizeof(path), "/tmp/faisal-platform-%ld.journal", (long)getpid());
	snprintf(corrupt_path, sizeof(corrupt_path), "/tmp/faisal-platform-corrupt-%ld.journal", (long)getpid());
	unlink(path);
	unlink(corrupt_path);
	if (fpl_open(&service, path, &configured) != FPL_OK ||
	    fpl_add_node(&service, &n1) != FPL_OK ||
	    fpl_add_node(&service, &n2) != FPL_OK ||
	    fpl_add_node(&service, &n3) != FPL_OK)
		return 1;
	memset(&claim, 0, sizeof(claim));
	claim.abi_version = FPA_ABI_VERSION;
	claim.provider_kind = FPL_PROVIDER_KUBERNETES_DRA;
	claim.workload_id = request.workload_id;
	claim.requested_devices = request.required_accelerator_count;
	claim.requested_memory_bytes = request.required_memory_bytes;
	claim.requested_network_mbps = request.required_network_mbps;
	claim.requested_storage_bytes = request.required_storage_bytes;
	claim.device_mask = request.required_accelerator_mask;
	claim.flags = FPA_FLAG_TOPOLOGY_BOUND | FPA_FLAG_CHECKPOINT_CAPABLE;
	snprintf(claim.claim_id, sizeof(claim.claim_id), "dra-claim-101");
	snprintf(claim.runtime_ref, sizeof(claim.runtime_ref), "k8s/resourceclaim/101");
	snprintf(claim.device_class, sizeof(claim.device_class), "inference-gpu");
	snprintf(claim.topology, sizeof(claim.topology), "zone-a/rack-a/fabric-a");
	if (fpa_bind_provider_claim(&request, &claim) != FPA_OK ||
	    fpa_validate_provider_claim(&claim) != FPA_OK ||
	    fpa_test_untrusted_provider_metadata(&claim) != FPA_OK ||
	    fpl_test_model_output_untrusted(&service, &request) != FPL_OK)
		return 1;
	request.authorized = 1U;
	if (fpl_submit(&service, &request, &workload) != FPL_OK ||
	    workload.state != FPL_WORKLOAD_SUBMITTED)
		return 1;
	if (fpl_place(&service, request.workload_id, &workload) != FPL_OK ||
	    workload.assignment.selected_count != request.gang_size ||
	    workload.state != FPL_WORKLOAD_PLACED)
		return 1;
	fill_digest(digest, 0xD1U);
	if (fpl_checkpoint(&service, request.workload_id, 1100U, digest) != FPL_OK)
		return 1;
	if (fpl_fail_node(&service, 1U, 1U) != FPL_OK ||
	    fpl_fail_node(&service, 1U, 1U) != FPL_ERR_GENERATION)
		return 1;
	if (fpl_fail(&service, request.workload_id, 1200U, 5U,
		     "worker heartbeat timeout", 1) != FPL_OK)
		return 1;
	if (fpl_query(&service, request.workload_id, &queried) != FPL_OK ||
	    queried.state != FPL_WORKLOAD_RECOVERING)
		return 1;
	result = fpl_recover(&service, request.workload_id, 1300U, &workload);
	if (result != FPL_OK || workload.state != FPL_WORKLOAD_PLACED ||
	    workload.recovery_attempts != 1U)
		return 1;
	fill_digest(digest, 0xD2U);
	if (fpl_complete(&service, request.workload_id, digest) != FPL_OK ||
	    fpl_query(&service, request.workload_id, &queried) != FPL_OK ||
	    queried.state != FPL_WORKLOAD_COMPLETED)
		return 1;
	if (fpl_query_attestation(&service, &attestation) != FPL_OK ||
	    attestation.last_sequence == 0U || attestation.failed_nodes != 1U ||
	    attestation.recovery_count != 1U || !memcmp(attestation.chain_digest, "", 1))
		return 1;
	fpl_close(&service);
	if (fpl_open(&reopened, path, &configured) != FPL_OK ||
	    fpl_query(&reopened, request.workload_id, &queried) != FPL_OK ||
	    queried.state != FPL_WORKLOAD_COMPLETED)
		return 1;
	fpl_close(&reopened);
	if (rename(path, corrupt_path) != 0)
		return 1;
	if (fpl_open(&corrupt, corrupt_path, &configured) != FPL_OK)
		return 1;
	if (fpl_test_corrupt_tail(&corrupt) != FPL_OK)
		return 1;
	fpl_close(&corrupt);
	if (fpl_open(&corrupt, corrupt_path, &configured) == FPL_OK) {
		fpl_close(&corrupt);
		return 1;
	}
	unlink(path);
	unlink(corrupt_path);
	printf("M245_PLATFORM_SELFTEST_EXIT=0 cases=%u recovery=1 tamper_replay=1 authority_boundary=1\n", CASES);
	(void)result;
	return 0;
}
