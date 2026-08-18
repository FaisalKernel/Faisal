#include "../../faisal-fleet/faisal_fleet_intent.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FLE_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static struct fle_node make_node(uint64_t id, uint64_t generation,
	const char *zone, const char *rack, const char *fabric, uint32_t health)
{
	struct fle_node node;
	memset(&node, 0, sizeof(node));
	node.node_id = id;
	node.generation = generation;
	node.total_cpu_millis = 16000;
	node.free_cpu_millis = 12000;
	node.total_memory_bytes = 64ULL << 30;
	node.free_memory_bytes = 48ULL << 30;
	node.accelerator_mask = FLE_CAP_INFERENCE;
	node.accelerator_count = 1;
	node.capability_mask = FLE_CAP_INFERENCE | FLE_CAP_NETWORK_FABRIC;
	node.health_ppm = health;
	node.state = FLE_STATE_READY;
	strncpy(node.zone, zone, sizeof(node.zone) - 1);
	strncpy(node.rack, rack, sizeof(node.rack) - 1);
	strncpy(node.fabric, fabric, sizeof(node.fabric) - 1);
	return node;
}

static void seed_intent(struct fle_intent *intent)
{
	memset(intent, 0, sizeof(*intent));
	intent->abi_version = FLE_ABI_VERSION;
	intent->policy_flags = FLE_POLICY_FAIL_CLOSED | FLE_POLICY_REQUIRE_LINEAGE |
		FLE_POLICY_REQUIRE_AUTHORITY | FLE_POLICY_REQUIRE_TOPOLOGY;
	intent->objective_id = 7001;
	intent->tenant_id = 44;
	intent->agent_id = 9001;
	intent->expected_node_generation = 1;
	intent->deadline_ns = 1000000000ULL;
	intent->required_cpu_millis = 1000;
	intent->required_memory_bytes = 1ULL << 30;
	intent->required_accelerator_mask = FLE_CAP_INFERENCE;
	intent->required_accelerator_count = 1;
	intent->required_capability_mask = FLE_CAP_INFERENCE;
	intent->gang_size = 2;
	intent->preemption_class = 2;
	intent->authorized = 1;
	strcpy(intent->tenant, "tenant-44");
	strcpy(intent->objective, "agent-inference-team");
	strcpy(intent->zone, "zone-a");
	strcpy(intent->rack, "rack-1");
	strcpy(intent->fabric, "fabric-a");
	intent->lineage_digest[0] = 0x71;
	intent->policy_digest[0] = 0x22;
}

int main(void)
{
	struct fle_service service;
	struct fle_intent intent;
	struct fle_assignment assignment, recovered, queried;
	struct fle_node node1, node2, node3, node4;

	if (fle_init(&service, FLE_POLICY_FAIL_CLOSED | FLE_POLICY_REQUIRE_LINEAGE |
		FLE_POLICY_REQUIRE_AUTHORITY | FLE_POLICY_REQUIRE_TOPOLOGY, 100) != FLE_OK)
		return fail("init", -1);
	node1 = make_node(1, 1, "zone-a", "rack-1", "fabric-a", 990000);
	node2 = make_node(2, 1, "zone-a", "rack-1", "fabric-a", 980000);
	node3 = make_node(3, 1, "zone-b", "rack-2", "fabric-b", 999000);
	node4 = make_node(4, 1, "zone-a", "rack-2", "fabric-a", 970000);
	if (fle_add_node(&service, &node1) != FLE_OK ||
		fle_add_node(&service, &node2) != FLE_OK ||
		fle_add_node(&service, &node3) != FLE_OK ||
		fle_add_node(&service, &node4) != FLE_OK)
		return fail("node admission", -1);
	seed_intent(&intent);
	if (fle_place(&service, &intent, &assignment) != FLE_OK ||
		assignment.state != FLE_ASSIGN_PLACED || assignment.selected_count != 2 ||
		assignment.selected_nodes[0] != 1 || assignment.selected_nodes[1] != 2 ||
		!assignment.evidence_digest[0])
		return fail("topology placement", -1);
	printf("FLE_TOPOLOGY_GANG_PLACEMENT_OK nodes=%llu,%llu score=%u\n",
		(unsigned long long)assignment.selected_nodes[0],
		(unsigned long long)assignment.selected_nodes[1], assignment.score);

	intent.expected_node_generation = 1;
	if (fle_fail_node(&service, 1, 1) != FLE_OK)
		return fail("node failure", -1);
	intent.rack[0] = '\0';
	if (fle_recover(&service, assignment.assignment_id, &intent, &recovered) != FLE_OK ||
		recovered.state != FLE_ASSIGN_RECOVERED || recovered.recovery_sequence == 0 ||
		recovered.selected_count != 2 || recovered.selected_nodes[0] == 1 ||
		recovered.selected_nodes[1] == 1 || !recovered.evidence_digest[0])
		return fail("recovery", -1);
	printf("FLE_NODE_FAILURE_RECOVERY_OK nodes=%llu,%llu recovery=%llu\n",
		(unsigned long long)recovered.selected_nodes[0],
		(unsigned long long)recovered.selected_nodes[1],
		(unsigned long long)recovered.recovery_sequence);

	if (fle_query_assignment(&service, assignment.assignment_id, &queried) != FLE_OK ||
		queried.state != FLE_ASSIGN_RECOVERED)
		return fail("assignment query", -1);
	printf("FLE_LINEAGE_ASSIGNMENT_QUERY_OK sequence=%llu\n",
		(unsigned long long)queried.placement_sequence);

	seed_intent(&intent);
	intent.objective_id = 7002;
	intent.authorized = 0;
	if (fle_place(&service, &intent, &assignment) == FLE_OK)
		return fail("unauthorized placement", -1);
	printf("FLE_AUTHORITY_REJECT_OK\n");
	seed_intent(&intent);
	intent.objective_id = 7003;
	intent.lineage_digest[0] = 0;
	if (fle_place(&service, &intent, &assignment) == FLE_OK)
		return fail("missing lineage placement", -1);
	printf("FLE_LINEAGE_REJECT_OK\n");
	seed_intent(&intent);
	intent.objective_id = 7004;
	intent.expected_node_generation = 2;
	if (fle_place(&service, &intent, &assignment) == FLE_OK)
		return fail("stale generation placement", -1);
	printf("FLE_GENERATION_POLICY_REJECT_OK\n");
	if (fle_test_policy_boundaries(&service) != FLE_OK)
		return fail("policy helper", -1);
	printf("FLE_SELFTEST_EXIT=0\n");
	return 0;
}
