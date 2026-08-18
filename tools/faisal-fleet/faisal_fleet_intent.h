#ifndef FAISAL_FLEET_INTENT_H
#define FAISAL_FLEET_INTENT_H

#include <stddef.h>
#include <stdint.h>

#define FLE_ABI_VERSION 1U
#define FLE_MAX_NODES 32U
#define FLE_MAX_ASSIGNMENTS 32U
#define FLE_MAX_GANG 8U
#define FLE_MAX_NAME 64U
#define FLE_MAX_DOMAIN 64U
#define FLE_DIGEST_SIZE 32U
#define FLE_STATE_READY 1U
#define FLE_STATE_DRAINING 2U
#define FLE_STATE_FAILED 3U
#define FLE_ASSIGN_PLACED 1U
#define FLE_ASSIGN_RECOVERING 2U
#define FLE_ASSIGN_RECOVERED 3U
#define FLE_ASSIGN_REJECTED 4U
#define FLE_CAP_INFERENCE 1U
#define FLE_CAP_TRAINING 2U
#define FLE_CAP_MEMORY_TIER 4U
#define FLE_CAP_NETWORK_FABRIC 8U
#define FLE_POLICY_FAIL_CLOSED 1U
#define FLE_POLICY_REQUIRE_LINEAGE 2U
#define FLE_POLICY_REQUIRE_AUTHORITY 4U
#define FLE_POLICY_REQUIRE_TOPOLOGY 8U
#define FLE_VIOLATION_AUTHORITY 1U
#define FLE_VIOLATION_LINEAGE 2U
#define FLE_VIOLATION_GENERATION 4U
#define FLE_VIOLATION_RESOURCE 8U
#define FLE_VIOLATION_TOPOLOGY 16U
#define FLE_VIOLATION_HEALTH 32U

enum fle_status {
	FLE_OK = 0,
	FLE_ERR_ARGUMENT = -1,
	FLE_ERR_FULL = -2,
	FLE_ERR_DUPLICATE = -3,
	FLE_ERR_POLICY = -4,
	FLE_ERR_NO_PLACEMENT = -5,
	FLE_ERR_NOT_FOUND = -6,
	FLE_ERR_STALE = -7,
	FLE_ERR_CONFLICT = -8,
	FLE_ERR_AUTHORITY = -9
};

struct fle_node {
	uint64_t node_id;
	uint64_t generation;
	uint64_t total_cpu_millis;
	uint64_t free_cpu_millis;
	uint64_t total_memory_bytes;
	uint64_t free_memory_bytes;
	uint32_t accelerator_mask;
	uint32_t accelerator_count;
	uint32_t capability_mask;
	uint32_t health_ppm;
	uint32_t state;
	char zone[FLE_MAX_DOMAIN];
	char rack[FLE_MAX_DOMAIN];
	char fabric[FLE_MAX_DOMAIN];
};

struct fle_intent {
	uint32_t abi_version;
	uint32_t policy_flags;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t agent_id;
	uint64_t expected_node_generation;
	uint64_t deadline_ns;
	uint64_t required_cpu_millis;
	uint64_t required_memory_bytes;
	uint32_t required_accelerator_mask;
	uint32_t required_accelerator_count;
	uint32_t required_capability_mask;
	uint32_t gang_size;
	uint32_t preemption_class;
	uint32_t authorized;
	char tenant[FLE_MAX_NAME];
	char objective[FLE_MAX_NAME];
	char zone[FLE_MAX_DOMAIN];
	char rack[FLE_MAX_DOMAIN];
	char fabric[FLE_MAX_DOMAIN];
	uint8_t lineage_digest[FLE_DIGEST_SIZE];
	uint8_t policy_digest[FLE_DIGEST_SIZE];
};

struct fle_assignment {
	uint64_t assignment_id;
	uint64_t objective_id;
	uint64_t tenant_id;
	uint64_t agent_id;
	uint64_t placement_sequence;
	uint64_t recovery_sequence;
	uint32_t state;
	uint32_t selected_count;
	uint32_t violation_mask;
	uint32_t score;
	uint64_t selected_nodes[FLE_MAX_GANG];
	uint8_t evidence_digest[FLE_DIGEST_SIZE];
	char reason[FLE_MAX_NAME * 2];
};

struct fle_service {
	uint32_t policy_flags;
	uint64_t next_assignment_id;
	uint64_t next_sequence;
	uint64_t now_ns;
	struct fle_node nodes[FLE_MAX_NODES];
	struct fle_assignment assignments[FLE_MAX_ASSIGNMENTS];
	size_t node_count;
	size_t assignment_count;
};

int fle_init(struct fle_service *service, uint32_t policy_flags, uint64_t now_ns);
int fle_add_node(struct fle_service *service, const struct fle_node *node);
int fle_validate_intent(const struct fle_service *service,
	const struct fle_intent *intent);
int fle_place(struct fle_service *service, const struct fle_intent *intent,
	struct fle_assignment *out);
int fle_fail_node(struct fle_service *service, uint64_t node_id,
	uint64_t generation);
int fle_recover(struct fle_service *service, uint64_t assignment_id,
	const struct fle_intent *intent, struct fle_assignment *out);
int fle_query_assignment(const struct fle_service *service, uint64_t assignment_id,
	struct fle_assignment *out);
int fle_test_policy_boundaries(struct fle_service *service);

#endif
