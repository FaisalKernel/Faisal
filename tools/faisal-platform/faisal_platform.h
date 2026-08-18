#ifndef FAISAL_PLATFORM_H
#define FAISAL_PLATFORM_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../faisal-fleet/faisal_fleet_intent.h"

#define FPL_ABI_VERSION 1U
#define FPL_EVENT_MAGIC 0x46504c31U
#define FPL_EVENT_VERSION 1U
#define FPL_DIGEST_SIZE 32U
#define FPL_MAX_NODES 64U
#define FPL_MAX_WORKLOADS 64U
#define FPL_MAX_GANG 8U
#define FPL_MAX_NAME 96U
#define FPL_MAX_DOMAIN 64U
#define FPL_MAX_PROVIDER 48U
#define FPL_MAX_REASON 192U
#define FPL_MAX_PAYLOAD 65536U
#define FPL_MAX_RECOVERY_ATTEMPTS 8U

#define FPL_REQUIRE_AUTHORITY (1U << 0)
#define FPL_REQUIRE_LINEAGE (1U << 1)
#define FPL_REQUIRE_TOPOLOGY (1U << 2)
#define FPL_FAIL_CLOSED (1U << 3)

#define FPL_NODE_READY 1U
#define FPL_NODE_DRAINING 2U
#define FPL_NODE_FAILED 3U
#define FPL_NODE_QUARANTINED 4U

#define FPL_WORKLOAD_SUBMITTED 1U
#define FPL_WORKLOAD_PLACED 2U
#define FPL_WORKLOAD_CHECKPOINTED 3U
#define FPL_WORKLOAD_COMPLETED 4U
#define FPL_WORKLOAD_FAILED 5U
#define FPL_WORKLOAD_RECOVERING 6U
#define FPL_WORKLOAD_REJECTED 7U
#define FPL_WORKLOAD_CANCELLED 8U

#define FPL_EVENT_NODE_UPSERT 1U
#define FPL_EVENT_NODE_FAILURE 2U
#define FPL_EVENT_WORKLOAD_SUBMIT 3U
#define FPL_EVENT_WORKLOAD_SNAPSHOT 4U
#define FPL_EVENT_WORKLOAD_CHECKPOINT 5U
#define FPL_EVENT_WORKLOAD_COMPLETE 6U
#define FPL_EVENT_WORKLOAD_FAILURE 7U
#define FPL_EVENT_WORKLOAD_RECOVERY 8U

#define FPL_PROVIDER_KUBERNETES_DRA 1U
#define FPL_PROVIDER_KUBERAY 2U
#define FPL_PROVIDER_DYNAMO 3U
#define FPL_PROVIDER_RAY 4U
#define FPL_PROVIDER_BARE_METAL 5U
#define FPL_PROVIDER_EDGE 6U

#define FPL_VIOLATION_AUTHORITY (1U << 0)
#define FPL_VIOLATION_LINEAGE (1U << 1)
#define FPL_VIOLATION_GENERATION (1U << 2)
#define FPL_VIOLATION_RESOURCE (1U << 3)
#define FPL_VIOLATION_TOPOLOGY (1U << 4)
#define FPL_VIOLATION_HEALTH (1U << 5)
#define FPL_VIOLATION_DEADLINE (1U << 6)
#define FPL_VIOLATION_PROVIDER (1U << 7)

enum fpl_status {
	FPL_OK = 0,
	FPL_ERR_ARGUMENT = -1,
	FPL_ERR_IO = -2,
	FPL_ERR_CORRUPT = -3,
	FPL_ERR_FULL = -4,
	FPL_ERR_NOT_FOUND = -5,
	FPL_ERR_STATE = -6,
	FPL_ERR_STALE = -7,
	FPL_ERR_POLICY = -8,
	FPL_ERR_NO_PLACEMENT = -9,
	FPL_ERR_AUTHORITY = -10,
	FPL_ERR_GENERATION = -11,
	FPL_ERR_DEADLINE = -12,
	FPL_ERR_PROVIDER = -13,
	FPL_ERR_RECOVERY = -14,
	FPL_ERR_TAMPER = -15,
	FPL_ERR_REPLAY = -16,
	FPL_ERR_OVERFLOW = -17
};

struct fpl_policy {
	uint64_t current_time_ns;
	uint64_t max_intent_age_ns;
	uint32_t flags;
	uint32_t max_workloads;
	uint32_t max_recovery_attempts;
	uint32_t reserved;
	uint8_t authority_digest[FPL_DIGEST_SIZE];
};

struct fpl_node {
	uint64_t node_id;
	uint64_t generation;
	uint64_t total_cpu_millis;
	uint64_t free_cpu_millis;
	uint64_t total_memory_bytes;
	uint64_t free_memory_bytes;
	uint64_t total_network_mbps;
	uint64_t free_network_mbps;
	uint64_t total_storage_bytes;
	uint64_t free_storage_bytes;
	uint32_t accelerator_mask;
	uint32_t accelerator_count;
	uint32_t capability_mask;
	uint32_t provider_mask;
	uint32_t health_ppm;
	uint32_t state;
	char provider[FPL_MAX_PROVIDER];
	char zone[FPL_MAX_DOMAIN];
	char rack[FPL_MAX_DOMAIN];
	char fabric[FPL_MAX_DOMAIN];
	uint8_t attestation_digest[FPL_DIGEST_SIZE];
};

struct fpl_intent {
	uint32_t abi_version;
	uint32_t provider_kind;
	uint64_t workload_id;
	uint64_t tenant_id;
	uint64_t agent_id;
	uint64_t objective_id;
	uint64_t created_at_ns;
	uint64_t deadline_ns;
	uint64_t required_cpu_millis;
	uint64_t required_memory_bytes;
	uint64_t required_network_mbps;
	uint64_t required_storage_bytes;
	uint32_t required_accelerator_mask;
	uint32_t required_accelerator_count;
	uint32_t required_capability_mask;
	uint32_t replicas;
	uint32_t gang_size;
	uint32_t priority;
	uint32_t preemption_class;
	uint32_t authorized;
	uint32_t allow_recovery;
	char tenant[FPL_MAX_NAME];
	char model_id[FPL_MAX_NAME];
	char objective[FPL_MAX_NAME];
	char zone[FPL_MAX_DOMAIN];
	char rack[FPL_MAX_DOMAIN];
	char fabric[FPL_MAX_DOMAIN];
	uint8_t lineage_digest[FPL_DIGEST_SIZE];
	uint8_t policy_digest[FPL_DIGEST_SIZE];
	uint8_t checkpoint_digest[FPL_DIGEST_SIZE];
	uint8_t provider_claim_digest[FPL_DIGEST_SIZE];
};

struct fpl_assignment {
	uint64_t assignment_id;
	uint64_t workload_id;
	uint64_t placement_generation;
	uint64_t recovery_sequence;
	uint32_t state;
	uint32_t selected_count;
	uint32_t violation_mask;
	uint32_t score;
	uint64_t selected_nodes[FPL_MAX_GANG];
	uint8_t evidence_digest[FPL_DIGEST_SIZE];
	char reason[FPL_MAX_REASON];
};

struct fpl_workload {
	struct fpl_intent intent;
	struct fpl_assignment assignment;
	uint64_t checkpoint_sequence;
	uint64_t last_transition_ns;
	uint32_t state;
	uint32_t recovery_attempts;
	uint32_t failure_class;
	uint32_t reserved;
	uint8_t checkpoint_digest[FPL_DIGEST_SIZE];
	char failure_reason[FPL_MAX_REASON];
};

struct fpl_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t workload_id;
	uint64_t node_id;
	uint64_t generation;
	uint64_t observed_at_ns;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FPL_DIGEST_SIZE];
	uint8_t payload_digest[FPL_DIGEST_SIZE];
	uint8_t event_digest[FPL_DIGEST_SIZE];
};

struct fpl_disk_record {
	struct fpl_event event;
	uint8_t payload[FPL_MAX_PAYLOAD];
};

struct fpl_cluster_snapshot {
	struct fpl_workload workload;
	uint32_t node_count;
	uint32_t reserved;
	struct fpl_node nodes[FPL_MAX_NODES];
};

struct fpl_attestation {
	uint64_t last_sequence;
	uint64_t next_workload_id;
	uint64_t next_assignment_id;
	uint64_t recovery_count;
	uint64_t failed_nodes;
	uint8_t chain_digest[FPL_DIGEST_SIZE];
};

struct fpl_service {
	int journal_fd;
	pthread_mutex_t lock;
	struct fpl_policy policy;
	struct fpl_node nodes[FPL_MAX_NODES];
	struct fpl_workload workloads[FPL_MAX_WORKLOADS];
	size_t node_count;
	size_t workload_count;
	uint64_t next_assignment_id;
	uint64_t next_sequence;
	uint64_t recovery_count;
	uint64_t failed_nodes;
	uint8_t chain_digest[FPL_DIGEST_SIZE];
};

int fpl_open(struct fpl_service *service, const char *journal_path,
	     const struct fpl_policy *policy);
void fpl_close(struct fpl_service *service);
int fpl_replay(struct fpl_service *service);
int fpl_query_attestation(const struct fpl_service *service,
			  struct fpl_attestation *out);
int fpl_add_node(struct fpl_service *service, const struct fpl_node *node);
int fpl_heartbeat(struct fpl_service *service, const struct fpl_node *node);
int fpl_fail_node(struct fpl_service *service, uint64_t node_id,
		  uint64_t generation);
int fpl_submit(struct fpl_service *service, const struct fpl_intent *intent,
	      struct fpl_workload *out);
int fpl_place(struct fpl_service *service, uint64_t workload_id,
	     struct fpl_workload *out);
int fpl_checkpoint(struct fpl_service *service, uint64_t workload_id,
		   uint64_t now_ns,
		   const uint8_t checkpoint_digest[FPL_DIGEST_SIZE]);
int fpl_complete(struct fpl_service *service, uint64_t workload_id,
		 const uint8_t result_digest[FPL_DIGEST_SIZE]);
int fpl_fail(struct fpl_service *service, uint64_t workload_id,
	    uint64_t now_ns, uint32_t failure_class, const char *reason,
	    int retryable);
int fpl_recover(struct fpl_service *service, uint64_t workload_id,
	       uint64_t now_ns, struct fpl_workload *out);
int fpl_query(const struct fpl_service *service, uint64_t workload_id,
	      struct fpl_workload *out);
int fpl_test_model_output_untrusted(struct fpl_service *service,
				    const struct fpl_intent *intent);
int fpl_test_corrupt_tail(const struct fpl_service *service);

#endif
