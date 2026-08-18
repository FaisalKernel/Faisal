#ifndef FAISAL_FABRIC_H
#define FAISAL_FABRIC_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FF_ABI_VERSION 1U
#define FF_DIGEST_SIZE 32U
#define FF_MAX_NODES 64U
#define FF_MAX_SHARDS 256U
#define FF_MAX_LEASES 512U
#define FF_MAX_EVENTS 4096U
#define FF_MAX_PAYLOAD 768U
#define FF_MAX_NAME 64U
#define FF_EVENT_MAGIC 0x46464231U
#define FF_EVENT_VERSION 1U
#define FF_FLAG_AUTHORITY_GRANTED (1U << 0)
#define FF_FLAG_VERIFIED_INPUT (1U << 1)
#define FF_FLAG_REQUIRES_LOCALITY (1U << 2)
#define FF_FLAG_MIGRATION_ALLOWED (1U << 3)
#define FF_FLAGS_ALL (FF_FLAG_AUTHORITY_GRANTED | FF_FLAG_VERIFIED_INPUT | \
			  FF_FLAG_REQUIRES_LOCALITY | FF_FLAG_MIGRATION_ALLOWED)

enum ff_node_state {
	FF_NODE_HEALTHY = 1U,
	FF_NODE_DRAINING = 2U,
	FF_NODE_QUARANTINED = 3U,
	FF_NODE_OFFLINE = 4U
};

enum ff_shard_state {
	FF_SHARD_PENDING = 1U,
	FF_SHARD_PLACED = 2U,
	FF_SHARD_RUNNING = 3U,
	FF_SHARD_MIGRATING = 4U,
	FF_SHARD_RECOVERY = 5U,
	FF_SHARD_BACKPRESSURED = 6U,
	FF_SHARD_COMPLETED = 7U,
	FF_SHARD_QUARANTINED = 8U
};

enum ff_lease_state {
	FF_LEASE_ACTIVE = 1U,
	FF_LEASE_RELEASED = 2U,
	FF_LEASE_EXPIRED = 3U,
	FF_LEASE_QUARANTINED = 4U
};

enum ff_event_kind {
	FF_EVENT_REGISTER_NODE = 1U,
	FF_EVENT_SUBMIT_SHARD = 2U,
	FF_EVENT_LEASE = 3U,
	FF_EVENT_NODE_QUARANTINE = 4U,
	FF_EVENT_BACKPRESSURE = 5U
};

enum ff_status {
	FF_OK = 0,
	FF_ERR_ARGUMENT = -1,
	FF_ERR_IO = -2,
	FF_ERR_FULL = -3,
	FF_ERR_NOT_FOUND = -4,
	FF_ERR_DUPLICATE = -5,
	FF_ERR_STATE = -6,
	FF_ERR_AUTHORITY = -7,
	FF_ERR_GENERATION = -8,
	FF_ERR_DEADLINE = -9,
	FF_ERR_NO_CAPACITY = -10,
	FF_ERR_TAMPER = -11,
	FF_ERR_REPLAY = -12,
	FF_ERR_TOPOLOGY = -13,
	FF_ERR_EXPIRED = -14,
	FF_ERR_OVERFLOW = -15,
	FF_ERR_QUARANTINED = -16,
	FF_ERR_CORRUPT = -17,
	FF_ERR_BACKPRESSURE = -18
};

struct ff_resource_vector {
	uint64_t cpu_ns;
	uint64_t memory_bytes;
	uint64_t gpu_ns;
	uint64_t npu_ns;
	uint64_t network_bytes;
	uint64_t storage_bytes;
	uint64_t cost_micro;
	uint64_t energy_uj;
};

struct ff_policy {
	uint64_t current_time_ns;
	uint64_t observation_max_age_ns;
	uint64_t default_lease_ns;
	uint64_t max_lease_ns;
	uint32_t minimum_priority;
	uint32_t max_queue_depth;
	uint32_t require_authority;
	uint32_t require_verified_input;
};

struct ff_node {
	uint64_t node_id;
	uint64_t generation;
	uint64_t observed_at_ns;
	uint32_t state;
	uint32_t health_permille;
	uint32_t pressure_permille;
	uint32_t thermal_permille;
	uint32_t forecast_permille;
	struct ff_resource_vector capacity;
	struct ff_resource_vector available;
	uint64_t numa_mask;
	uint64_t accelerator_mask;
	uint8_t identity_digest[FF_DIGEST_SIZE];
	uint8_t topology_digest[FF_DIGEST_SIZE];
	char name[FF_MAX_NAME];
};

struct ff_shard {
	uint64_t shard_id;
	uint64_t objective_id;
	uint64_t agent_id;
	uint64_t tenant_id;
	uint64_t trace_id;
	uint64_t task_generation;
	uint64_t session_generation;
	uint64_t issued_at_ns;
	uint64_t deadline_ns;
	uint64_t node_id;
	uint64_t node_generation;
	uint64_t lease_id;
	uint64_t placement_generation;
	uint32_t state;
	uint32_t priority;
	uint32_t flags;
	struct ff_resource_vector demand;
	uint8_t budget_receipt_digest[FF_DIGEST_SIZE];
	uint8_t provenance_digest[FF_DIGEST_SIZE];
	uint8_t locality_digest[FF_DIGEST_SIZE];
	uint8_t request_digest[FF_DIGEST_SIZE];
	char name[FF_MAX_NAME];
};

struct ff_lease {
	uint64_t lease_id;
	uint64_t shard_id;
	uint64_t node_id;
	uint64_t previous_node_id;
	uint64_t node_generation;
	uint64_t lease_generation;
	uint64_t issued_at_ns;
	uint64_t expiry_ns;
	uint32_t state;
	uint32_t shard_state;
	struct ff_resource_vector demand;
	uint8_t shard_request_digest[FF_DIGEST_SIZE];
	uint8_t node_identity_digest[FF_DIGEST_SIZE];
	uint8_t lease_digest[FF_DIGEST_SIZE];
};

struct ff_event {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint64_t node_id;
	uint64_t shard_id;
	uint64_t lease_id;
	uint64_t observed_at_ns;
	int32_t status;
	uint32_t payload_len;
	uint8_t previous_digest[FF_DIGEST_SIZE];
	uint8_t payload_digest[FF_DIGEST_SIZE];
	uint8_t event_digest[FF_DIGEST_SIZE];
};

struct ff_journal_attestation {
	uint64_t last_sequence;
	uint64_t record_count;
	uint64_t node_count;
	uint64_t shard_count;
	uint64_t lease_count;
	uint64_t backpressure_count;
	uint8_t chain_digest[FF_DIGEST_SIZE];
};

struct ff_disk_record {
	struct ff_event event;
	uint8_t payload[FF_MAX_PAYLOAD];
};

struct ff_service {
	int journal_fd;
	pthread_mutex_t lock;
	struct ff_policy policy;
	struct ff_node nodes[FF_MAX_NODES];
	struct ff_shard shards[FF_MAX_SHARDS];
	struct ff_lease leases[FF_MAX_LEASES];
	size_t node_count;
	size_t shard_count;
	size_t lease_count;
	uint64_t next_node_id;
	uint64_t next_shard_id;
	uint64_t next_lease_id;
	uint64_t event_sequence;
	uint64_t backpressure_count;
	uint8_t chain_digest[FF_DIGEST_SIZE];
};

int ff_open(struct ff_service *service, const char *journal_path,
	    const struct ff_policy *policy);
void ff_close(struct ff_service *service);
int ff_register_node(struct ff_service *service, const struct ff_node *observation,
		     struct ff_node *out);
int ff_submit_shard(struct ff_service *service, const struct ff_shard *request,
		   struct ff_shard *out);
int ff_place_shard(struct ff_service *service, uint64_t shard_id,
		  uint64_t now_ns, struct ff_shard *out, struct ff_lease *lease_out);
int ff_renew_lease(struct ff_service *service, uint64_t lease_id,
		  uint64_t now_ns, uint64_t extension_ns, struct ff_lease *out);
int ff_migrate_shard(struct ff_service *service, uint64_t shard_id,
		     uint64_t now_ns, struct ff_shard *shard_out,
		     struct ff_lease *lease_out);
int ff_release_lease(struct ff_service *service, uint64_t lease_id,
		     uint64_t now_ns, struct ff_shard *shard_out);
int ff_quarantine_node(struct ff_service *service, uint64_t node_id,
		       uint64_t now_ns, struct ff_node *out);
int ff_recover_expired(struct ff_service *service, uint64_t now_ns,
		       uint32_t *recovered, uint32_t *unrecoverable);
int ff_query_node(const struct ff_service *service, uint64_t node_id,
		  struct ff_node *out);
int ff_query_shard(const struct ff_service *service, uint64_t shard_id,
		   struct ff_shard *out);
int ff_query_journal(const struct ff_service *service,
		    struct ff_journal_attestation *out);
int ff_verify_event(const struct ff_event *event, const uint8_t *payload,
		   const uint8_t previous_digest[FF_DIGEST_SIZE]);

#endif
