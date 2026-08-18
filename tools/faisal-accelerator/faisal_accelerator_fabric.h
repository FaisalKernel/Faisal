#ifndef FAISAL_ACCELERATOR_FABRIC_H
#define FAISAL_ACCELERATOR_FABRIC_H

#include <stddef.h>
#include <stdint.h>

#define FAF_ABI_VERSION 1U
#define FAF_MAX_DEVICES 32U
#define FAF_MAX_LINKS 128U
#define FAF_MAX_REGIONS 128U
#define FAF_MAX_COLLECTIVES 64U
#define FAF_MAX_PARTICIPANTS 16U
#define FAF_MAX_NAME 64U
#define FAF_DIGEST_SIZE 32U
#define FAF_POLICY_FAIL_CLOSED 1U
#define FAF_POLICY_REQUIRE_AUTHORITY 2U
#define FAF_POLICY_REQUIRE_PROVENANCE 4U
#define FAF_DEVICE_READY 1U
#define FAF_DEVICE_DRAINING 2U
#define FAF_DEVICE_LOST 3U
#define FAF_REGION_HOST 1U
#define FAF_REGION_DEVICE 2U
#define FAF_REGION_SHARED 3U
#define FAF_REGION_REMOTE 4U
#define FAF_REGION_ACTIVE 1U
#define FAF_REGION_RELEASED 2U
#define FAF_ACCESS_READ 1U
#define FAF_ACCESS_WRITE 2U
#define FAF_ACCESS_DMA 4U
#define FAF_ACCESS_PEER 8U
#define FAF_LINK_PCIE 1U
#define FAF_LINK_NVLINK 2U
#define FAF_LINK_XGMI 3U
#define FAF_LINK_FABRIC 4U
#define FAF_LINK_NETWORK 5U
#define FAF_OP_ALLREDUCE 1U
#define FAF_OP_ALLGATHER 2U
#define FAF_OP_REDUCE 3U
#define FAF_OP_BROADCAST 4U
#define FAF_OP_REDUCESCATTER 5U
#define FAF_OP_ALLTOALL 6U
#define FAF_COLLECTIVE_QUEUED 1U
#define FAF_COLLECTIVE_COMPLETED 2U
#define FAF_COLLECTIVE_ABORTED 3U
#define FAF_VIOLATION_AUTHORITY 1U
#define FAF_VIOLATION_PROVENANCE 2U
#define FAF_VIOLATION_DEVICE_LOST 4U
#define FAF_VIOLATION_GENERATION 8U
#define FAF_VIOLATION_TOPOLOGY 16U
#define FAF_VIOLATION_ACCESS 32U

enum faf_status {
	FAF_OK = 0,
	FAF_ERR_ARGUMENT = -1,
	FAF_ERR_FULL = -2,
	FAF_ERR_DUPLICATE = -3,
	FAF_ERR_NOT_FOUND = -4,
	FAF_ERR_POLICY = -5,
	FAF_ERR_CAPACITY = -6,
	FAF_ERR_TOPOLOGY = -7,
	FAF_ERR_STALE = -8,
	FAF_ERR_STATE = -9,
	FAF_ERR_AUTHORITY = -10,
	FAF_ERR_UNSUPPORTED = -11
};

struct faf_device {
	uint64_t device_id;
	uint64_t generation;
	uint64_t memory_bytes;
	uint64_t free_memory_bytes;
	uint32_t capability_mask;
	uint32_t health_ppm;
	uint32_t state;
	uint32_t provider_kind;
	char name[FAF_MAX_NAME];
};

struct faf_link {
	uint64_t link_id;
	uint64_t src_device_id;
	uint64_t dst_device_id;
	uint64_t generation;
	uint64_t bandwidth_bytes_s;
	uint64_t latency_ns;
	uint32_t kind;
	uint32_t access_mask;
};

struct faf_region {
	uint64_t region_id;
	uint64_t owner_agent_id;
	uint64_t device_id;
	uint64_t device_generation;
	uint64_t size_bytes;
	uint64_t capability;
	uint32_t tier;
	uint32_t access_mask;
	uint32_t state;
	uint32_t reserved;
	uint8_t provenance_digest[FAF_DIGEST_SIZE];
};

struct faf_collective {
	uint64_t operation_id;
	uint64_t owner_agent_id;
	uint64_t group_id;
	uint64_t sequence;
	uint64_t bytes;
	uint64_t expected_generation;
	uint32_t op_kind;
	uint32_t participant_count;
	uint32_t state;
	uint32_t authorized;
	uint32_t violation_mask;
	uint64_t device_ids[FAF_MAX_PARTICIPANTS];
	uint64_t region_ids[FAF_MAX_PARTICIPANTS];
	uint8_t provenance_digest[FAF_DIGEST_SIZE];
};

struct faf_service {
	uint32_t policy_flags;
	uint64_t next_device_id;
	uint64_t next_link_id;
	uint64_t next_region_id;
	uint64_t next_operation_id;
	uint64_t next_sequence;
	uint64_t now_ns;
	struct faf_device devices[FAF_MAX_DEVICES];
	struct faf_link links[FAF_MAX_LINKS];
	struct faf_region regions[FAF_MAX_REGIONS];
	struct faf_collective collectives[FAF_MAX_COLLECTIVES];
	size_t device_count;
	size_t link_count;
	size_t region_count;
	size_t collective_count;
};

int faf_init(struct faf_service *service, uint32_t policy_flags,
	uint64_t now_ns);
int faf_add_device(struct faf_service *service, const struct faf_device *device,
	uint64_t *device_id_out);
int faf_add_link(struct faf_service *service, const struct faf_link *link,
	uint64_t *link_id_out);
int faf_register_region(struct faf_service *service, uint64_t owner_agent_id,
	uint64_t device_id, uint64_t size_bytes, uint32_t tier,
	uint32_t access_mask, const uint8_t provenance_digest[FAF_DIGEST_SIZE],
	struct faf_region *out);
int faf_release_region(struct faf_service *service, uint64_t region_id,
	uint64_t owner_agent_id);
int faf_submit_collective(struct faf_service *service, uint64_t owner_agent_id,
	uint64_t group_id, uint32_t op_kind, uint64_t bytes,
	uint64_t expected_generation, uint32_t authorized,
	const uint64_t *device_ids, const uint64_t *region_ids,
	uint32_t participant_count, const uint8_t provenance_digest[FAF_DIGEST_SIZE],
	struct faf_collective *out);
int faf_complete_collective(struct faf_service *service, uint64_t operation_id,
	uint64_t observed_generation, uint32_t authorized);
int faf_fail_device(struct faf_service *service, uint64_t device_id,
	uint64_t expected_generation);
int faf_query_collective(const struct faf_service *service, uint64_t operation_id,
	struct faf_collective *out);
int faf_test_policy_boundaries(struct faf_service *service);

#endif
