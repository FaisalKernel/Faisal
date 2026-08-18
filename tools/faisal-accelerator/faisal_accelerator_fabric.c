#include "faisal_accelerator_fabric.h"
#include <openssl/sha.h>
#include <string.h>

static int device_index(const struct faf_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->device_count; i++)
		if (s->devices[i].device_id == id)
			return (int)i;
	return -1;
}

static int link_index(const struct faf_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->link_count; i++)
		if (s->links[i].link_id == id)
			return (int)i;
	return -1;
}

static int region_index(const struct faf_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->region_count; i++)
		if (s->regions[i].region_id == id)
			return (int)i;
	return -1;
}

static int collective_index(const struct faf_service *s, uint64_t id)
{
	size_t i;
	for (i = 0; i < s->collective_count; i++)
		if (s->collectives[i].operation_id == id)
			return (int)i;
	return -1;
}

static int digest_present(const uint8_t digest[FAF_DIGEST_SIZE])
{
	size_t i;
	for (i = 0; i < FAF_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static int valid_op(uint32_t op)
{
	return op >= FAF_OP_ALLREDUCE && op <= FAF_OP_ALLTOALL;
}

static int link_exists(const struct faf_service *s, uint64_t src, uint64_t dst,
	uint32_t required_access)
{
	size_t i;
	for (i = 0; i < s->link_count; i++) {
		const struct faf_link *link = &s->links[i];
		if (((link->src_device_id == src && link->dst_device_id == dst) ||
			(link->src_device_id == dst && link->dst_device_id == src)) &&
			(link->access_mask & required_access) == required_access)
			return 1;
	}
	return 0;
}

static int region_matches(const struct faf_service *s, uint64_t region_id,
	uint64_t owner_agent_id, uint64_t device_id)
{
	int idx = region_index(s, region_id);
	if (idx < 0)
		return 0;
	return s->regions[idx].owner_agent_id == owner_agent_id &&
		s->regions[idx].device_id == device_id &&
		s->regions[idx].state == FAF_REGION_ACTIVE &&
		(s->regions[idx].access_mask & (FAF_ACCESS_READ | FAF_ACCESS_WRITE)) ==
		(FAF_ACCESS_READ | FAF_ACCESS_WRITE);
}

static void collective_digest(const struct faf_collective *op,
	const uint8_t provenance[FAF_DIGEST_SIZE], uint8_t out[FAF_DIGEST_SIZE])
{
	struct faf_collective copy = *op;
	memset(copy.provenance_digest, 0, sizeof(copy.provenance_digest));
	memcpy(copy.provenance_digest, provenance, FAF_DIGEST_SIZE);
	SHA256((const unsigned char *)&copy, sizeof(copy), out);
}

int faf_init(struct faf_service *service, uint32_t policy_flags,
	uint64_t now_ns)
{
	if (!service || !policy_flags || (policy_flags & ~(FAF_POLICY_FAIL_CLOSED |
		FAF_POLICY_REQUIRE_AUTHORITY | FAF_POLICY_REQUIRE_PROVENANCE)))
		return FAF_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy_flags = policy_flags;
	service->next_device_id = 1;
	service->next_link_id = 1;
	service->next_region_id = 1;
	service->next_operation_id = 1;
	service->next_sequence = 1;
	service->now_ns = now_ns;
	return FAF_OK;
}

int faf_add_device(struct faf_service *service, const struct faf_device *device,
	uint64_t *device_id_out)
{
	struct faf_device copy;
	if (!service || !device || !device->memory_bytes || !device->generation ||
		!device->health_ppm || device->state != FAF_DEVICE_READY ||
		service->device_count >= FAF_MAX_DEVICES)
		return FAF_ERR_ARGUMENT;
	if (device->device_id && device_index(service, device->device_id) >= 0)
		return FAF_ERR_DUPLICATE;
	copy = *device;
	if (!copy.device_id)
		copy.device_id = service->next_device_id++;
	if (!copy.free_memory_bytes)
		copy.free_memory_bytes = copy.memory_bytes;
	service->devices[service->device_count++] = copy;
	if (device_id_out)
		*device_id_out = copy.device_id;
	return FAF_OK;
}

int faf_add_link(struct faf_service *service, const struct faf_link *link,
	uint64_t *link_id_out)
{
	struct faf_link copy;
	if (!service || !link || !link->src_device_id || !link->dst_device_id ||
		link->src_device_id == link->dst_device_id || !link->generation ||
		!link->bandwidth_bytes_s || !link->latency_ns || !link->access_mask ||
		service->link_count >= FAF_MAX_LINKS ||
		device_index(service, link->src_device_id) < 0 ||
		device_index(service, link->dst_device_id) < 0)
		return FAF_ERR_ARGUMENT;
	if (link->link_id && link_index(service, link->link_id) >= 0)
		return FAF_ERR_DUPLICATE;
	copy = *link;
	if (!copy.link_id)
		copy.link_id = service->next_link_id++;
	service->links[service->link_count++] = copy;
	if (link_id_out)
		*link_id_out = copy.link_id;
	return FAF_OK;
}

int faf_register_region(struct faf_service *service, uint64_t owner_agent_id,
	uint64_t device_id, uint64_t size_bytes, uint32_t tier,
	uint32_t access_mask, const uint8_t provenance_digest[FAF_DIGEST_SIZE],
	struct faf_region *out)
{
	struct faf_region region;
	int idx;
	if (!service || !owner_agent_id || !device_id || !size_bytes || !out ||
		!provenance_digest || !digest_present(provenance_digest) ||
		tier < FAF_REGION_HOST || tier > FAF_REGION_REMOTE || !access_mask ||
		service->region_count >= FAF_MAX_REGIONS)
		return FAF_ERR_ARGUMENT;
	idx = device_index(service, device_id);
	if (idx < 0 || service->devices[idx].state != FAF_DEVICE_READY)
		return FAF_ERR_STATE;
	if (size_bytes > service->devices[idx].free_memory_bytes)
		return FAF_ERR_CAPACITY;
	memset(&region, 0, sizeof(region));
	region.region_id = service->next_region_id++;
	region.owner_agent_id = owner_agent_id;
	region.device_id = device_id;
	region.device_generation = service->devices[idx].generation;
	region.size_bytes = size_bytes;
	region.capability = (region.region_id << 1) | 1ULL;
	region.tier = tier;
	region.access_mask = access_mask;
	region.state = FAF_REGION_ACTIVE;
	memcpy(region.provenance_digest, provenance_digest, FAF_DIGEST_SIZE);
	service->devices[idx].free_memory_bytes -= size_bytes;
	service->regions[service->region_count++] = region;
	*out = region;
	return FAF_OK;
}

int faf_release_region(struct faf_service *service, uint64_t region_id,
	uint64_t owner_agent_id)
{
	int ridx;
	int didx;
	if (!service || !region_id || !owner_agent_id)
		return FAF_ERR_ARGUMENT;
	ridx = region_index(service, region_id);
	if (ridx < 0)
		return FAF_ERR_NOT_FOUND;
	if (service->regions[ridx].owner_agent_id != owner_agent_id ||
		service->regions[ridx].state != FAF_REGION_ACTIVE)
		return FAF_ERR_AUTHORITY;
	didx = device_index(service, service->regions[ridx].device_id);
	if (didx >= 0)
		service->devices[didx].free_memory_bytes += service->regions[ridx].size_bytes;
	service->regions[ridx].state = FAF_REGION_RELEASED;
	return FAF_OK;
}

int faf_submit_collective(struct faf_service *service, uint64_t owner_agent_id,
	uint64_t group_id, uint32_t op_kind, uint64_t bytes,
	uint64_t expected_generation, uint32_t authorized,
	const uint64_t *device_ids, const uint64_t *region_ids,
	uint32_t participant_count, const uint8_t provenance_digest[FAF_DIGEST_SIZE],
	struct faf_collective *out)
{
	struct faf_collective op;
	uint32_t i, j;
	if (!service || !owner_agent_id || !group_id || !valid_op(op_kind) || !bytes ||
		!expected_generation || !device_ids || !region_ids || !out ||
		participant_count < 2 || participant_count > FAF_MAX_PARTICIPANTS ||
		service->collective_count >= FAF_MAX_COLLECTIVES)
		return FAF_ERR_ARGUMENT;
	if ((service->policy_flags & FAF_POLICY_REQUIRE_AUTHORITY) && !authorized)
		return FAF_ERR_AUTHORITY;
	if ((service->policy_flags & FAF_POLICY_REQUIRE_PROVENANCE) &&
		(!provenance_digest || !digest_present(provenance_digest)))
		return FAF_ERR_POLICY;
	memset(&op, 0, sizeof(op));
	op.operation_id = service->next_operation_id++;
	op.owner_agent_id = owner_agent_id;
	op.group_id = group_id;
	op.sequence = service->next_sequence++;
	op.bytes = bytes;
	op.expected_generation = expected_generation;
	op.op_kind = op_kind;
	op.participant_count = participant_count;
	op.authorized = authorized;
	op.state = FAF_COLLECTIVE_QUEUED;
	for (i = 0; i < participant_count; i++) {
		int didx = device_index(service, device_ids[i]);
		if (didx < 0 || service->devices[didx].state != FAF_DEVICE_READY ||
			service->devices[didx].generation != expected_generation)
			return FAF_ERR_STALE;
		if (!region_matches(service, region_ids[i], owner_agent_id, device_ids[i]))
			return FAF_ERR_POLICY;
		for (j = 0; j < i; j++)
			if (device_ids[j] == device_ids[i])
				return FAF_ERR_DUPLICATE;
		if (i && !link_exists(service, device_ids[i - 1], device_ids[i],
			FAF_ACCESS_DMA | FAF_ACCESS_PEER))
			return FAF_ERR_TOPOLOGY;
		op.device_ids[i] = device_ids[i];
		op.region_ids[i] = region_ids[i];
	}
	if (!link_exists(service, device_ids[participant_count - 1], device_ids[0],
		FAF_ACCESS_DMA | FAF_ACCESS_PEER))
		return FAF_ERR_TOPOLOGY;
	if (provenance_digest)
		memcpy(op.provenance_digest, provenance_digest, FAF_DIGEST_SIZE);
	collective_digest(&op, op.provenance_digest, op.provenance_digest);
	service->collectives[service->collective_count++] = op;
	*out = op;
	return FAF_OK;
}

int faf_complete_collective(struct faf_service *service, uint64_t operation_id,
	uint64_t observed_generation, uint32_t authorized)
{
	int oidx;
	struct faf_collective *op;
	uint32_t i;
	if (!service || !operation_id)
		return FAF_ERR_ARGUMENT;
	 oidx = collective_index(service, operation_id);
	if (oidx < 0)
		return FAF_ERR_NOT_FOUND;
	op = &service->collectives[oidx];
	if (op->state != FAF_COLLECTIVE_QUEUED)
		return FAF_ERR_STATE;
	if (!authorized || !(service->policy_flags & FAF_POLICY_REQUIRE_AUTHORITY)) {
		if (!authorized) {
			op->violation_mask |= FAF_VIOLATION_AUTHORITY;
			op->state = FAF_COLLECTIVE_ABORTED;
			return FAF_ERR_AUTHORITY;
		}
	}
	if (observed_generation != op->expected_generation) {
		op->violation_mask |= FAF_VIOLATION_GENERATION;
		op->state = FAF_COLLECTIVE_ABORTED;
		return FAF_ERR_STALE;
	}
	for (i = 0; i < op->participant_count; i++) {
		int didx = device_index(service, op->device_ids[i]);
		int ridx = region_index(service, op->region_ids[i]);
		if (didx < 0 || ridx < 0 || service->devices[didx].state != FAF_DEVICE_READY ||
			service->devices[didx].generation != op->expected_generation ||
			service->regions[ridx].state != FAF_REGION_ACTIVE) {
			op->violation_mask |= FAF_VIOLATION_DEVICE_LOST;
			op->state = FAF_COLLECTIVE_ABORTED;
			return FAF_ERR_STALE;
		}
	}
	op->state = FAF_COLLECTIVE_COMPLETED;
	return FAF_OK;
}

int faf_fail_device(struct faf_service *service, uint64_t device_id,
	uint64_t expected_generation)
{
	int didx;
	size_t i;
	uint32_t j;
	if (!service || !device_id)
		return FAF_ERR_ARGUMENT;
	didx = device_index(service, device_id);
	if (didx < 0)
		return FAF_ERR_NOT_FOUND;
	if (service->devices[didx].generation != expected_generation)
		return FAF_ERR_STALE;
	service->devices[didx].state = FAF_DEVICE_LOST;
	service->devices[didx].generation++;
	for (i = 0; i < service->collective_count; i++) {
		struct faf_collective *op = &service->collectives[i];
		if (op->state != FAF_COLLECTIVE_QUEUED)
			continue;
		for (j = 0; j < op->participant_count; j++) {
			if (op->device_ids[j] == device_id) {
				op->state = FAF_COLLECTIVE_ABORTED;
				op->violation_mask |= FAF_VIOLATION_DEVICE_LOST;
				break;
			}
		}
	}
	return FAF_OK;
}

int faf_query_collective(const struct faf_service *service, uint64_t operation_id,
	struct faf_collective *out)
{
	int idx;
	if (!service || !out)
		return FAF_ERR_ARGUMENT;
	idx = collective_index(service, operation_id);
	if (idx < 0)
		return FAF_ERR_NOT_FOUND;
	*out = service->collectives[idx];
	return FAF_OK;
}

int faf_test_policy_boundaries(struct faf_service *service)
{
	if (!service)
		return FAF_ERR_ARGUMENT;
	if (!(service->policy_flags & FAF_POLICY_FAIL_CLOSED))
		return FAF_ERR_POLICY;
	return FAF_OK;
}
