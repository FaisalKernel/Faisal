#include "../../faisal-accelerator/faisal_accelerator_fabric.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FAF_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static struct faf_device make_device(uint64_t id)
{
	struct faf_device device;
	memset(&device, 0, sizeof(device));
	device.device_id = id;
	device.generation = 1;
	device.memory_bytes = 8ULL << 30;
	device.free_memory_bytes = device.memory_bytes;
	device.capability_mask = FAF_ACCESS_DMA | FAF_ACCESS_PEER;
	device.health_ppm = 990000;
	device.state = FAF_DEVICE_READY;
	device.provider_kind = 100 + (uint32_t)id;
	snprintf(device.name, sizeof(device.name), "provider-device-%llu",
		(unsigned long long)id);
	return device;
}

static struct faf_link make_link(uint64_t src, uint64_t dst)
{
	struct faf_link link;
	memset(&link, 0, sizeof(link));
	link.src_device_id = src;
	link.dst_device_id = dst;
	link.generation = 1;
	link.bandwidth_bytes_s = 900ULL * 1000ULL * 1000ULL * 1000ULL;
	link.latency_ns = 500;
	link.kind = FAF_LINK_FABRIC;
	link.access_mask = FAF_ACCESS_DMA | FAF_ACCESS_PEER;
	return link;
}

int main(void)
{
	struct faf_service service;
	struct faf_device device;
	struct faf_link link;
	struct faf_region regions[4];
	struct faf_collective op, queried;
	uint64_t devices[4] = {1, 2, 3, 4};
	uint64_t region_ids[4];
	uint8_t provenance[FAF_DIGEST_SIZE] = {0};
	uint8_t digest[FAF_DIGEST_SIZE];
	uint32_t i;
	int rc;

	for (i = 0; i < FAF_DIGEST_SIZE; i++)
		provenance[i] = (uint8_t)(i + 1);
	if (faf_init(&service, FAF_POLICY_FAIL_CLOSED |
		FAF_POLICY_REQUIRE_AUTHORITY | FAF_POLICY_REQUIRE_PROVENANCE, 100) != FAF_OK)
		return fail("init", -1);
	for (i = 0; i < 4; i++) {
		device = make_device(i + 1);
		if (faf_add_device(&service, &device, NULL) != FAF_OK)
			return fail("device admission", -1);
	}
	for (i = 0; i < 3; i++) {
		link = make_link(i + 1, i + 2);
		if (faf_add_link(&service, &link, NULL) != FAF_OK)
			return fail("link admission", -1);
	}
	link = make_link(4, 1);
	if (faf_add_link(&service, &link, NULL) != FAF_OK)
		return fail("ring link admission", -1);
	for (i = 0; i < 4; i++) {
		if (faf_register_region(&service, 77, devices[i], 64ULL << 20,
			FAF_REGION_DEVICE, FAF_ACCESS_READ | FAF_ACCESS_WRITE |
			FAF_ACCESS_DMA | FAF_ACCESS_PEER, provenance, &regions[i]) != FAF_OK)
			return fail("region registration", -1);
		region_ids[i] = regions[i].region_id;
	}
	printf("FAF_DEVICE_MEMORY_TOPOLOGY_OK devices=4 regions=4 links=4\n");

	if (faf_submit_collective(&service, 77, 9001, FAF_OP_ALLREDUCE,
		64ULL << 20, 1, 1, devices, region_ids, 4, provenance, &op) != FAF_OK ||
		op.state != FAF_COLLECTIVE_QUEUED || !op.provenance_digest[0])
		return fail("collective admission", -1);
	memcpy(digest, op.provenance_digest, sizeof(digest));
	if (faf_complete_collective(&service, op.operation_id, 1, 1) != FAF_OK ||
		faf_query_collective(&service, op.operation_id, &queried) != FAF_OK ||
		queried.state != FAF_COLLECTIVE_COMPLETED ||
		memcmp(digest, queried.provenance_digest, sizeof(digest)) != 0)
		return fail("collective completion", -1);
	printf("FAF_ALLREDUCE_PROVENANCE_COMPLETION_OK operation=%llu\n",
		(unsigned long long)op.operation_id);

	if (faf_submit_collective(&service, 77, 9002, FAF_OP_ALLGATHER,
		32ULL << 20, 1, 1, devices, region_ids, 4, provenance, &op) != FAF_OK)
		return fail("second collective admission", -1);
	if (faf_fail_device(&service, 2, 1) != FAF_OK ||
		faf_query_collective(&service, op.operation_id, &queried) != FAF_OK ||
		queried.state != FAF_COLLECTIVE_ABORTED ||
		!(queried.violation_mask & FAF_VIOLATION_DEVICE_LOST))
		return fail("device loss abort", -1);
	printf("FAF_DEVICE_LOSS_ABORT_OK operation=%llu\n",
		(unsigned long long)op.operation_id);
	if (faf_submit_collective(&service, 77, 9003, FAF_OP_REDUCE,
		16ULL << 20, 1, 1, devices, region_ids, 4, provenance, &op) != FAF_ERR_STALE)
		return fail("stale generation rejection", -1);
	printf("FAF_STALE_GENERATION_REJECT_OK\n");
	if (faf_submit_collective(&service, 77, 9004, FAF_OP_BROADCAST,
		16ULL << 20, 2, 0, devices, region_ids, 4, provenance, &op) != FAF_ERR_AUTHORITY)
		return fail("authority rejection", -1);
	printf("FAF_AUTHORITY_REJECT_OK\n");
	if (faf_release_region(&service, region_ids[0], 88) != FAF_ERR_AUTHORITY)
		return fail("region owner rejection", -1);
	printf("FAF_REGION_OWNER_REJECT_OK\n");
	if (faf_test_policy_boundaries(&service) != FAF_OK)
		return fail("policy helper", -1);
	printf("FAF_SELFTEST_EXIT=0\n");
	(void)rc;
	return 0;
}
