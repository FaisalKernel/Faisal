#define _GNU_SOURCE
#include "../../faisal-accelerator/faisal_accelerator_fabric.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FAF_BENCH_ROUNDS 5000U
#define FAF_BENCH_DEVICES 8U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct faf_device make_device(uint64_t id)
{
	struct faf_device device;
	memset(&device, 0, sizeof(device));
	device.device_id = id;
	device.generation = 1;
	device.memory_bytes = 16ULL << 30;
	device.free_memory_bytes = device.memory_bytes;
	device.capability_mask = FAF_ACCESS_DMA | FAF_ACCESS_PEER;
	device.health_ppm = 990000;
	device.state = FAF_DEVICE_READY;
	device.provider_kind = 200;
	snprintf(device.name, sizeof(device.name), "bench-device-%llu",
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
	link.bandwidth_bytes_s = 1ULL << 40;
	link.latency_ns = 250;
	link.kind = FAF_LINK_FABRIC;
	link.access_mask = FAF_ACCESS_DMA | FAF_ACCESS_PEER;
	return link;
}

int main(void)
{
	struct faf_service service;
	struct faf_device device;
	struct faf_link link;
	struct faf_region regions[FAF_BENCH_DEVICES];
	struct faf_collective op;
	uint64_t devices[FAF_BENCH_DEVICES];
	uint64_t region_ids[FAF_BENCH_DEVICES];
	uint8_t provenance[FAF_DIGEST_SIZE] = {1};
	uint64_t start, elapsed;
	unsigned int round, i, submitted = 0;

	start = now_ns();
	for (round = 0; round < FAF_BENCH_ROUNDS; round++) {
		if (faf_init(&service, FAF_POLICY_FAIL_CLOSED |
			FAF_POLICY_REQUIRE_AUTHORITY | FAF_POLICY_REQUIRE_PROVENANCE,
			1000 + round) != FAF_OK)
			return 1;
		for (i = 0; i < FAF_BENCH_DEVICES; i++) {
			device = make_device(i + 1);
			devices[i] = i + 1;
			if (faf_add_device(&service, &device, NULL) != FAF_OK)
				return 2;
		}
		for (i = 0; i < FAF_BENCH_DEVICES - 1; i++) {
			link = make_link(i + 1, i + 2);
			if (faf_add_link(&service, &link, NULL) != FAF_OK)
				return 3;
		}
		link = make_link(FAF_BENCH_DEVICES, 1);
		if (faf_add_link(&service, &link, NULL) != FAF_OK)
			return 4;
		for (i = 0; i < FAF_BENCH_DEVICES; i++) {
			if (faf_register_region(&service, 42, devices[i], 1ULL << 20,
				FAF_REGION_DEVICE, FAF_ACCESS_READ | FAF_ACCESS_WRITE |
				FAF_ACCESS_DMA | FAF_ACCESS_PEER, provenance, &regions[i]) != FAF_OK)
				return 5;
			region_ids[i] = regions[i].region_id;
		}
		if (faf_submit_collective(&service, 42, round + 1, FAF_OP_ALLREDUCE,
			1ULL << 20, 1, 1, devices, region_ids, FAF_BENCH_DEVICES,
			provenance, &op) != FAF_OK)
			return 6;
		if (faf_complete_collective(&service, op.operation_id, 1, 1) != FAF_OK)
			return 7;
		submitted++;
	}
	elapsed = now_ns() - start;
	printf("FAF_BENCH rounds=%u devices_per_round=%u regions=%u participants=%u completed=%u total_ns=%llu ns_per_round=%llu\n",
		FAF_BENCH_ROUNDS, FAF_BENCH_DEVICES, FAF_BENCH_DEVICES,
		FAF_BENCH_DEVICES, submitted, (unsigned long long)elapsed,
		(unsigned long long)(elapsed / FAF_BENCH_ROUNDS));
	printf("FAF_BENCH_SCOPE=local_userspace_policy_fixture_not_vendor_collective_or_physical_dma_qualification\n");
	return 0;
}
