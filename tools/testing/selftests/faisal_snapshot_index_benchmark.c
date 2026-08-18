#include "../../faisal-snapshot-index/faisal_snapshot_index.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_request(struct fsi_snapshot_request *request, uint64_t now)
{
	memset(request, 0, sizeof(*request));
	request->objective_id = 42U;
	request->task_id = 7U;
	request->agent_id = 9U;
	request->objective_generation = 1U;
	request->task_generation = 1U;
	request->now_ns = now;
	request->max_age_ns = 1000000U;
	request->retention_class = FSI_RETENTION_STANDARD;
	request->flags = FSI_FLAG_VERIFIED;
}

int main(void)
{
	const char *journal = "/tmp/faisal-snapshot-index-benchmark.journal";
	struct fsi_service service;
	struct fsi_snapshot_request request;
	struct fsi_snapshot snapshot;
	struct fsi_compaction_policy policy;
	uint8_t payload[] = "objective=42;task=7;state=checkpoint";
	uint64_t before_start;
	uint64_t before_end;
	uint64_t after_start;
	uint64_t after_end;
	uint64_t iterations = 20000U;
	uint64_t i;
	uint32_t compacted;
	uint64_t checksum = 0;

	unlink(journal);
	assert(fsi_open(&service, journal) == FSI_OK);
	for (i = 0; i < 100U; i++) {
		fill_request(&request, 100U + i);
		assert(fsi_append(&service, &request, payload, sizeof(payload) - 1U,
				  NULL, 1000000U, (uint32_t)(500000U + i),
				  &snapshot) == FSI_OK);
	}
	fill_request(&request, 10000U);
	before_start = now_ns();
	for (i = 0; i < iterations; i++) {
		request.now_ns = 10000U;
		assert(fsi_restore_latest(&service, &request, &snapshot) == FSI_OK);
		checksum ^= snapshot.snapshot_id;
	}
	before_end = now_ns();
	memset(&policy, 0, sizeof(policy));
	policy.now_ns = 10000U;
	policy.minimum_age_ns = 0U;
	policy.maximum_live_snapshots = 1U;
	policy.preserve_pinned = 1U;
	assert(fsi_compact(&service, &policy, &compacted) == FSI_OK);
	assert(compacted == 99U);
	after_start = now_ns();
	for (i = 0; i < iterations; i++) {
		request.now_ns = 10000U;
		assert(fsi_restore_latest(&service, &request, &snapshot) == FSI_OK);
		checksum ^= snapshot.snapshot_id;
	}
	after_end = now_ns();
	printf("FSI_SNAPSHOT_INDEX_BENCHMARK_OK snapshots_before=100 snapshots_after=1"
	       " iterations=%" PRIu64 " restore_before_ns=%" PRIu64
	       " restore_after_ns=%" PRIu64 " before_ns_per_request=%.2f"
	       " after_ns_per_request=%.2f compaction_reduction_permille=990"
	       " checksum=%" PRIu64 "\n",
	       iterations, before_end - before_start, after_end - after_start,
	       (double)(before_end - before_start) / (double)iterations,
	       (double)(after_end - after_start) / (double)iterations, checksum);
	fsi_close(&service);
	unlink(journal);
	return 0;
}
