#include "../../faisal-snapshot-index/faisal_snapshot_index.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_request(struct fsi_snapshot_request *request, uint64_t now_ns)
{
	memset(request, 0, sizeof(*request));
	request->objective_id = 1U;
	request->task_id = 11U;
	request->agent_id = 100U;
	request->objective_generation = 1U;
	request->task_generation = 1U;
	request->now_ns = now_ns;
	request->max_age_ns = 10000U;
	request->retention_class = FSI_RETENTION_STANDARD;
	request->minimum_importance_ppm = 0U;
	request->flags = FSI_FLAG_VERIFIED;
}

int main(void)
{
	const char *journal = "/tmp/faisal-snapshot-index-selftest.journal";
	const char *corrupt_journal = "/tmp/faisal-snapshot-index-corrupt.journal";
	struct fsi_service service;
	struct fsi_snapshot_request request;
	struct fsi_snapshot first;
	struct fsi_snapshot second;
	struct fsi_snapshot pinned;
	struct fsi_snapshot restored;
	struct fsi_snapshot tampered;
	struct fsi_compaction_policy policy;
	struct fsi_attestation attestation;
	uint8_t payload_one[] = "objective=1;task=11;step=plan";
	uint8_t payload_two[] = "objective=1;task=11;step=execute";
	uint8_t payload_pinned[] = "objective=1;task=11;step=verified";
	uint32_t count;
	int fd;

	unlink(journal);
	unlink(corrupt_journal);
	assert(fsi_open(&service, journal) == FSI_OK);
	fill_request(&request, 100U);
	assert(fsi_append(&service, &request, payload_one, sizeof(payload_one) - 1U,
			  NULL, 1000U, 900000U, &first) == FSI_OK);
	request.now_ns = 200U;
	assert(fsi_append(&service, &request, payload_two, sizeof(payload_two) - 1U,
			  first.snapshot_digest, 1200U, 800000U, &second) == FSI_OK);
	assert(second.sequence > first.sequence);
	request.now_ns = 300U;
	assert(fsi_restore_latest(&service, &request, &restored) == FSI_OK);
	assert(restored.snapshot_id == second.snapshot_id);
	tampered = restored;
	tampered.payload[0] ^= 0x01U;
	assert(fsi_verify_snapshot(&tampered) == FSI_ERR_TAMPER);
	request.objective_generation = 2U;
	assert(fsi_restore_latest(&service, &request, &restored) == FSI_ERR_GENERATION);
	request.objective_generation = 1U;
	memset(&policy, 0, sizeof(policy));
	policy.now_ns = 500U;
	policy.minimum_age_ns = 100U;
	policy.maximum_live_snapshots = 1U;
	policy.preserve_pinned = 1U;
	assert(fsi_compact(&service, &policy, &count) == FSI_OK);
	assert(count == 1U);
	assert(fsi_expire(&service, 1300U, &count) == FSI_OK);
	assert(count == 1U);
	fill_request(&request, 1400U);
	request.retention_class = FSI_RETENTION_PINNED;
	assert(fsi_append(&service, &request, payload_pinned,
			  sizeof(payload_pinned) - 1U, NULL, 1500U, 1000000U,
			  &pinned) == FSI_OK);
	assert(fsi_expire(&service, 2000U, &count) == FSI_OK);
	assert(count == 0U);
	request.now_ns = 1450U;
	assert(fsi_restore_latest(&service, &request, &restored) == FSI_OK);
	assert(restored.snapshot_id == pinned.snapshot_id);
	assert(fsi_query_attestation(&service, &attestation) == FSI_OK);
	assert(attestation.active_snapshots == 1U);
	assert(attestation.compacted_snapshots == 1U);
	assert(attestation.expired_snapshots == 1U);
	fsi_close(&service);
	assert(fsi_open(&service, journal) == FSI_OK);
	assert(fsi_query_attestation(&service, &attestation) == FSI_OK);
	assert(attestation.journal_records == 5U);
	fsi_close(&service);
	assert(fsi_open(&service, corrupt_journal) == FSI_OK);
	fill_request(&request, 100U);
	assert(fsi_append(&service, &request, payload_one, sizeof(payload_one) - 1U,
			  NULL, 1000U, 900000U, &first) == FSI_OK);
	fsi_close(&service);
	fd = open(corrupt_journal, O_RDWR);
	assert(fd >= 0);
	assert(lseek(fd, -1, SEEK_END) >= 0);
	assert(write(fd, "X", 1U) == 1);
	close(fd);
	assert(fsi_open(&service, corrupt_journal) == FSI_ERR_CORRUPT);
	printf("FSI_SNAPSHOT_INDEX_SELFTEST_OK cases=24 active=1 compacted=1 expired=1 replay_records=5\n");
	unlink(journal);
	unlink(corrupt_journal);
	return 0;
}
