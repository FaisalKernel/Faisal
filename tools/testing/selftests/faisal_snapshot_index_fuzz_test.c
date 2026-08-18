#include "../../faisal-snapshot-index/faisal_snapshot_index.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_request(struct fsi_snapshot_request *request, uint64_t now)
{
	memset(request, 0, sizeof(*request));
	request->objective_id = 4U;
	request->task_id = 5U;
	request->agent_id = 6U;
	request->objective_generation = 1U;
	request->task_generation = 1U;
	request->now_ns = now;
	request->max_age_ns = 100000U;
	request->retention_class = FSI_RETENTION_STANDARD;
}

int main(void)
{
	const char *journal = "/tmp/faisal-snapshot-index-fuzz.journal";
	struct fsi_service service;
	struct fsi_snapshot_request request;
	struct fsi_snapshot snapshot;
	uint8_t payload[] = "bounded";
	uint8_t oversized[FSI_MAX_PAYLOAD + 1U];
	uint32_t rejected = 0;
	uint32_t accepted = 0;
	uint32_t i;

	memset(oversized, 'X', sizeof(oversized));
	unlink(journal);
	assert(fsi_open(&service, journal) == FSI_OK);
	for (i = 0; i < 10000U; i++) {
		int rc;

		fill_request(&request, i + 1U);
		switch (i % 7U) {
		case 0U:
			request.objective_id = 0U;
			rc = fsi_restore_latest(&service, &request, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		case 1U:
			request.task_generation = 0U;
			rc = fsi_restore_latest(&service, &request, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		case 2U:
			request.retention_class = 0U;
			rc = fsi_append(&service, &request, payload, sizeof(payload) - 1U,
					NULL, request.now_ns + 10U, 100U, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		case 3U:
			rc = fsi_append(&service, &request, oversized, sizeof(oversized),
					NULL, request.now_ns + 10U, 100U, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		case 4U:
			rc = fsi_append(&service, &request, payload, sizeof(payload) - 1U,
					NULL, request.now_ns, 100U, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		case 5U:
			rc = fsi_append(&service, &request, payload, sizeof(payload) - 1U,
					NULL, request.now_ns + 10U, 1000001U, &snapshot);
			assert(rc == FSI_ERR_ARGUMENT);
			rejected++;
			break;
		default:
			if (accepted < 64U) {
				rc = fsi_append(&service, &request, payload,
						sizeof(payload) - 1U, NULL,
						request.now_ns + 1000U, 500000U,
						&snapshot);
				assert(rc == FSI_OK);
				accepted++;
			} else {
				rc = fsi_restore_latest(&service, &request, &snapshot);
				assert(rc == FSI_OK || rc == FSI_ERR_NOT_FOUND);
			}
			break;
		}
	}
	fsi_close(&service);
	unlink(journal);
	printf("FSI_SNAPSHOT_INDEX_FUZZ_OK iterations=10000 rejected=%u accepted=%u\n",
	       rejected, accepted);
	return 0;
}
