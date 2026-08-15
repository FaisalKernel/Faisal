#define _GNU_SOURCE
#include "../../faisal-orchestrator/faisal_orchestrator_service.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M74_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m74-orchestration.journal";
	struct fmo_service service;
	struct fmo_request request;
	struct fmo_run run;
	int rc;

	unlink(journal);
	unlink("/tmp/faisal-m74-orchestration.journal.ckpt");
	memset(&service, 0, sizeof(service));
	rc = fmo_open(&service, journal);
	if (rc != 0)
		return fail("open", rc);
	memset(&request, 0, sizeof(request));
	strncpy(request.model_id, "faisal-test-model", sizeof(request.model_id) - 1);
	request.model_digest[0] = 0x74;
	request.model_digest[1] = 0x31;
	request.cpu_time_ns = 100000000ULL;
	request.memory_pages = 1024;
	request.workload = FMO_WORKLOAD_INFERENCE;
	request.supervisor_approved = 1;
	request.operator_approved = 1;
	request.supervisor_nonce = 0x11110001ULL;
	request.operator_nonce = 0x22220002ULL;
	request.proposed_action_mask = 1ULL << 4;
	if (fmo_test_policy_denials(&service, &request) != 0)
		return fail("policy denials", rc);
	{
		unsigned int i;
		for (i = 0; i < 128; i++) {
			struct fmo_request malformed = request;
			struct fmo_run rejected;
			malformed.reserved = i + 1;
			if (fmo_admit(&service, &malformed, &rejected) == 0)
				return fail("reserved policy field accepted", (int)i);
		}
	}
	printf("M74_POLICY_FUZZ_REJECT_OK iterations=128\n");
	printf("M74_POLICY_DENIALS_OK\n");
	if (fmo_admit(&service, &request, &run) != 0 ||
	    run.state != FMO_ADMITTED || !run.checkpoint_id ||
	    !run.checkpoint_sequence || !run.manifest_digest[0] ||
	    service.run_count != 1)
		return fail("admission", rc);
	printf("M74_RESOURCE_ADMISSION_OK run=%llu cpu_ns=%llu memory_pages=%llu\n",
	       (unsigned long long)run.run_id,
	       (unsigned long long)request.cpu_time_ns,
	       (unsigned long long)request.memory_pages);
	if (fmo_record_output(&service, &run, "proposed:delete-file", 1) != 0 ||
	    fmo_test_output_is_untrusted(&run) != 0)
		return fail("untrusted output", rc);
	printf("M74_MODEL_OUTPUT_NOT_AUTHORITY_OK action_mask=0x%llx\n",
	       (unsigned long long)run.proposed_action_mask);
	if (fmo_rollback(&service, &run) != 0 ||
	    run.state != FMO_ROLLED_BACK ||
	    run.recovery_state != AGI_LC_RECOVERY_CONTINUED ||
	    !run.recovery_sequence)
		return fail("rollback", rc);
	printf("M74_CHECKPOINT_ROLLBACK_OK checkpoint=%llu recovery=%llu\n",
	       (unsigned long long)run.checkpoint_id,
	       (unsigned long long)run.recovery_sequence);
	memset(&request, 0, sizeof(request));
	request.cpu_time_ns = 1;
	request.memory_pages = 1;
	request.workload = FMO_WORKLOAD_INFERENCE;
	request.supervisor_approved = 1;
	request.operator_approved = 1;
	request.supervisor_nonce = 1;
	request.operator_nonce = 2;
	if (fmo_admit(&service, &request, &run) == 0)
		return fail("empty model identity accepted", rc);
	printf("M74_MODEL_IDENTITY_BOUNDARY_OK\n");
	fmo_close(&service);
	unlink(journal);
	unlink("/tmp/faisal-m74-orchestration.journal.ckpt");
	printf("M74_SELFTEST_EXIT=0\n");
	return 0;
}
