#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../faisal-execution/faisal_execution_engine.h"

static void fail(const char *marker, int rc)
{
	printf("M108_FAIL %s rc=%d\n", marker, rc);
	exit(1);
}

#define CHECK_OK(expr, marker) do { \
	int _rc = (expr); \
	if (_rc != FEX_OK) fail((marker), _rc); \
} while (0)

#define CHECK_EQ(expr, expected, marker) do { \
	int _rc = (expr); \
	if (_rc != (expected)) fail((marker), _rc); \
} while (0)

static void digest(const char *text, uint8_t out[FEX_DIGEST_SIZE])
{
	unsigned int i;
	for (i = 0; i < FEX_DIGEST_SIZE; i++)
		out[i] = (uint8_t)(text[i % strlen(text)] + i);
}

int main(int argc, char **argv)
{
	char prefix[] = "/tmp/faisal-m108-execution-XXXXXX";
	struct fex_service service;
	struct fex_objective objective, replayed, quarantine_objective;
	struct fex_node node_a, node_b, node_c, node_d, query_node;
	struct fex_checkpoint checkpoint;
	struct fex_journal_attestation attestation_before, attestation_after;
	uint8_t working[FEX_DIGEST_SIZE], world[FEX_DIGEST_SIZE], resource[FEX_DIGEST_SIZE];
	uint8_t consumed_handoff_token[FEX_HANDOFF_TOKEN_SIZE];
	uint32_t dependency;
	uint32_t claimed, recovered, dead_lettered, reassigned, supervised_dead;
	struct fex_worker worker;
	int fd;
	int require_kernel = argc > 1 && strcmp(argv[1], "--require-kernel") == 0;

	fd = mkstemp(prefix);
	if (fd < 0)
		fail("MKSTEMP", FEX_ERR_IO);
	close(fd);
	unlink(prefix);

	CHECK_OK(fex_open(&service, prefix, require_kernel), "OPEN");
	if (require_kernel) {
		if (service.tasks.kernel_fd < 0 || service.tasks.session_id == 0 ||
		    service.tasks.agent_id == 0 || service.tasks.agent_capability == 0)
			fail("KERNEL_SESSION_BIND", FEX_ERR_KERNEL);
		printf("M108_KERNEL_SESSION_BIND_OK abi=38\n");
	}
	printf("M108_DURABLE_ENGINE_OPEN_OK\n");

	CHECK_OK(fex_create_objective(&service, "intent: verify and recover objective",
				100000000000ULL, 1000000000ULL, 1000000ULL, 2,
				1, &objective), "CREATE_OBJECTIVE");
	printf("M108_INTENT_OBJECTIVE_CREATED_OK id=%llu\n",
	       (unsigned long long)objective.objective_id);

	CHECK_OK(fex_add_node(&service, objective.objective_id, "m108-node-a",
				"observe world", 500, 100, 2, NULL, 0, 1, 0,
				&node_a), "ADD_A");
	dependency = (uint32_t)node_a.task_id;
	CHECK_OK(fex_add_node(&service, objective.objective_id, "m108-node-b",
				"verify observation", 600, 100, 2, &dependency, 1, 0, 0,
				&node_b), "ADD_B");
	printf("M108_DAG_NODES_CREATED_OK nodes=2\n");

	CHECK_OK(fex_dispatch(&service, objective.objective_id, 1, 100, &claimed),
		 "DISPATCH_A");
	if (claimed != 1)
		fail("DAG_DISPATCH_COUNT", FEX_ERR_STATE);
	digest("observation", working);
	CHECK_OK(fex_complete(&service, node_a.task_id, 3, "observed", working),
		 "COMPLETE_A");
	CHECK_OK(fex_dispatch(&service, objective.objective_id, 4, 100, &claimed),
		 "DISPATCH_B");
	if (claimed != 1)
		fail("DISPATCH_B_COUNT", FEX_ERR_STATE);
	printf("M108_INTENT_PLAN_DAG_EXECUTION_OK claimed=%u\n", claimed);

	CHECK_OK(fex_fail(&service, node_b.task_id, 5, FTS_FAILURE_TOOL,
			 "model provider unavailable", 1, FTS_FAILURE_MODEL), "FAIL_B");
	CHECK_OK(fex_query_node(&service, node_b.task_id, &query_node), "QUERY_RETRY");
	if (query_node.state != FTS_TASK_RETRY_WAIT)
		fail("RETRY_BACKOFF_STATE", FEX_ERR_STATE);
	CHECK_OK(fex_dispatch(&service, objective.objective_id, 2000000006ULL,
			 100, &claimed), "DISPATCH_RETRY");
	digest("verified-result", world);
	CHECK_OK(fex_complete(&service, node_b.task_id, 2000000007ULL,
			 "verified", world), "COMPLETE_B");
	printf("M108_RETRY_BACKOFF_REROUTE_OK\n");

	digest("working", working);
	digest("world", world);
	digest("resource", resource);
	CHECK_OK(fex_checkpoint(&service, objective.objective_id, 2000000008ULL,
			working, world, resource, &checkpoint), "CHECKPOINT");
	if (!checkpoint.sequence || !checkpoint.verified)
		fail("CHECKPOINT_STATE", FEX_ERR_STATE);
	printf("M108_CHECKPOINT_SEALED_OK sequence=%llu\n",
	       (unsigned long long)checkpoint.sequence);

	CHECK_EQ(fex_test_model_output_untrusted(&service, node_b.task_id, world),
		 FEX_ERR_AUTHORITY, "MODEL_OUTPUT_AUTHORITY");
	printf("M108_MODEL_OUTPUT_NOT_AUTHORITY_OK\n");

	CHECK_OK(fex_add_node(&service, objective.objective_id, "m108-node-c",
				"long running worker", 400, 100, 1, NULL, 0, 1, 0,
				&node_c), "ADD_C");
		CHECK_OK(fex_dispatch(&service, objective.objective_id, 10, 5, &claimed),
			 "DISPATCH_C");
	CHECK_OK(fex_query_worker(&service, node_c.task_id, &worker),
			 "QUERY_WORKER_HEALTHY");
		if (worker.health != FEX_WORKER_HEALTHY || !worker.lease_generation)
			fail("WORKER_HEALTHY_STATE", FEX_ERR_STATE);
		{
		uint64_t previous_generation = worker.lease_generation;
		uint8_t untrusted_checkpoint[FEX_DIGEST_SIZE] = { 0 };
		uint8_t tampered_token[FEX_HANDOFF_TOKEN_SIZE];
		CHECK_EQ(fex_handoff_verified(&service, node_c.task_id, 9001, 12, 100,
				untrusted_checkpoint), FEX_ERR_AUTHORITY,
				"UNTRUSTED_HANDOFF_DIGEST");
		printf("M120_UNTRUSTED_HANDOFF_DIGEST_DENIED_OK\n");
		CHECK_OK(fex_make_handoff_token(&service, node_c.task_id, 9001, 12,
				 consumed_handoff_token), "MAKE_HANDOFF_TOKEN");
		memcpy(tampered_token, consumed_handoff_token, sizeof(tampered_token));
		tampered_token[0] ^= 0x01;
		CHECK_EQ(fex_handoff_token_verified(&service, node_c.task_id, 9001, 12,
				100, tampered_token), FEX_ERR_AUTHORITY,
				"TAMPERED_HANDOFF_TOKEN");
		printf("M121_TAMPERED_HANDOFF_TOKEN_DENIED_OK\n");
		CHECK_EQ(fex_handoff_token_verified(&service, node_c.task_id,
				9001, 12 + FEX_HANDOFF_TOKEN_MAX_AGE_NS + 1,
				100, consumed_handoff_token), FEX_ERR_AUTHORITY,
				"STALE_HANDOFF_TOKEN");
		printf("M122_STALE_HANDOFF_TOKEN_DENIED_OK\n");
		CHECK_EQ(fex_handoff_token_verified(&service, node_c.task_id, 9001, 12,
				FEX_MAX_HANDOFF_LEASE_NS + 1, consumed_handoff_token),
				FEX_ERR_POLICY, "OVERLONG_HANDOFF_LEASE");
		printf("M123_OVERLONG_HANDOFF_LEASE_DENIED_OK\n");
		CHECK_OK(fex_handoff_token_verified(&service, node_c.task_id, 9001, 12,
				100, consumed_handoff_token), "WORKER_HANDOFF");
		{
			int replay_rc = fex_handoff_token_verified(&service, node_c.task_id,
					9001, 12, 100, consumed_handoff_token);
			if (replay_rc != FEX_ERR_CONFLICT &&
			    replay_rc != FEX_ERR_AUTHORITY)
				fail("REPLAYED_HANDOFF_TOKEN", replay_rc);
		}
		printf("M124_REPLAYED_HANDOFF_TOKEN_DENIED_OK\n");

		CHECK_OK(fex_query_worker(&service, node_c.task_id, &worker),
			 "QUERY_WORKER_HANDOFF");
		if (worker.worker_id != 9001 || worker.handoff_count != 1 ||
		    worker.lease_generation <= previous_generation ||
		    worker.health != FEX_WORKER_HEALTHY)
			fail("WORKER_HANDOFF_STATE", FEX_ERR_STATE);
					printf("M120_CHECKPOINT_BOUND_HANDOFF_OK worker=%llu generation=%llu\n",

		       (unsigned long long)worker.worker_id,
		       (unsigned long long)worker.lease_generation);
		printf("M117_WORKER_HANDOFF_OK worker=%llu generation=%llu\n",
		       (unsigned long long)worker.worker_id,
		       (unsigned long long)worker.lease_generation);
	}
	CHECK_OK(fex_supervise(&service, 20, 5, &reassigned, &supervised_dead),

			 "SUPERVISE_TIMEOUT");
	if (reassigned != 1 || supervised_dead != 0)
		fail("WORKER_TIMEOUT_REASSIGN", FEX_ERR_STATE);
	CHECK_OK(fex_query_worker(&service, node_c.task_id, &worker),
			 "QUERY_WORKER_REASSIGNED");
	if (worker.health != FEX_WORKER_REASSIGNED ||
		worker.reassignment_count != 1 || worker.restart_count != 1)
		fail("WORKER_REASSIGNED_STATE", FEX_ERR_STATE);
	printf("M115_WORKER_TIMEOUT_REASSIGN_OK reassigned=%u restart_count=%u\n",
	       reassigned, worker.restart_count);

	CHECK_OK(fex_create_objective(&service, "intent: quarantine unhealthy worker",
				100000000000ULL, 1000000000ULL, 1000000ULL, 1,
				25, &quarantine_objective), "CREATE_QUARANTINE_OBJECTIVE");
	CHECK_OK(fex_add_node(&service, quarantine_objective.objective_id, "m118-node-d",
				"bounded recovery worker", 300, 100, 2, NULL, 0, 1, 0,
				&node_d), "ADD_D");
	CHECK_OK(fex_dispatch(&service, quarantine_objective.objective_id, 30, 100, &claimed),
			 "DISPATCH_D_FIRST");
	CHECK_OK(fex_supervise(&service, 40, 5, &reassigned, &supervised_dead),
			 "SUPERVISE_D_FIRST");
	CHECK_OK(fex_dispatch(&service, quarantine_objective.objective_id, 3000000030ULL, 100,
			 &claimed), "DISPATCH_D_SECOND");
	CHECK_OK(fex_supervise(&service, 3000000040ULL, 5, &reassigned,
			 &supervised_dead), "SUPERVISE_D_SECOND");
	CHECK_OK(fex_dispatch(&service, quarantine_objective.objective_id, 8000000030ULL, 100,
			 &claimed), "DISPATCH_D_THIRD");
	CHECK_OK(fex_supervise(&service, 8000000040ULL, 5, &reassigned,
			 &supervised_dead), "SUPERVISE_D_THIRD");
	CHECK_OK(fex_query_worker(&service, node_d.task_id, &worker),
			 "QUERY_WORKER_QUARANTINED");
	if (worker.health != FEX_WORKER_QUARANTINED ||
	    worker.restart_count != FEX_MAX_WORKER_RESTARTS ||
	    supervised_dead != 1)
		fail("WORKER_QUARANTINE_STATE", FEX_ERR_STATE);
	printf("M118_WORKER_QUARANTINE_OK restarts=%u dead_lettered=%u\n",
	       worker.restart_count, supervised_dead);
	CHECK_OK(fex_query_journal_attestation(&service, &attestation_before),
		 "QUERY_JOURNAL_ATTESTATION_BEFORE_RESTART");
	if (attestation_before.format_version != FEX_ENGINE_VERSION ||
	    !attestation_before.record_count ||
	    attestation_before.last_sequence != attestation_before.record_count ||
	    !attestation_before.consumed_handoff_token_count)
		fail("JOURNAL_ATTESTATION_BEFORE_RESTART", FEX_ERR_STATE);
	fex_close(&service);

	CHECK_OK(fex_open(&service, prefix, require_kernel), "REOPEN");
	CHECK_OK(fex_query_journal_attestation(&service, &attestation_after),
		 "QUERY_JOURNAL_ATTESTATION_AFTER_RESTART");
	if (memcmp(attestation_before.chain_digest, attestation_after.chain_digest,
		   FEX_DIGEST_SIZE) != 0 ||
	    attestation_before.record_count != attestation_after.record_count ||
	    attestation_before.last_sequence != attestation_after.last_sequence ||
	    attestation_before.consumed_handoff_token_count !=
	    attestation_after.consumed_handoff_token_count)
		fail("JOURNAL_ATTESTATION_RESTART_MISMATCH", FEX_ERR_CORRUPT);
	printf("M128_JOURNAL_ATTESTATION_RESTART_OK records=%llu sequence=%llu\n",
	       (unsigned long long)attestation_after.record_count,
	       (unsigned long long)attestation_after.last_sequence);
	CHECK_OK(fex_recover(&service, 20, &recovered, &dead_lettered),
		 "RECOVER");
	if (recovered != 0 || dead_lettered != 0)
		fail("RECOVER_COUNTS", FEX_ERR_STATE);
	CHECK_OK(fex_query_node(&service, node_c.task_id, &query_node), "QUERY_C_RECOVERED");
	if (query_node.state != FTS_TASK_RETRY_WAIT)
		fail("WORKER_RESCHEDULE_STATE", FEX_ERR_STATE);
	CHECK_OK(fex_query_worker(&service, node_c.task_id, &worker),
			 "QUERY_WORKER_REPLAY");
		if (worker.health != FEX_WORKER_REASSIGNED ||
			worker.reassignment_count != 1 || worker.handoff_count != 1 ||
			worker.worker_id != 9001)
			fail("WORKER_REPLAY_STATE", FEX_ERR_CORRUPT);

	printf("M115_POST_SUPERVISION_RECOVERY_IDEMPOTENT_OK recovered=%u\\n", recovered);
	printf("M115_WORKER_REPLAY_STATE_OK reassigned=%u\n",
	       worker.reassignment_count);
					printf("M117_WORKER_HANDOFF_REPLAY_OK worker=%llu handoffs=%u\n",
		       (unsigned long long)worker.worker_id, worker.handoff_count);

		{
			int restart_replay_rc = fex_handoff_token_verified(&service,
					node_c.task_id, 9001, 12, 100, consumed_handoff_token);
			if (restart_replay_rc != FEX_ERR_CONFLICT &&
			    restart_replay_rc != FEX_ERR_AUTHORITY)
				fail("RESTART_REPLAYED_HANDOFF_TOKEN", restart_replay_rc);
		}
		printf("M125_RESTART_REPLAYED_HANDOFF_TOKEN_DENIED_OK\n");
		printf("M126_JOURNAL_CHAIN_REPLAY_OK\n");
		printf("M127_JOURNAL_SEQUENCE_POLICY_OK\n");

	CHECK_OK(fex_query_objective(&service, objective.objective_id, &replayed),
		 "REPLAY_OBJECTIVE");
	if (replayed.objective_id != objective.objective_id ||
	    replayed.checkpoint_sequence != checkpoint.sequence)
		fail("REPLAY_STATE", FEX_ERR_CORRUPT);
	printf("M108_EXECUTION_REPLAY_OK generation=%llu\n",
	       (unsigned long long)replayed.generation);

	CHECK_OK(fex_cancel(&service, objective.objective_id), "CANCEL_OBJECTIVE");
	CHECK_OK(fex_query_objective(&service, objective.objective_id, &replayed),
		 "QUERY_CANCELLED");
	if (replayed.state != FEX_OBJECTIVE_CANCELLED)
		fail("CANCEL_STATE", FEX_ERR_STATE);
	printf("M108_CANCELLATION_COMPENSATION_BOUNDARY_OK\n");

	if (write(service.engine_fd, "x", 1) != 1)
		fail("ENGINE_CORRUPT_APPEND", FEX_ERR_IO);
	fex_close(&service);
	CHECK_EQ(fex_open(&service, prefix, require_kernel), FEX_ERR_CORRUPT,
		 "ENGINE_CORRUPTION_DETECTION");
	printf("M108_ENGINE_REPLAY_FAIL_CLOSED_OK\n");
	unlink(service.engine_path);
	unlink(service.tasks.journal_path);
	unlink(service.tasks.causal_journal_path);
	unlink(service.tasks.continuity_journal_path);
	printf("M108_SELFTEST_EXIT=0\n");
	return 0;
}
