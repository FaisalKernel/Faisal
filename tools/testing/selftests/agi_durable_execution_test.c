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
	struct fex_objective objective, replayed;
	struct fex_node node_a, node_b, node_c, query_node;
	struct fex_checkpoint checkpoint;
	uint8_t working[FEX_DIGEST_SIZE], world[FEX_DIGEST_SIZE], resource[FEX_DIGEST_SIZE];
	uint32_t dependency;
	uint32_t claimed, recovered, dead_lettered;
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
	fex_close(&service);
	CHECK_OK(fex_open(&service, prefix, require_kernel), "REOPEN");
	CHECK_OK(fex_recover(&service, 20, &recovered, &dead_lettered),
		 "RECOVER");
	if (recovered != 1 || dead_lettered != 0)
		fail("RECOVER_COUNTS", FEX_ERR_STATE);
	CHECK_OK(fex_query_node(&service, node_c.task_id, &query_node), "QUERY_C_RECOVERED");
	if (query_node.state != FTS_TASK_READY)
		fail("WORKER_RESCHEDULE_STATE", FEX_ERR_STATE);
	printf("M108_RESTART_WORKER_RECOVERY_OK recovered=%u\n", recovered);

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
