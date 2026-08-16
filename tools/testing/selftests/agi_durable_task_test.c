#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../faisal-task/faisal_task_service.h"

static void fail(const char *marker, int result)
{
	printf("M95_FAIL %s result=%d errno=%d\n", marker, result, errno);
	exit(1);
}

#define CHECK_OK(expr, marker) do { \
	int _result = (expr); \
	if (_result != FTS_OK) fail((marker), _result); \
} while (0)

#define CHECK_EQ(expr, expected, marker) do { \
	int _result = (expr); \
	if (_result != (expected)) fail((marker), _result); \
} while (0)

struct query_worker {
	const struct fts_service *service;
	uint64_t task_id;
	int failures;
};

static void *query_worker(void *argument)
{
	struct query_worker *worker = argument;
	unsigned int i;

	for (i = 0; i < 1000; i++) {
		struct fts_task task;

		if (fts_query(worker->service, worker->task_id, &task) != FTS_OK)
			worker->failures++;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	char journal_path[] = "/tmp/faisal-m95-task-XXXXXX";
	struct fts_service service;
	struct fts_task task_a, task_b, task_c, task_d, task_e, task_f, task_g, query;
	uint32_t dependency;
	uint32_t recovered;
	uint32_t dead_lettered;
	pthread_t workers[4];
	struct query_worker worker_state[4];
	int temporary_fd;
	unsigned int i;
	int require_kernel = argc > 1 && strcmp(argv[1], "--require-kernel") == 0;

	temporary_fd = mkstemp(journal_path);
	if (temporary_fd < 0)
		fail("mkstemp", FTS_ERR_IO);
	close(temporary_fd);
	unlink(journal_path);

	CHECK_OK(fts_open(&service, journal_path, require_kernel), "OPEN");
	if (require_kernel) {
		if (service.kernel_fd < 0 || service.session_id == 0 ||
		    service.agent_id == 0 || service.agent_capability == 0)
			fail("KERNEL_SESSION_BIND", FTS_ERR_KERNEL);
		printf("M95_KERNEL_SESSION_BIND_OK abi=38\n");
	}
	printf("M95_DURABLE_TASK_SERVICE_OPEN_OK\n");

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-a", "collect evidence",
			   100000000000ULL, 1000000, 1000, 500, 100, 2,
			   NULL, 0, &task_a), "SUBMIT_A");
	CHECK_OK(fts_submit(&service, 42, "goal-42-task-a", "collect evidence",
			   100000000000ULL, 1000000, 1000, 500, 100, 2,
			   NULL, 0, &query), "IDEMPOTENT_DUPLICATE");
	CHECK_EQ(fts_submit(&service, 42, "goal-42-task-a", "different objective",
			   100000000000ULL, 1000000, 1000, 500, 100, 2,
			   NULL, 0, &query), FTS_ERR_CONFLICT, "IDEMPOTENCY_CONFLICT");
	if (query.task_id != task_a.task_id)
		fail("IDEMPOTENT_ID", FTS_ERR_CONFLICT);
	printf("M95_IDEMPOTENT_SUBMIT_OK task=%llu\n",
	       (unsigned long long)task_a.task_id);

	dependency = (uint32_t)task_a.task_id;
	CHECK_OK(fts_submit(&service, 42, "goal-42-task-b", "evaluate evidence",
			   100000000000ULL, 2000000, 2000, 600, 200, 2,
			   &dependency, 1, &task_b), "SUBMIT_B");
	CHECK_EQ(fts_claim(&service, task_b.task_id, 1, 100, &query),
		 FTS_ERR_DEPENDENCY, "DEPENDENCY_GATE");
	printf("M95_DEPENDENCY_GATE_OK\n");

	CHECK_OK(fts_claim(&service, task_a.task_id, 1, 100, &query), "CLAIM_A");
	if (query.state != FTS_TASK_LEASED || !query.lease_generation)
		fail("CLAIM_STATE", FTS_ERR_STATE);
	CHECK_OK(fts_heartbeat(&service, task_a.task_id, query.lease_generation,
			       2, 100, &query), "HEARTBEAT_A");
	if (query.state != FTS_TASK_RUNNING)
		fail("HEARTBEAT_STATE", FTS_ERR_STATE);
	CHECK_OK(fts_complete(&service, task_a.task_id, query.lease_generation,
			       3, "evidence-collected", 100, 5, &task_a), "COMPLETE_A");
	printf("M95_LEASE_HEARTBEAT_COMPLETE_OK sequence=%llu\n",
	       (unsigned long long)task_a.sequence);

	CHECK_OK(fts_claim(&service, task_b.task_id, 4, 100, &task_b), "CLAIM_B");
	CHECK_OK(fts_fail(&service, task_b.task_id, task_b.lease_generation, 5,
			 FTS_FAILURE_TOOL, "source temporarily unavailable", 1,
			 &task_b), "RETRY_B");
	if (task_b.state != FTS_TASK_RETRY_WAIT || task_b.retry_count != 1)
		fail("RETRY_STATE", FTS_ERR_STATE);
	CHECK_EQ(fts_claim(&service, task_b.task_id, 6, 100, &query),
		 FTS_ERR_LEASE, "BACKOFF_GATE");
	CHECK_OK(fts_claim(&service, task_b.task_id, 2000000006ULL, 100, &task_b),
		 "RECLAIM_B");
	CHECK_OK(fts_complete(&service, task_b.task_id, task_b.lease_generation,
			       2000000007ULL, "evidence-verified", 200, 7, &task_b),
		 "COMPLETE_B");
	printf("M95_RETRY_BACKOFF_REPLAN_OK retries=%u\n", task_b.retry_count);

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-c", "deploy improvement",
			   100000000000ULL, 1000000, 1000, 700, 500, 2,
			   NULL, 0, &task_c), "SUBMIT_C");
	CHECK_OK(fts_claim(&service, task_c.task_id, 10, 5, &task_c), "CLAIM_C");
	fts_close(&service);
	CHECK_OK(fts_open(&service, journal_path, require_kernel), "REOPEN");
	CHECK_OK(fts_recover_expired(&service, 20, &recovered, &dead_lettered),
		 "RECOVER_EXPIRED");
	if (recovered != 1 || dead_lettered != 0)
		fail("RECOVER_COUNTS", FTS_ERR_STATE);
	CHECK_OK(fts_query(&service, task_c.task_id, &query), "QUERY_RECOVERED");
	if (query.state != FTS_TASK_READY)
		fail("RECOVERED_STATE", FTS_ERR_STATE);
	printf("M95_RESTART_RECOVERY_OK recovered=%u dead_lettered=%u\n",
	       recovered, dead_lettered);

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-d", "stop unsafe action",
			   100000000000ULL, 1000000, 1000, 800, 900, 1,
			   NULL, 0, &task_d), "SUBMIT_D");
	CHECK_OK(fts_cancel(&service, task_d.task_id, FTS_STOP_POLICY, &task_d),
		 "CANCEL_D");
	if (task_d.state != FTS_TASK_CANCELLED || task_d.stop_reason != FTS_STOP_POLICY)
		fail("CANCEL_STATE", FTS_ERR_STATE);
	printf("M95_POLICY_CANCEL_STOP_OK\n");

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-e", "deadline test",
			   50, 1000, 1000, 400, 100, 1, NULL, 0, &task_e),
		 "SUBMIT_E");
	CHECK_EQ(fts_claim(&service, task_e.task_id, 50, 100, &query),
		 FTS_ERR_DEADLINE, "DEADLINE_STOP");
	CHECK_OK(fts_query(&service, task_e.task_id, &query), "QUERY_DEADLINE");
	if (query.state != FTS_TASK_DEAD_LETTER ||
	    query.stop_reason != FTS_STOP_DEADLINE)
		fail("DEADLINE_STATE", FTS_ERR_STATE);
	printf("M95_DEADLINE_STOP_OK\n");

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-f", "budget test",
			   100000000000ULL, 10, 10, 400, 100, 1, NULL, 0, &task_f),
		 "SUBMIT_F");
	CHECK_OK(fts_claim(&service, task_f.task_id, 60, 100, &task_f), "CLAIM_F");
	CHECK_EQ(fts_complete(&service, task_f.task_id, task_f.lease_generation,
			     61, "too expensive", 11, 0, &query),
		 FTS_ERR_BUDGET, "BUDGET_STOP");
	printf("M95_BUDGET_STOP_OK\n");

	CHECK_OK(fts_submit(&service, 42, "goal-42-task-g", "exhaust retries",
			   100000000000ULL, 1000, 1000, 400, 100, 1, NULL, 0, &task_g),
		 "SUBMIT_G");
	CHECK_OK(fts_claim(&service, task_g.task_id, 70, 100, &task_g), "CLAIM_G1");
	CHECK_OK(fts_fail(&service, task_g.task_id, task_g.lease_generation, 71,
			 FTS_FAILURE_TOOL, "first failure", 1, &task_g), "FAIL_G1");
	CHECK_OK(fts_claim(&service, task_g.task_id, 2000000072ULL, 100, &task_g),
		 "CLAIM_G2");
	CHECK_EQ(fts_fail(&service, task_g.task_id, task_g.lease_generation,
			 2000000073ULL, FTS_FAILURE_TOOL, "retry exhausted", 1, &query),
		 FTS_ERR_STOPPED, "FAIL_G2_DEAD_LETTER");
	CHECK_OK(fts_query(&service, task_g.task_id, &query), "QUERY_G");
	if (query.state != FTS_TASK_DEAD_LETTER)
		fail("DEAD_LETTER_STATE", FTS_ERR_STATE);
	printf("M95_RETRY_EXHAUSTION_DEAD_LETTER_OK\n");

	CHECK_OK(fts_query(&service, task_a.task_id, &query), "QUERY_A");
	for (i = 0; i < 4; i++) {
		worker_state[i].service = &service;
		worker_state[i].task_id = task_a.task_id;
		worker_state[i].failures = 0;
		if (pthread_create(&workers[i], NULL, query_worker, &worker_state[i]) != 0)
			fail("THREAD_CREATE", FTS_ERR_STATE);
	}
	for (i = 0; i < 4; i++)
		pthread_join(workers[i], NULL);
	for (i = 0; i < 4; i++)
		if (worker_state[i].failures)
			fail("CONCURRENT_QUERY", FTS_ERR_STATE);
	printf("M95_CONCURRENT_QUERY_OK workers=4\n");

	fts_close(&service);
	CHECK_OK(fts_open(&service, journal_path, require_kernel), "REOPEN_FINAL");
	CHECK_OK(fts_query(&service, task_a.task_id, &query), "REPLAY_A");
	if (query.state != FTS_TASK_SUCCEEDED)
		fail("REPLAY_A_STATE", FTS_ERR_STATE);
	CHECK_OK(fts_query(&service, task_b.task_id, &query), "REPLAY_B");
	if (query.state != FTS_TASK_SUCCEEDED)
		fail("REPLAY_B_STATE", FTS_ERR_STATE);
	printf("M95_REPLAY_STATE_OK\n");

	CHECK_OK(fts_test_corrupt_tail(&service), "CORRUPT_TAIL");
	fts_close(&service);
	CHECK_EQ(fts_open(&service, journal_path, require_kernel),
		 FTS_ERR_CORRUPT, "CORRUPTION_DETECTION");
	printf("M95_CORRUPTION_FAIL_CLOSED_OK\n");
	unlink(journal_path);
	printf("M95_SELFTEST_EXIT=0\n");
	return 0;
}
