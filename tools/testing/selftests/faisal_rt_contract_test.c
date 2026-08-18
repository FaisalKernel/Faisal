#include "../../faisal-rt/faisal_rt_contract.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "FRT_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static struct frt_job job(uint64_t id, uint64_t deadline, uint64_t budget,
	uint32_t priority, uint32_t criticality)
{
	struct frt_job j;
	memset(&j, 0, sizeof(j));
	j.job_id = id;
	j.release_ns = 1000;
	j.deadline_ns = deadline;
	j.budget_ns = budget;
	j.cpu_affinity_mask = 1;
	j.priority = priority;
	j.criticality = criticality;
	return j;
}

int main(void)
{
	struct frt_service service;
	struct frt_job root, critical, missed, queried;
	struct frt_dispatch dispatch;

	if (frt_init(&service, FRT_POLICY_FAIL_CLOSED | FRT_POLICY_REQUIRE_DEADLINE |
		FRT_POLICY_REQUIRE_BUDGET, 1, 1000) != FRT_OK)
		return fail("init", -1);
	root = job(1, 10000, 400, 1, FRT_CRITICALITY_BEST_EFFORT);
	critical = job(2, 5000, 200, 1, FRT_CRITICALITY_HARD);
	critical.dependency_count = 1;
	critical.dependencies[0] = 1;
	if (frt_admit(&service, &root) != FRT_OK ||
		frt_admit(&service, &critical) != FRT_OK)
		return fail("admit graph", -1);
	if (frt_select(&service, &dispatch) != FRT_OK || dispatch.job_id != 1 ||
		dispatch.effective_priority <= root.priority ||
		dispatch.dependency_fanout != 0)
		return fail("dependency priority inheritance", -1);
	printf("FRT_PRIORITY_INHERITANCE_OK selected=%llu effective=%u\n",
		(unsigned long long)dispatch.job_id, dispatch.effective_priority);
	if (frt_charge(&service, 1, 1100, 100, 1) != FRT_OK ||
		frt_complete(&service, 1, 1200, 1) != FRT_OK)
		return fail("root completion", -1);
	if (frt_select(&service, &dispatch) != FRT_OK || dispatch.job_id != 2 ||
		dispatch.slack_ns != 3800)
		return fail("critical successor selection", -1);
	printf("FRT_DEADLINE_PRIORITY_DISPATCH_OK selected=%llu slack=%llu\n",
		(unsigned long long)dispatch.job_id, (unsigned long long)dispatch.slack_ns);
	if (frt_charge(&service, 2, 1300, 250, 1) != FRT_ERR_VIOLATION ||
		frt_query(&service, 2, &queried) != FRT_OK ||
		queried.state != FRT_STATE_OVERRUN ||
		!(queried.violation_mask & FRT_VIOLATION_BUDGET))
		return fail("budget overrun", -1);
	printf("FRT_BUDGET_OVERRUN_REJECT_OK violations=0x%x\n", queried.violation_mask);

	missed = job(3, 2000, 100, 99, FRT_CRITICALITY_SOFT);
	if (frt_admit(&service, &missed) != FRT_OK)
		return fail("missed admit", -1);
	service.now_ns = 2000;
	if (frt_select(&service, &dispatch) != FRT_ERR_BLOCKED ||
		frt_query(&service, 3, &queried) != FRT_OK ||
		queried.state != FRT_STATE_MISSED ||
		!(queried.violation_mask & FRT_VIOLATION_DEADLINE))
		return fail("deadline miss", -1);
	printf("FRT_DEADLINE_MISS_FAIL_CLOSED_OK\n");

	root = job(4, 10000, 100, 1, FRT_CRITICALITY_SOFT);
	root.cpu_affinity_mask = 2;
	if (frt_admit(&service, &root) == FRT_OK)
		return fail("CPU affinity mismatch accepted", -1);
	printf("FRT_CPU_AFFINITY_REJECT_OK\n");
	root = job(5, 10000, 100, 1, FRT_CRITICALITY_SOFT);
	root.dependency_count = 1;
	root.dependencies[0] = 5;
	if (frt_admit(&service, &root) == FRT_OK)
		return fail("dependency self-cycle accepted", -1);
	printf("FRT_DEPENDENCY_CYCLE_REJECT_OK\n");

	root = job(6, 10000, 100, 1, FRT_CRITICALITY_SOFT);
	if (frt_admit(&service, &root) != FRT_OK ||
		frt_select(&service, &dispatch) != FRT_OK || dispatch.job_id != 6 ||
		frt_complete(&service, 6, 2100, 0) != FRT_ERR_VIOLATION ||
		frt_query(&service, 6, &queried) != FRT_OK ||
		!(queried.violation_mask & FRT_VIOLATION_AUTHORITY))
		return fail("authority boundary", -1);
	printf("FRT_MODEL_OUTPUT_NOT_AUTHORITY_OK\n");
	if (frt_test_policy_boundaries(&service) != FRT_OK)
		return fail("policy boundary helper", -1);
	printf("FRT_SELFTEST_EXIT=0\n");
	return 0;
}
