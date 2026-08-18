#define _GNU_SOURCE
#include "../../faisal-rt/faisal_rt_contract.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define FRT_BENCH_ROUNDS 10000U
#define FRT_BENCH_JOBS 32U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct frt_job make_job(uint32_t i, uint64_t now)
{
	struct frt_job j;
	memset(&j, 0, sizeof(j));
	j.job_id = i + 1;
	j.release_ns = now;
	j.deadline_ns = now + 1000000ULL + (uint64_t)(FRT_BENCH_JOBS - i) * 1000ULL;
	j.budget_ns = 100000ULL;
	j.cpu_affinity_mask = 1;
	j.priority = i;
	j.criticality = (i % 3U) + 1U;
	return j;
}

int main(void)
{
	struct frt_service service;
	struct frt_dispatch dispatch;
	struct frt_job j;
	uint64_t start, elapsed;
	uint64_t logical_now = 1000;
	unsigned int round, i, selected = 0;

	start = now_ns();
	for (round = 0; round < FRT_BENCH_ROUNDS; round++) {
		if (frt_init(&service, FRT_POLICY_FAIL_CLOSED |
			FRT_POLICY_REQUIRE_DEADLINE | FRT_POLICY_REQUIRE_BUDGET,
			1, logical_now) != FRT_OK)
			return 1;
		for (i = 0; i < FRT_BENCH_JOBS; i++) {
			j = make_job(i, logical_now);
			if (frt_admit(&service, &j) != FRT_OK)
				return 2;
		}
		for (i = 0; i < FRT_BENCH_JOBS; i++) {
			if (frt_select(&service, &dispatch) != FRT_OK)
				return 3;
			if (frt_complete(&service, dispatch.job_id,
				logical_now + 100, 1) != FRT_OK)
				return 4;
			selected++;
		}
		logical_now += 1000;
	}
	elapsed = now_ns() - start;
	printf("FRT_BENCH rounds=%u jobs_per_round=%u selections=%u total_ns=%llu ns_per_round=%llu ns_per_selection=%llu\n",
		FRT_BENCH_ROUNDS, FRT_BENCH_JOBS, selected,
		(unsigned long long)elapsed,
		(unsigned long long)(elapsed / FRT_BENCH_ROUNDS),
		(unsigned long long)(elapsed / selected));
	printf("FRT_BENCH_SCOPE=local_userspace_policy_fixture_not_PREEMPT_RT_or_hard_latency_qualification\n");
	return 0;
}
