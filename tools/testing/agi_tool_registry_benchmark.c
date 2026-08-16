#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../faisal-tool/faisal_tool_service.h"

#define BENCH_ITERATIONS 4U

static uint64_t monotonic_ns(void)
{
	struct timespec time;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &time) != 0)
		return 0;
	return (uint64_t)time.tv_sec * 1000000000ULL + (uint64_t)time.tv_nsec;
}

static void fill_digest(uint8_t digest[M99_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, M99_DIGEST_SIZE);
}

static void host_authority(struct fts_authority_ref *authority,
				   uint64_t lease_id)
{
	memset(authority, 0, sizeof(*authority));
	authority->lease_id = lease_id;
	authority->grant_id = lease_id + 1;
	authority->grant_capability = lease_id + 2;
	authority->agent_id = 4;
	authority->agent_capability = 5;
	authority->lineage_id = lease_id + 3;
	authority->generation = 1;
	authority->operation_class = AGI_LC_INTENT_OP_TOOL;
	authority->resource_mask = AGI_LC_RESOURCE_CPU;
	authority->intent_digest[0] = 0x99;
	authority->intent_digest[1] = (uint8_t)lease_id;
}

static void policy(struct m98_policy *policy_out, uint64_t now_ns)
{
	memset(policy_out, 0, sizeof(*policy_out));
	policy_out->deadline_ns = now_ns + 1000000000ULL;
	policy_out->cpu_budget_ns = 1000000000ULL;
	policy_out->money_budget_micro = 1000000ULL;
	policy_out->max_steps = 8;
	policy_out->max_retries = 1;
	policy_out->risk_ceiling = 20;
	policy_out->supervisor_approved = 1;
	policy_out->operator_approved = 1;
	policy_out->supervisor_nonce = 11;
	policy_out->operator_nonce = 12;
}

static int direct_m98_iteration(struct m98_service *service, unsigned int index,
					const struct fts_authority_ref *authority)
{
	struct m98_policy mission_policy;
	struct m98_mission mission;
	uint8_t plan[M99_DIGEST_SIZE];
	uint8_t model[M99_DIGEST_SIZE];
	uint8_t action[M99_DIGEST_SIZE];
	uint64_t now = 1000 + index * 10;

	policy(&mission_policy, now);
	fill_digest(plan, 0x10 + (uint8_t)index);
	fill_digest(model, 0x20 + (uint8_t)index);
	fill_digest(action, 0x30 + (uint8_t)index);
	if (m98_create(service, "benchmark direct action", &mission_policy, now,
		       &mission) != M98_OK)
		return -1;
	if (m98_observe(service, mission.mission_id, now + 1, index + 1,
			M98_TRIGGER_MANUAL, plan, model, action,
			"direct benchmark observation", &mission) != M98_OK)
		return -1;
	if (m98_propose(service, mission.mission_id, now + 2, authority,
			plan, model, action, 10, AGI_LC_RESOURCE_CPU, 100,
			"direct benchmark proposal", "direct trusted action", &mission) != M98_OK)
		return -1;
	return m98_execute_result(service, mission.mission_id, now + 3, 100, 10,
				 M98_DECISION_CONTINUE, 1, "direct verified result", &mission) ==
		M98_OK ? 0 : -1;
}

static int governed_m99_iteration(struct m99_service *service, unsigned int index,
					  const struct fts_authority_ref *authority,
					  uint64_t tool_id)
{
	struct m98_policy mission_policy;
	struct m98_mission mission;
	struct m99_invocation invocation;
	uint8_t plan[M99_DIGEST_SIZE];
	uint8_t model[M99_DIGEST_SIZE];
	uint8_t action[M99_DIGEST_SIZE];
	uint8_t input[M99_DIGEST_SIZE];
	uint8_t output[M99_DIGEST_SIZE];
	uint64_t now = 2000 + index * 10;

	policy(&mission_policy, now);
	fill_digest(plan, 0x40 + (uint8_t)index);
	fill_digest(model, 0x50 + (uint8_t)index);
	fill_digest(action, 0x60 + (uint8_t)index);
	fill_digest(input, 0x70 + (uint8_t)index);
	fill_digest(output, 0x80 + (uint8_t)index);
	if (m98_create(&service->mission, "benchmark governed action", &mission_policy,
		       now, &mission) != M98_OK)
		return -1;
	if (m98_observe(&service->mission, mission.mission_id, now + 1, index + 1,
			M98_TRIGGER_MANUAL, plan, model, action,
			"governed benchmark observation", &mission) != M98_OK)
		return -1;
	if (m98_propose(&service->mission, mission.mission_id, now + 2, authority,
			plan, model, action, 10, AGI_LC_RESOURCE_CPU, 100,
			"governed benchmark proposal", "registered governed action", &mission) != M98_OK)
		return -1;
	if (m99_admit(service, mission.mission_id, now + 3, authority, tool_id,
		      input, &invocation) != M99_OK)
		return -1;
	if (m99_execute(service, invocation.invocation_id, now + 4, &invocation) != M99_OK)
		return -1;
	return m99_complete(service, invocation.invocation_id, now + 5, 0, 1,
				output, "governed verified result", &invocation) == M99_OK ? 0 : -1;
}

int main(void)
{
	char direct_path[] = "/tmp/faisal-m99-bench-direct-XXXXXX";
	char governed_path[] = "/tmp/faisal-m99-bench-governed-XXXXXX";
	struct m98_service direct;
	struct m99_service governed;
	struct fts_authority_ref direct_authority;
	struct fts_authority_ref governed_authority;
	struct m99_tool_spec tool;
	uint8_t implementation[M99_DIGEST_SIZE];
	uint64_t start;
	uint64_t end;
	uint64_t direct_total = 0;
	uint64_t governed_total = 0;
	unsigned int index;
	int fd;

	fd = mkstemp(direct_path);
	if (fd < 0)
		return 1;
	close(fd);
	unlink(direct_path);
	fd = mkstemp(governed_path);
	if (fd < 0)
		return 1;
	close(fd);
	unlink(governed_path);
	if (m98_open(&direct, direct_path, 0) != M98_OK)
		return 1;
	if (m99_open(&governed, governed_path, 0) != M99_OK)
		return 1;
	host_authority(&direct_authority, 99101);
	host_authority(&governed_authority, 99102);
	fill_digest(implementation, 0x91);
	if (m99_register(&governed, "benchmark-tool", "bounded benchmark fixture",
			AGI_LC_INTENT_OP_TOOL, AGI_LC_RESOURCE_CPU, 10,
			M99_TOOL_FLAG_REQUIRES_OBSERVATION, 100, 10,
			implementation, &tool) != M99_OK)
		return 1;
	start = monotonic_ns();
	for (index = 0; index < BENCH_ITERATIONS; index++)
		if (direct_m98_iteration(&direct, index, &direct_authority) != 0)
			return 1;
	end = monotonic_ns();
	direct_total = end - start;
	start = monotonic_ns();
	for (index = 0; index < BENCH_ITERATIONS; index++)
		if (governed_m99_iteration(&governed, index, &governed_authority,
					   tool.tool_id) != 0)
			return 1;
	end = monotonic_ns();
	governed_total = end - start;
	printf("M99_BENCHMARK_ITERATIONS=%u\n", BENCH_ITERATIONS);
	printf("M99_BENCHMARK_DIRECT_M98_TOTAL_NS=%llu\n",
	       (unsigned long long)direct_total);
	printf("M99_BENCHMARK_GOVERNED_M99_TOTAL_NS=%llu\n",
	       (unsigned long long)governed_total);
	printf("M99_BENCHMARK_DIRECT_M98_MEAN_NS=%llu\n",
	       (unsigned long long)(direct_total / BENCH_ITERATIONS));
	printf("M99_BENCHMARK_GOVERNED_M99_MEAN_NS=%llu\n",
	       (unsigned long long)(governed_total / BENCH_ITERATIONS));
	printf("M99_BENCHMARK_SCOPE=journaled_host_path_not_external_tool_latency\n");
	m99_close(&governed);
	m98_close(&direct);
	unlink(direct_path);
	unlink(governed_path);
	{
		char suffix[sizeof(direct_path) + 32];
		snprintf(suffix, sizeof(suffix), "%s.task", direct_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.causal", direct_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.continuity", direct_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.mission", direct_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.tools", governed_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.task", governed_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.causal", governed_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.continuity", governed_path);
		unlink(suffix);
		snprintf(suffix, sizeof(suffix), "%s.mission", governed_path);
		unlink(suffix);
	}
	return 0;
}
