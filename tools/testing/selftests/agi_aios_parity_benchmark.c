// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../faisal-execution/faisal_execution_engine.h"

#define M222_AGENTS 8U
#define M222_PHASES 4U
#define M222_ITERATIONS 8U
#define M222_MEMORY_ITEMS 4U
#define M222_MAX_SAMPLES M222_ITERATIONS

struct reference_agent {
	uint32_t state;
	uint32_t context_epoch;
	uint32_t memory_items;
	uint32_t tool_calls;
	uint32_t verified;
};

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void digest(const char *text, uint8_t out[FEX_DIGEST_SIZE])
{
	size_t length = strlen(text);
	unsigned int i;

	for (i = 0; i < FEX_DIGEST_SIZE; i++)
		out[i] = (uint8_t)(text[i % length] + i + (i / length));
}

static int reference_iteration(unsigned int iteration)
{
	struct reference_agent agents[M222_AGENTS];
	unsigned int agent;
	unsigned int phase;

	memset(agents, 0, sizeof(agents));
	for (agent = 0; agent < M222_AGENTS; agent++) {
		agents[agent].state = 1;
		for (phase = 0; phase < M222_PHASES; phase++) {
			/* Transparent AIOS-style reference: FIFO dispatch, context epoch,
			 * bounded memory list, tool admission, and verification. */
			agents[agent].context_epoch++;
			if (agents[agent].memory_items < M222_MEMORY_ITEMS)
				agents[agent].memory_items++;
			agents[agent].tool_calls++;
			agents[agent].state = phase == M222_PHASES - 1 ? 3 : 2;
		}
		agents[agent].verified = agents[agent].state == 3;
		if (!agents[agent].verified || agents[agent].context_epoch != M222_PHASES ||
		    agents[agent].memory_items != M222_MEMORY_ITEMS ||
		    agents[agent].tool_calls != M222_PHASES)
			return -1;
	}
	(void)iteration;
	return 0;
}

static int faisal_iteration(struct fex_service *service, unsigned int iteration,
					uint64_t now_ns)
{
	struct fex_objective objective;
	struct fex_node nodes[M222_PHASES];
	uint8_t digest_value[FEX_DIGEST_SIZE];
	uint32_t dependency;
	uint32_t claimed;
	unsigned int phase;
	char intent[FEX_MAX_INTENT];
	char key[64];
	char action[64];
	char result[64];

	snprintf(intent, sizeof(intent), "m222-aios-parity-agent-%u", iteration);
	if (fex_create_objective(service, intent, now_ns + 1000000000ULL,
				1000000000ULL, 1000000ULL, 1, now_ns, &objective) != FEX_OK)
		return -1;
	for (phase = 0; phase < M222_PHASES; phase++) {
		dependency = phase ? (uint32_t)nodes[phase - 1].task_id : 0;
		snprintf(key, sizeof(key), "m222-%u-%u", iteration, phase);
		snprintf(action, sizeof(action), "agent-%u-phase-%u", iteration, phase);
		if (fex_add_node(service, objective.objective_id, key, action,
				700U - phase * 10U, 10, 1,
				phase ? &dependency : NULL, phase ? 1U : 0U,
				1, 0, &nodes[phase]) != FEX_OK)
			return -1;
	}
	for (phase = 0; phase < M222_PHASES; phase++) {
		if (fex_dispatch(service, objective.objective_id,
				now_ns + phase + 1, 1000000U, &claimed) != FEX_OK ||
		    claimed != 1)
			return -1;
		snprintf(result, sizeof(result), "verified-phase-%u", phase);
		digest(result, digest_value);
		if (fex_complete(service, nodes[phase].task_id,
				now_ns + phase + 2, result, digest_value) != FEX_OK)
			return -1;
	}
	return 0;
}

static uint64_t mean(const uint64_t *samples, unsigned int count)
{
	uint64_t total = 0;
	unsigned int i;

	for (i = 0; i < count; i++)
		total += samples[i];
	return count ? total / count : 0;
}

static uint64_t percentile95(uint64_t *samples, unsigned int count)
{
	unsigned int i;
	unsigned int j;
	uint64_t value;

	for (i = 1; i < count; i++) {
		value = samples[i];
		j = i;
		while (j && samples[j - 1] > value) {
			samples[j] = samples[j - 1];
			j--;
		}
		samples[j] = value;
	}
	return count ? samples[(count * 95U + 99U) / 100U - 1U] : 0;
}

static int open_journal(char *path, size_t size, unsigned int iteration)
{
	int fd;

	if (snprintf(path, size, "/tmp/faisal-m222-parity-%u-XXXXXX", iteration) < 0)
		return -1;
	fd = mkstemp(path);
	if (fd < 0)
		return -1;
	close(fd);
	unlink(path);
	return 0;
}

static void remove_journal_files(const char *path)
{
	char suffix[512];
	const char *names[] = {
		"", ".execution", ".tasks", ".causal", ".continuity",
		".mission", ".intent", ".lifecycle"
	};
	unsigned int i;

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (names[i][0] == '\0')
			unlink(path);
		else if (snprintf(suffix, sizeof(suffix), "%s%s", path, names[i]) > 0)
			unlink(suffix);
	}
}

static int priority_policy_check(void)
{
	struct fex_service service;
	struct fex_objective objective;
	struct fex_node low;
	struct fex_node high;
	struct fex_node query_low;
	struct fex_node query_high;
	uint8_t digest_value[FEX_DIGEST_SIZE];
	uint32_t claimed;
	char path[256];
	int rc;

	if (open_journal(path, sizeof(path), 9000) != 0 ||
	    fex_open(&service, path, 0) != FEX_OK)
		return -1;
	rc = fex_create_objective(&service, "m222 dispatch policy", 1000000000ULL,
				1000000000ULL, 1000000ULL, 1, 1000, &objective);
	if (rc != FEX_OK)
		return -1;
	rc = fex_add_node(&service, objective.objective_id, "m222-low", "low priority",
				10, 1, 1, NULL, 0, 1, 0, &low);
	if (rc != FEX_OK)
		return -1;
	rc = fex_add_node(&service, objective.objective_id, "m222-high", "high priority",
				900, 1, 1, NULL, 0, 1, 0, &high);
	if (rc != FEX_OK)
		return -1;
	if (fex_dispatch(&service, objective.objective_id, 1001, 1000000, &claimed) != FEX_OK ||
	    claimed != 1 || fex_query_node(&service, low.task_id, &query_low) != FEX_OK ||
	    fex_query_node(&service, high.task_id, &query_high) != FEX_OK ||
	    query_high.state != FTS_TASK_LEASED || query_low.state == FTS_TASK_LEASED)
		return -1;
	digest("m222-policy-high", digest_value);
	if (fex_complete(&service, high.task_id, 1002, "high complete", digest_value) != FEX_OK ||
	    fex_dispatch(&service, objective.objective_id, 1003, 1000000, &claimed) != FEX_OK ||
	    claimed != 1 || fex_complete(&service, low.task_id, 1004, "low complete", digest_value) != FEX_OK)
		return -1;
	fex_close(&service);
	remove_journal_files(path);
	return 0;
}

int main(void)
{
	uint64_t reference_samples[M222_MAX_SAMPLES];
	uint64_t faisal_samples[M222_MAX_SAMPLES];
	uint64_t recovery_start;
	uint64_t recovery_end;
	uint64_t reference_start;
	uint64_t reference_end;
	uint64_t faisal_start;
	uint64_t faisal_end;
	struct fex_journal_attestation before;
	struct fex_journal_attestation after;
	char path[256];
	struct fex_service service;
	unsigned int iteration;
	unsigned int recovery_ok = 0;

	if (priority_policy_check() != 0) {
		fprintf(stderr, "M222_DISPATCH_POLICY_FAIL\n");
		return 1;
	}
	printf("M222_DISPATCH_POLICY_ORDER_OK\n");
	for (iteration = 0; iteration < M222_ITERATIONS; iteration++) {
		reference_start = monotonic_ns();
		if (reference_iteration(iteration) != 0)
			return 1;
		reference_end = monotonic_ns();
		reference_samples[iteration] = reference_end - reference_start;

		if (open_journal(path, sizeof(path), iteration) != 0 ||
		    fex_open(&service, path, 0) != FEX_OK)
			return 1;
		faisal_start = monotonic_ns();
		if (faisal_iteration(&service, iteration, 1000000ULL + iteration * 1000ULL) != 0)
			return 1;
		faisal_end = monotonic_ns();
		faisal_samples[iteration] = faisal_end - faisal_start;
		if (fex_query_journal_attestation(&service, &before) != FEX_OK ||
		    before.record_count == 0 || before.last_sequence == 0)
			return 1;
		fex_close(&service);
		recovery_start = monotonic_ns();
		if (fex_open(&service, path, 0) != FEX_OK ||
		    fex_query_journal_attestation(&service, &after) != FEX_OK ||
		    after.record_count != before.record_count ||
		    after.last_sequence != before.last_sequence ||
		    memcmp(after.chain_digest, before.chain_digest, FEX_DIGEST_SIZE) != 0)
			return 1;
		recovery_end = monotonic_ns();
		fex_close(&service);
		remove_journal_files(path);
		recovery_ok++;
		(void)recovery_start;
		(void)recovery_end;
	}

	printf("M222_AIOS_PARITY_AGENTS=%u\n", M222_AGENTS);
	printf("M222_AIOS_PARITY_PHASES=%u\n", M222_PHASES);
	printf("M222_AIOS_PARITY_ITERATIONS=%u\n", M222_ITERATIONS);
	printf("M222_REFERENCE_MEAN_NS=%llu\n",
	       (unsigned long long)mean(reference_samples, M222_ITERATIONS));
	printf("M222_REFERENCE_P95_NS=%llu\n",
	       (unsigned long long)percentile95(reference_samples, M222_ITERATIONS));
	printf("M222_FAISAL_DURABLE_MEAN_NS=%llu\n",
	       (unsigned long long)mean(faisal_samples, M222_ITERATIONS));
	printf("M222_FAISAL_DURABLE_P95_NS=%llu\n",
	       (unsigned long long)percentile95(faisal_samples, M222_ITERATIONS));
	printf("M222_FAISAL_RECOVERY_OK=%u\n", recovery_ok == M222_ITERATIONS);
	printf("M222_FAISAL_PROVENANCE_BOUNDARY=journal_chain_attestation_and_verified_evidence_digest\n");
	printf("M222_COMPARISON_SCOPE=transparent_reference_fixture_not_actual_AIOS_implementation\n");
	printf("M222_SUPERIORITY_CLAIM=none_without_same_hardware_and_workload_baseline\n");
	printf("M222_SELFTEST_EXIT=0\n");
	return 0;
}
