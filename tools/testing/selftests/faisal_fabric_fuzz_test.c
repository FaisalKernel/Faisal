#include "../../faisal-fabric/faisal_fabric.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t next_rand(uint32_t *state)
{
	*state = *state * 1664525U + 1013904223U;
	return *state;
}

int main(void)
{
	struct ff_event event;
	struct ff_shard shard;
	struct ff_shard out;
	uint8_t payload[FF_MAX_PAYLOAD];
	uint8_t previous[FF_DIGEST_SIZE];
	struct ff_service service;
	struct ff_policy policy;
	char path[128];
	uint32_t state = 0x242f00U;
	unsigned int rejected = 0U;
	unsigned int accepted = 0U;
	unsigned int i;

	memset(&policy, 0, sizeof(policy));
	policy.current_time_ns = 100U;
	policy.default_lease_ns = 100U;
	policy.max_lease_ns = 200U;
	policy.max_queue_depth = FF_MAX_SHARDS;
	snprintf(path, sizeof(path), "/tmp/faisal-fabric-fuzz-%ld.journal", (long)getpid());
	unlink(path);
	if (ff_open(&service, path, &policy) != FF_OK)
		return 1;
	for (i = 0U; i < 10000U; ++i) {
		memset(&event, 0, sizeof(event));
		memset(payload, 0, sizeof(payload));
		memset(previous, 0, sizeof(previous));
		for (size_t j = 0U; j < sizeof(event); ++j)
			((uint8_t *)&event)[j] = (uint8_t)next_rand(&state);
		for (size_t j = 0U; j < sizeof(payload); ++j)
			payload[j] = (uint8_t)next_rand(&state);
		if (ff_verify_event(&event, payload, previous) == FF_OK)
			accepted++;
		else
			rejected++;
		memset(&shard, 0, sizeof(shard));
		shard.objective_id = next_rand(&state);
		shard.agent_id = next_rand(&state);
		shard.tenant_id = next_rand(&state);
		shard.trace_id = next_rand(&state);
		shard.task_generation = next_rand(&state);
		shard.session_generation = next_rand(&state);
		shard.issued_at_ns = next_rand(&state);
		shard.deadline_ns = next_rand(&state);
		shard.priority = next_rand(&state);
		shard.flags = next_rand(&state);
		shard.demand.cpu_ns = next_rand(&state);
		shard.demand.memory_bytes = next_rand(&state);
		memset(shard.budget_receipt_digest, (int)next_rand(&state), FF_DIGEST_SIZE);
		memset(shard.provenance_digest, (int)next_rand(&state), FF_DIGEST_SIZE);
		(void)ff_submit_shard(&service, &shard, &out);
	}
	ff_close(&service);
	unlink(path);
	if (accepted != 0U || rejected != 10000U)
		return 1;
	printf("M242_FABRIC_FUZZ_EXIT=0 iterations=10000 rejected=%u accepted=%u\n",
	       rejected, accepted);
	return 0;
}
