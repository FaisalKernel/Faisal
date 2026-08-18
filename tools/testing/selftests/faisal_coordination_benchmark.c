#define _POSIX_C_SOURCE 200809L

#include "../../faisal-coordination/faisal_coordination.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

static void fill_bytes(uint8_t *bytes, uint8_t value)
{
	memset(bytes, value, MAC_DIGEST_SIZE);
}

static uint64_t now_ns(void)
{
	struct timespec ts;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int one_round(struct mac_service *service)
{
	struct mac_policy limits;
	struct mac_agent agents[3];
	struct mac_capability capability;
	struct mac_delegation request;
	struct mac_evidence evidence;
	struct mac_vote vote;
	struct mac_receipt receipt;
	uint64_t agent_id;
	uint64_t registered_id;
	uint64_t delegation_id;
	int result;

	memset(&limits, 0, sizeof(limits));
	limits.coordinator_generation = 9U;
	limits.current_time_ns = 2000000000ULL;
	limits.max_lease_ns = 10000000000ULL;
	limits.max_cpu_budget_ns = 100000000000ULL;
	limits.max_memory_budget_bytes = 1ULL << 30;
	limits.max_cost_micro = 1000000U;
	limits.minimum_capability_confidence_ppm = 700000U;
	limits.max_delegations = MAC_MAX_DELEGATIONS;
	limits.require_explicit_authority = 1U;
	limits.require_evidence_for_commit = 1U;
	result = mac_init(service, &limits);
	if (result != MAC_OK)
		return result;
	memset(agents, 0, sizeof(agents));
	for (agent_id = 0U; agent_id < 3U; ++agent_id) {
		agents[agent_id].agent_id = agent_id + 1U;
		agents[agent_id].agent_generation = 1U;
		agents[agent_id].trust_ppm = 900000U;
		fill_bytes(agents[agent_id].identity_digest, (uint8_t)(0x11U + agent_id));
		result = mac_register_agent(service, &agents[agent_id], &registered_id);
		if (result != MAC_OK)
			return result;
	}
	memset(&capability, 0, sizeof(capability));
	capability.owner_agent_id = 2U;
	capability.capability_generation = 1U;
	capability.capability_class = 3U;
	capability.confidence_ppm = 900000U;
	fill_bytes(capability.scope_digest, 0x31U);
	fill_bytes(capability.capability_digest, 0x32U);
	result = mac_register_capability(service, &capability, NULL);
	if (result != MAC_OK)
		return result;
	memset(&request, 0, sizeof(request));
	request.objective_id = 44U;
	request.parent_agent_id = 1U;
	request.target_agent_id = 2U;
	request.trace_id = 101U;
	request.parent_generation = 1U;
	request.target_generation = 1U;
	request.coordinator_generation = 9U;
	request.message_sequence = 1U;
	request.created_at_ns = 1000000000ULL;
	request.deadline_ns = 20000000000ULL;
	request.lease_until_ns = 10000000000ULL;
	request.cpu_budget_ns = 1000000U;
	request.memory_budget_bytes = 4096U;
	request.cost_budget_micro = 100U;
	request.required_capability_mask = 1ULL << 3;
	request.participant_count = 3U;
	request.quorum_required = 2U;
	request.evidence_required = 1U;
	request.flags = MAC_FLAG_AUTHORITY_GRANTED;
	request.participant_ids[0] = 1U;
	request.participant_ids[1] = 2U;
	request.participant_ids[2] = 3U;
	fill_bytes(request.objective_digest, 0x41U);
	fill_bytes(request.context_digest, 0x42U);
	(void)snprintf(request.message, sizeof(request.message), "benchmark delegation");
	result = mac_admit_delegation(service, &request, &receipt);
	if (result != MAC_OK)
		return result;
	delegation_id = receipt.delegation_id;
	memset(&evidence, 0, sizeof(evidence));
	evidence.delegation_id = delegation_id;
	evidence.agent_id = 2U;
	evidence.sequence = 1U;
	evidence.observed_at_ns = 1500000000ULL;
	evidence.kind = MAC_EVIDENCE_VERIFICATION;
	evidence.verified = 1U;
	fill_bytes(evidence.evidence_digest, 0x51U);
	fill_bytes(evidence.provenance_digest, 0x52U);
	result = mac_add_evidence(service, delegation_id, &evidence);
	if (result != MAC_OK)
		return result;
	memset(&vote, 0, sizeof(vote));
	vote.delegation_id = delegation_id;
	vote.agent_generation = 1U;
	vote.coordinator_generation = 9U;
	vote.decision = MAC_VOTE_APPROVE;
	vote.evidence_count = 1U;
	fill_bytes(vote.evidence_digest, 0x51U);
	fill_bytes(vote.rationale_digest, 0x61U);
	vote.agent_id = 2U;
	vote.vote_sequence = 2U;
	result = mac_vote(service, delegation_id, &vote, &receipt);
	if (result != MAC_OK)
		return result;
	vote.agent_id = 3U;
	vote.vote_sequence = 3U;
	fill_bytes(vote.rationale_digest, 0x62U);
	result = mac_vote(service, delegation_id, &vote, &receipt);
	if (result != MAC_OK)
		return result;
	result = mac_commit(service, delegation_id, &receipt);
	if (result != MAC_OK)
		return result;
	return mac_verify_receipt(service, &receipt);
}

int main(void)
{
	static struct mac_service service;
	const uint64_t rounds = 100000U;
	uint64_t i;
	uint64_t start;
	uint64_t elapsed;
	int result;

	start = now_ns();
	for (i = 0U; i < rounds; ++i) {
		result = one_round(&service);
		if (result != MAC_OK) {
			printf("M236_BENCHMARK_EXIT=1 round=%llu status=%d\n",
			       (unsigned long long)i, result);
			return 1;
		}
	}
	elapsed = now_ns() - start;
	printf("M236_BENCHMARK_EXIT=0 rounds=%llu operations=%llu elapsed_ns=%llu ns_per_operation=%.2f\n",
	       (unsigned long long)rounds,
	       (unsigned long long)(rounds * 10ULL),
	       (unsigned long long)elapsed,
	       (double)elapsed / (double)(rounds * 10ULL));
	return 0;
}
