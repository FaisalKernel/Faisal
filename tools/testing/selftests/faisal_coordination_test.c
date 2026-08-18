#include "../../faisal-coordination/faisal_coordination.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT_EQ(label, actual, expected) do { \
	int _actual = (actual); \
	int _expected = (expected); \
	if (_actual != _expected) { \
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", (label), _actual, _expected); \
		failures++; \
	} \
} while (0)

static void fill_bytes(uint8_t *bytes, uint8_t value)
{
	memset(bytes, value, MAC_DIGEST_SIZE);
}

static struct mac_policy policy(void)
{
	struct mac_policy value;

	memset(&value, 0, sizeof(value));
	value.coordinator_generation = 9U;
	value.current_time_ns = 2000000000ULL;
	value.max_lease_ns = 10000000000ULL;
	value.max_cpu_budget_ns = 100000000000ULL;
	value.max_memory_budget_bytes = 1ULL << 30;
	value.max_cost_micro = 1000000U;
	value.minimum_capability_confidence_ppm = 700000U;
	value.max_delegations = MAC_MAX_DELEGATIONS;
	value.require_explicit_authority = 1U;
	value.require_evidence_for_commit = 1U;
	return value;
}

static struct mac_agent agent(uint64_t id, uint8_t identity)
{
	struct mac_agent value;

	memset(&value, 0, sizeof(value));
	value.agent_id = id;
	value.agent_generation = 1U;
	value.capability_generation = 1U;
	value.trust_ppm = 900000U;
	fill_bytes(value.identity_digest, identity);
	return value;
}

static struct mac_delegation request(uint32_t flags)
{
	struct mac_delegation value;

	memset(&value, 0, sizeof(value));
	value.objective_id = 44U;
	value.parent_agent_id = 1U;
	value.target_agent_id = 2U;
	value.trace_id = 101U;
	value.parent_generation = 1U;
	value.target_generation = 1U;
	value.coordinator_generation = 9U;
	value.message_sequence = 1U;
	value.created_at_ns = 1000000000ULL;
	value.deadline_ns = 20000000000ULL;
	value.lease_until_ns = 10000000000ULL;
	value.cpu_budget_ns = 1000000U;
	value.memory_budget_bytes = 4096U;
	value.cost_budget_micro = 100U;
	value.required_capability_mask = 1ULL << 3;
	value.participant_count = 3U;
	value.quorum_required = 2U;
	value.evidence_required = 1U;
	value.flags = flags;
	value.participant_ids[0] = 1U;
	value.participant_ids[1] = 2U;
	value.participant_ids[2] = 3U;
	fill_bytes(value.objective_digest, 0x41U);
	fill_bytes(value.context_digest, 0x42U);
	(void)snprintf(value.message, sizeof(value.message), "delegate research verification");
	return value;
}

static struct mac_evidence evidence(uint64_t delegation_id, uint64_t agent_id)
{
	struct mac_evidence value;

	memset(&value, 0, sizeof(value));
	value.delegation_id = delegation_id;
	value.agent_id = agent_id;
	value.sequence = 1U;
	value.observed_at_ns = 1500000000ULL;
	value.kind = MAC_EVIDENCE_VERIFICATION;
	value.verified = 1U;
	fill_bytes(value.evidence_digest, 0x51U);
	fill_bytes(value.provenance_digest, 0x52U);
	(void)snprintf(value.detail, sizeof(value.detail), "verified source and capability state");
	return value;
}

static struct mac_vote vote(uint64_t delegation_id, uint64_t agent_id,
			    uint32_t decision)
{
	struct mac_vote value;

	memset(&value, 0, sizeof(value));
	value.delegation_id = delegation_id;
	value.agent_id = agent_id;
	value.agent_generation = 1U;
	value.vote_sequence = agent_id;
	value.coordinator_generation = 9U;
	value.decision = decision;
	value.evidence_count = 1U;
	fill_bytes(value.evidence_digest, 0x51U);
	fill_bytes(value.rationale_digest, (uint8_t)(0x60U + agent_id));
	return value;
}

int main(void)
{
	struct mac_service service;
	struct mac_policy limits = policy();
	struct mac_capability capability;
	struct mac_agent agent_one;
	struct mac_agent agent_two;
	struct mac_agent agent_three;
	struct mac_delegation model_request;
	struct mac_delegation authorized_request;
	struct mac_delegation challenge_request;
	struct mac_delegation stale_request;
	struct mac_receipt receipt;
	struct mac_receipt queried;
	struct mac_evidence ev;
	struct mac_vote v;
	uint64_t id;
	uint64_t model_id;
	uint64_t authorized_id;
	uint64_t challenge_id;
	int result;

	EXPECT_EQ("init", mac_init(&service, &limits), MAC_OK);
	agent_one = agent(1U, 0x11U);
	agent_two = agent(2U, 0x22U);
	agent_three = agent(3U, 0x33U);
	EXPECT_EQ("agent-1", mac_register_agent(&service, &agent_one, &id), MAC_OK);
	EXPECT_EQ("agent-2", mac_register_agent(&service, &agent_two, &id), MAC_OK);
	EXPECT_EQ("agent-3", mac_register_agent(&service, &agent_three, &id), MAC_OK);
	memset(&capability, 0, sizeof(capability));
	capability.owner_agent_id = 2U;
	capability.capability_generation = 1U;
	capability.capability_class = 3U;
	capability.confidence_ppm = 900000U;
	fill_bytes(capability.scope_digest, 0x31U);
	fill_bytes(capability.capability_digest, 0x32U);
	EXPECT_EQ("capability-register", mac_register_capability(&service, &capability, &id), MAC_OK);
	EXPECT_EQ("capability-negotiate", mac_negotiate_capability(&service, 2U, 1ULL << 3, 700000U), MAC_OK);
	EXPECT_EQ("capability-deny", mac_negotiate_capability(&service, 2U, 1ULL << 4, 700000U), MAC_ERR_CAPABILITY);

	model_request = request(MAC_FLAG_MODEL_PROPOSAL);
	EXPECT_EQ("model-admit", mac_admit_delegation(&service, &model_request, &receipt), MAC_OK);
	model_id = receipt.delegation_id;
	ev = evidence(model_id, 2U);
	EXPECT_EQ("model-evidence", mac_add_evidence(&service, model_id, &ev), MAC_OK);
	EXPECT_EQ("evidence-replay", mac_add_evidence(&service, model_id, &ev), MAC_ERR_REPLAY);
	v = vote(model_id, 2U, MAC_VOTE_APPROVE);
	EXPECT_EQ("model-vote-2", mac_vote(&service, model_id, &v, &receipt), MAC_OK);
	v = vote(model_id, 3U, MAC_VOTE_APPROVE);
	EXPECT_EQ("model-vote-3", mac_vote(&service, model_id, &v, &receipt), MAC_OK);
	EXPECT_EQ("model-authority-denied", mac_commit(&service, model_id, &receipt), MAC_ERR_AUTHORITY);

	authorized_request = request(MAC_FLAG_AUTHORITY_GRANTED);
	EXPECT_EQ("authorized-admit", mac_admit_delegation(&service, &authorized_request, &receipt), MAC_OK);
	authorized_id = receipt.delegation_id;
	ev = evidence(authorized_id, 2U);
	EXPECT_EQ("authorized-evidence", mac_add_evidence(&service, authorized_id, &ev), MAC_OK);
	v = vote(authorized_id, 2U, MAC_VOTE_APPROVE);
	EXPECT_EQ("authorized-vote-2", mac_vote(&service, authorized_id, &v, &receipt), MAC_OK);
	EXPECT_EQ("vote-replay", mac_vote(&service, authorized_id, &v, &receipt), MAC_ERR_REPLAY);
	v = vote(authorized_id, 3U, MAC_VOTE_APPROVE);
	EXPECT_EQ("authorized-vote-3", mac_vote(&service, authorized_id, &v, &receipt), MAC_OK);
	EXPECT_EQ("authorized-commit", mac_commit(&service, authorized_id, &receipt), MAC_OK);
	EXPECT_EQ("receipt-verify", mac_verify_receipt(&service, &receipt), MAC_OK);
	EXPECT_EQ("receipt-query", mac_query_receipt(&service, authorized_id, &queried), MAC_OK);
	EXPECT_EQ("receipt-query-verify", mac_verify_receipt(&service, &queried), MAC_OK);
	queried.receipt_digest[0] ^= 0xFFU;
	EXPECT_EQ("receipt-tamper", mac_verify_receipt(&service, &queried), MAC_ERR_TAMPER);

	challenge_request = request(MAC_FLAG_AUTHORITY_GRANTED | MAC_FLAG_MODEL_PROPOSAL);
	EXPECT_EQ("challenge-admit", mac_admit_delegation(&service, &challenge_request, &receipt), MAC_OK);
	challenge_id = receipt.delegation_id;
	v = vote(challenge_id, 2U, MAC_VOTE_CHALLENGE);
	v.evidence_count = 0U;
	EXPECT_EQ("challenge-vote", mac_vote(&service, challenge_id, &v, &receipt), MAC_OK);
	EXPECT_EQ("challenge-commit-denied", mac_commit(&service, challenge_id, &receipt), MAC_ERR_STATE);

	stale_request = request(MAC_FLAG_AUTHORITY_GRANTED);
	stale_request.target_generation = 2U;
	result = mac_admit_delegation(&service, &stale_request, &receipt);
	EXPECT_EQ("generation-fence", result, MAC_ERR_STALE);

	if (failures != 0) {
		printf("M236_SELFTEST_EXIT=1 failures=%d\n", failures);
		return 1;
	}
	printf("M236_SELFTEST_EXIT=0 cases=29\n");
	return 0;
}
