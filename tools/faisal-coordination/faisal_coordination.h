#ifndef FAISAL_COORDINATION_H
#define FAISAL_COORDINATION_H

#include <stddef.h>
#include <stdint.h>

#define MAC_DIGEST_SIZE 32U
#define MAC_MAX_AGENTS 32U
#define MAC_MAX_CAPABILITIES 64U
#define MAC_MAX_DELEGATIONS 128U
#define MAC_MAX_EVIDENCE 8U
#define MAC_MAX_RECEIPTS 256U
#define MAC_MAX_MESSAGE 256U
#define MAC_MAX_DETAIL 128U
#define MAC_MAX_PARTICIPANTS 32U
#define MAC_PPM_SCALE 1000000U

#define MAC_FLAG_MODEL_PROPOSAL (1U << 0)
#define MAC_FLAG_DELEGATED (1U << 1)
#define MAC_FLAG_REQUIRES_EVIDENCE (1U << 2)
#define MAC_FLAG_REQUIRES_CHALLENGE_WINDOW (1U << 3)
#define MAC_FLAG_AUTHORITY_GRANTED (1U << 4)
#define MAC_FLAG_OPERATOR_CONFIRMED (1U << 5)
#define MAC_FLAG_RESOURCE_RESERVED (1U << 6)

#define MAC_VOTE_APPROVE 1U
#define MAC_VOTE_REJECT 2U
#define MAC_VOTE_CHALLENGE 3U

#define MAC_EVIDENCE_OBSERVATION 1U
#define MAC_EVIDENCE_RESULT 2U
#define MAC_EVIDENCE_VERIFICATION 3U
#define MAC_EVIDENCE_PROVENANCE 4U
#define MAC_EVIDENCE_RESOURCE 5U

#define MAC_DECISION_DENIED 0U
#define MAC_DECISION_ADMITTED 1U
#define MAC_DECISION_VOTING 2U
#define MAC_DECISION_COMMITTED 3U
#define MAC_DECISION_REJECTED 4U
#define MAC_DECISION_CHALLENGED 5U
#define MAC_DECISION_TAMPERED 6U

#define MAC_DEFAULT_LEASE_NS (30ULL * 1000000000ULL)
#define MAC_MAX_LEASE_NS (7ULL * 24ULL * 60ULL * 60ULL * 1000000000ULL)

enum mac_status {
	MAC_OK = 0,
	MAC_ERR_ARGUMENT = -1,
	MAC_ERR_FULL = -2,
	MAC_ERR_DUPLICATE = -3,
	MAC_ERR_NOT_FOUND = -4,
	MAC_ERR_STALE = -5,
	MAC_ERR_REPLAY = -6,
	MAC_ERR_POLICY = -7,
	MAC_ERR_CAPABILITY = -8,
	MAC_ERR_QUORUM = -9,
	MAC_ERR_CONFLICT = -10,
	MAC_ERR_TAMPER = -11,
	MAC_ERR_AUTHORITY = -12,
	MAC_ERR_DEADLINE = -13,
	MAC_ERR_BUDGET = -14,
	MAC_ERR_STATE = -15
};

struct mac_policy {
	uint64_t coordinator_generation;
	uint64_t current_time_ns;
	uint64_t max_lease_ns;
	uint64_t max_cpu_budget_ns;
	uint64_t max_memory_budget_bytes;
	uint64_t max_cost_micro;
	uint32_t minimum_capability_confidence_ppm;
	uint32_t max_delegations;
	uint32_t require_explicit_authority;
	uint32_t require_evidence_for_commit;
	uint32_t reserved;
};

struct mac_agent {
	uint64_t agent_id;
	uint64_t agent_generation;
	uint64_t capability_generation;
	uint64_t last_message_sequence;
	uint64_t capability_mask;
	uint32_t active;
	uint32_t trust_ppm;
	uint32_t flags;
	uint32_t reserved;
	uint8_t identity_digest[MAC_DIGEST_SIZE];
};

struct mac_capability {
	uint64_t capability_id;
	uint64_t owner_agent_id;
	uint64_t capability_generation;
	uint32_t capability_class;
	uint32_t confidence_ppm;
	uint32_t active;
	uint32_t reserved;
	uint64_t scope_id;
	uint8_t scope_digest[MAC_DIGEST_SIZE];
	uint8_t capability_digest[MAC_DIGEST_SIZE];
};

struct mac_delegation {
	uint64_t delegation_id;
	uint64_t objective_id;
	uint64_t parent_agent_id;
	uint64_t target_agent_id;
	uint64_t trace_id;
	uint64_t parent_generation;
	uint64_t target_generation;
	uint64_t coordinator_generation;
	uint64_t message_sequence;
	uint64_t created_at_ns;
	uint64_t deadline_ns;
	uint64_t lease_until_ns;
	uint64_t cpu_budget_ns;
	uint64_t memory_budget_bytes;
	uint64_t cost_budget_micro;
	uint64_t required_capability_mask;
	uint32_t participant_count;
	uint32_t quorum_required;
	uint32_t evidence_required;
	uint32_t flags;
	uint64_t participant_ids[MAC_MAX_PARTICIPANTS];
	uint8_t objective_digest[MAC_DIGEST_SIZE];
	uint8_t context_digest[MAC_DIGEST_SIZE];
	char message[MAC_MAX_MESSAGE];
};

struct mac_evidence {
	uint64_t delegation_id;
	uint64_t agent_id;
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint32_t kind;
	uint32_t verified;
	uint32_t reserved0;
	uint32_t reserved1;
	uint8_t evidence_digest[MAC_DIGEST_SIZE];
	uint8_t provenance_digest[MAC_DIGEST_SIZE];
	char detail[MAC_MAX_DETAIL];
};

struct mac_vote {
	uint64_t delegation_id;
	uint64_t agent_id;
	uint64_t agent_generation;
	uint64_t vote_sequence;
	uint64_t coordinator_generation;
	uint32_t decision;
	uint32_t evidence_count;
	uint32_t challenge_reason;
	uint32_t reserved;
	uint8_t evidence_digest[MAC_DIGEST_SIZE];
	uint8_t rationale_digest[MAC_DIGEST_SIZE];
};

struct mac_receipt {
	uint64_t receipt_id;
	uint64_t delegation_id;
	uint64_t objective_id;
	uint64_t coordinator_generation;
	uint64_t receipt_sequence;
	uint32_t decision;
	int32_t status;
	uint32_t approvals;
	uint32_t rejections;
	uint32_t challenges;
	uint32_t evidence_count;
	uint8_t delegation_digest[MAC_DIGEST_SIZE];
	uint8_t votes_digest[MAC_DIGEST_SIZE];
	uint8_t receipt_digest[MAC_DIGEST_SIZE];
};

struct mac_delegation_state {
	struct mac_delegation request;
	uint8_t request_digest[MAC_DIGEST_SIZE];
	uint32_t decision;
	int32_t status;
	uint32_t vote_count;
	uint32_t approval_count;
	uint32_t rejection_count;
	uint32_t challenge_count;
	uint32_t evidence_count;
	uint32_t reserved;
	struct mac_vote votes[MAC_MAX_PARTICIPANTS];
	struct mac_evidence evidence[MAC_MAX_EVIDENCE];
	struct mac_receipt receipt;
};

struct mac_service {
	struct mac_policy policy;
	struct mac_agent agents[MAC_MAX_AGENTS];
	struct mac_capability capabilities[MAC_MAX_CAPABILITIES];
	struct mac_delegation_state delegations[MAC_MAX_DELEGATIONS];
	struct mac_receipt receipts[MAC_MAX_RECEIPTS];
	size_t agent_count;
	size_t capability_count;
	size_t delegation_count;
	size_t receipt_count;
	uint64_t next_agent_id;
	uint64_t next_capability_id;
	uint64_t next_delegation_id;
	uint64_t next_receipt_id;
};

int mac_init(struct mac_service *service, const struct mac_policy *policy);
int mac_register_agent(struct mac_service *service,
		       const struct mac_agent *agent,
		       uint64_t *out_agent_id);
int mac_register_capability(struct mac_service *service,
			    const struct mac_capability *capability,
			    uint64_t *out_capability_id);
int mac_negotiate_capability(const struct mac_service *service,
			     uint64_t agent_id,
			     uint64_t required_capability_mask,
			     uint32_t minimum_confidence_ppm);
int mac_admit_delegation(struct mac_service *service,
			 const struct mac_delegation *request,
			 struct mac_receipt *out);
int mac_add_evidence(struct mac_service *service,
			    uint64_t delegation_id,
			    const struct mac_evidence *evidence);
int mac_vote(struct mac_service *service,
		     uint64_t delegation_id,
		     const struct mac_vote *vote,
		     struct mac_receipt *out);
int mac_commit(struct mac_service *service,
		       uint64_t delegation_id,
		       struct mac_receipt *out);
int mac_verify_receipt(const struct mac_service *service,
			       const struct mac_receipt *receipt);
int mac_query_receipt(const struct mac_service *service,
			      uint64_t delegation_id,
			      struct mac_receipt *out);
int mac_authority_check(const struct mac_delegation *request);

#endif
