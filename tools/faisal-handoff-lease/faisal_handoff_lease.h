#ifndef FAISAL_HANDOFF_LEASE_H
#define FAISAL_HANDOFF_LEASE_H

#include <stddef.h>
#include <stdint.h>

#define FHL_ABI_VERSION 1U
#define FHL_DIGEST_SIZE 32U
#define FHL_MAX_LEASES 128U
#define FHL_MAX_REASON 192U
#define FHL_MAX_JOURNAL_PATH 4096U
#define FHL_MAGIC 0x46484c31U
#define FHL_VERSION 1U
#define FHL_KIND_PROPOSE 1U
#define FHL_KIND_APPROVE 2U
#define FHL_KIND_CONSUME 3U
#define FHL_KIND_REVOKE 4U
#define FHL_KIND_EXPIRE 5U
#define FHL_STATE_PROPOSED 1U
#define FHL_STATE_APPROVED 2U
#define FHL_STATE_CONSUMED 3U
#define FHL_STATE_REVOKED 4U
#define FHL_STATE_EXPIRED 5U
#define FHL_FLAG_MODEL_PROPOSAL (1U << 0)
#define FHL_FLAG_VERIFIED_CONTEXT (1U << 1)
#define FHL_FLAG_OPERATOR_APPROVAL (1U << 2)
#define FHL_FLAGS_ALL (FHL_FLAG_MODEL_PROPOSAL | FHL_FLAG_VERIFIED_CONTEXT | FHL_FLAG_OPERATOR_APPROVAL)

enum fhl_status {
	FHL_OK = 0,
	FHL_ERR_ARGUMENT = -1,
	FHL_ERR_IO = -2,
	FHL_ERR_CORRUPT = -3,
	FHL_ERR_FULL = -4,
	FHL_ERR_NOT_FOUND = -5,
	FHL_ERR_STATE = -6,
	FHL_ERR_CAPABILITY = -7,
	FHL_ERR_GENERATION = -8,
	FHL_ERR_EXPIRED = -9,
	FHL_ERR_REPLAY = -10,
	FHL_ERR_TAMPER = -11,
	FHL_ERR_POLICY = -12
};

struct fhl_lease {
	uint64_t lease_id;
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t source_agent_id;
	uint64_t source_generation;
	uint64_t target_agent_id;
	uint64_t target_generation;
	uint64_t coordinator_generation;
	uint64_t required_capability_mask;
	uint64_t source_capability_mask;
	uint64_t target_capability_mask;
	uint64_t issued_ns;
	uint64_t expires_ns;
	uint64_t nonce;
	uint64_t approval_agent_id;
	uint64_t approval_generation;
	uint64_t approved_ns;
	uint32_t state;
	uint32_t require_approval;
	uint32_t flags;
	uint32_t reserved;
	uint8_t reason_digest[FHL_DIGEST_SIZE];
	uint8_t context_digest[FHL_DIGEST_SIZE];
	uint8_t approval_digest[FHL_DIGEST_SIZE];
	uint8_t lease_digest[FHL_DIGEST_SIZE];
};

struct fhl_receipt {
	uint64_t receipt_id;
	uint64_t lease_id;
	uint64_t objective_id;
	uint64_t task_id;
	uint64_t source_agent_id;
	uint64_t target_agent_id;
	uint64_t sequence;
	uint32_t state;
	int32_t status;
	uint64_t capability_mask;
	uint8_t lease_digest[FHL_DIGEST_SIZE];
	uint8_t receipt_digest[FHL_DIGEST_SIZE];
};

struct fhl_record {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint64_t sequence;
	uint8_t previous_digest[FHL_DIGEST_SIZE];
	struct fhl_lease lease;
	uint8_t record_digest[FHL_DIGEST_SIZE];
};

struct fhl_attestation {
	uint64_t next_lease_id;
	uint64_t next_nonce;
	uint64_t next_sequence;
	uint64_t journal_records;
	uint64_t proposed;
	uint64_t approved;
	uint64_t consumed;
	uint64_t revoked;
	uint64_t expired;
	uint8_t chain_digest[FHL_DIGEST_SIZE];
};

struct fhl_service {
	int journal_fd;
	char journal_path[FHL_MAX_JOURNAL_PATH];
	struct fhl_lease leases[FHL_MAX_LEASES];
	size_t count;
	uint64_t next_lease_id;
	uint64_t next_nonce;
	uint64_t next_sequence;
	uint64_t journal_records;
	uint8_t chain_digest[FHL_DIGEST_SIZE];
};

int fhl_open(struct fhl_service *service, const char *journal_path);
void fhl_close(struct fhl_service *service);
int fhl_replay(struct fhl_service *service);
int fhl_propose(struct fhl_service *service,
		uint64_t objective_id, uint64_t task_id,
		uint64_t source_agent_id, uint64_t source_generation,
		uint64_t source_capability_mask,
		uint64_t target_agent_id, uint64_t target_generation,
		uint64_t target_capability_mask,
		uint64_t coordinator_generation,
		uint64_t required_capability_mask,
		uint64_t issued_ns, uint64_t expires_ns,
		uint32_t require_approval, uint32_t flags,
		const char *reason, const uint8_t context_digest[FHL_DIGEST_SIZE],
		struct fhl_lease *out);
int fhl_approve(struct fhl_service *service, uint64_t lease_id,
		uint64_t approver_agent_id, uint64_t approver_generation,
		uint64_t now_ns, const uint8_t approval_digest[FHL_DIGEST_SIZE],
		struct fhl_lease *out);
int fhl_consume(struct fhl_service *service, uint64_t lease_id,
		uint64_t target_agent_id, uint64_t target_generation,
		uint64_t target_capability_mask, uint64_t nonce, uint64_t now_ns,
		struct fhl_receipt *out);
int fhl_revoke(struct fhl_service *service, uint64_t lease_id,
		uint64_t now_ns, struct fhl_lease *out);
int fhl_expire(struct fhl_service *service, uint64_t now_ns,
		uint32_t *expired_count);
int fhl_query(const struct fhl_service *service, uint64_t lease_id,
		struct fhl_lease *out);
int fhl_verify_lease(const struct fhl_lease *lease);
int fhl_verify_record(const struct fhl_record *record,
		const uint8_t previous_digest[FHL_DIGEST_SIZE]);
int fhl_verify_receipt(const struct fhl_receipt *receipt);
int fhl_query_attestation(const struct fhl_service *service,
		struct fhl_attestation *out);

#endif
