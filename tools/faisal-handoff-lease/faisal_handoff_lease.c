#include "faisal_handoff_lease.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FHL_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if ((!data && length) || !digest)
		return FHL_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FHL_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    (length && EVP_DigestUpdate(ctx, data, length) != 1) ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FHL_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FHL_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FHL_OK;
}

static int write_full(int fd, const void *data, size_t length)
{
	const uint8_t *cursor = data;
	size_t written = 0;

	while (written < length) {
		ssize_t count = write(fd, cursor + written, length - written);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return FHL_ERR_IO;
		}
		if (count == 0)
			return FHL_ERR_IO;
		written += (size_t)count;
	}
	return FHL_OK;
}

static int read_full(int fd, void *data, size_t length, size_t *read_bytes)
{
	uint8_t *cursor = data;
	size_t received = 0;

	while (received < length) {
		ssize_t count = read(fd, cursor + received, length - received);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return FHL_ERR_IO;
		}
		if (count == 0)
			break;
		received += (size_t)count;
	}
	if (read_bytes)
		*read_bytes = received;
	return FHL_OK;
}

static int digest_lease(const struct fhl_lease *lease,
			uint8_t digest[FHL_DIGEST_SIZE])
{
	struct fhl_lease copy;

	if (!lease || !digest)
		return FHL_ERR_ARGUMENT;
	copy = *lease;
	memset(copy.lease_digest, 0, sizeof(copy.lease_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int digest_record(const struct fhl_record *record,
			uint8_t digest[FHL_DIGEST_SIZE])
{
	struct fhl_record copy;

	if (!record || !digest)
		return FHL_ERR_ARGUMENT;
	copy = *record;
	memset(copy.record_digest, 0, sizeof(copy.record_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int digest_receipt(const struct fhl_receipt *receipt,
			  uint8_t digest[FHL_DIGEST_SIZE])
{
	struct fhl_receipt copy;

	if (!receipt || !digest)
		return FHL_ERR_ARGUMENT;
	copy = *receipt;
	memset(copy.receipt_digest, 0, sizeof(copy.receipt_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

int fhl_verify_lease(const struct fhl_lease *lease)
{
	uint8_t digest[FHL_DIGEST_SIZE];
	int rc;

	if (!lease || lease->lease_id == 0 || lease->objective_id == 0 ||
	    lease->task_id == 0 || lease->source_agent_id == 0 ||
	    lease->target_agent_id == 0 || lease->source_generation == 0 ||
	    lease->target_generation == 0 || lease->coordinator_generation == 0 ||
	    lease->issued_ns == 0 || lease->expires_ns <= lease->issued_ns ||
	    lease->nonce == 0 || lease->state < FHL_STATE_PROPOSED ||
	    lease->state > FHL_STATE_EXPIRED ||
	    (lease->flags & ~FHL_FLAGS_ALL) ||
	    (lease->required_capability_mask & ~lease->source_capability_mask) ||
	    (lease->required_capability_mask & ~lease->target_capability_mask))
		return FHL_ERR_ARGUMENT;
	rc = digest_lease(lease, digest);
	if (rc != FHL_OK)
		return rc;
	return memcmp(digest, lease->lease_digest, FHL_DIGEST_SIZE) == 0 ?
		FHL_OK : FHL_ERR_TAMPER;
}

int fhl_verify_receipt(const struct fhl_receipt *receipt)
{
	uint8_t digest[FHL_DIGEST_SIZE];
	int rc;

	if (!receipt || receipt->receipt_id == 0 || receipt->lease_id == 0 ||
	    receipt->objective_id == 0 || receipt->task_id == 0 ||
	    receipt->source_agent_id == 0 || receipt->target_agent_id == 0 ||
	    receipt->sequence == 0)
		return FHL_ERR_ARGUMENT;
	rc = digest_receipt(receipt, digest);
	if (rc != FHL_OK)
		return rc;
	return memcmp(digest, receipt->receipt_digest, FHL_DIGEST_SIZE) == 0 ?
		FHL_OK : FHL_ERR_TAMPER;
}

int fhl_verify_record(const struct fhl_record *record,
		const uint8_t previous_digest[FHL_DIGEST_SIZE])
{
	uint8_t digest[FHL_DIGEST_SIZE];
	int rc;

	if (!record || !previous_digest || record->magic != FHL_MAGIC ||
	    record->version != FHL_VERSION || record->sequence == 0 ||
	    record->kind < FHL_KIND_PROPOSE || record->kind > FHL_KIND_EXPIRE ||
	    memcmp(record->previous_digest, previous_digest, FHL_DIGEST_SIZE) != 0)
		return FHL_ERR_CORRUPT;
	rc = fhl_verify_lease(&record->lease);
	if (rc != FHL_OK)
		return rc;
	rc = digest_record(record, digest);
	if (rc != FHL_OK)
		return rc;
	return memcmp(digest, record->record_digest, FHL_DIGEST_SIZE) == 0 ?
		FHL_OK : FHL_ERR_TAMPER;
}

static int find_lease(const struct fhl_service *service, uint64_t lease_id)
{
	size_t i;

	if (!service)
		return -1;
	for (i = 0; i < service->count; i++)
		if (service->leases[i].lease_id == lease_id)
			return (int)i;
	return -1;
}

static int append_record(struct fhl_service *service, uint16_t kind,
			 const struct fhl_lease *lease)
{
	struct fhl_record record;
	uint8_t digest[FHL_DIGEST_SIZE];
	int rc;

	if (!service || service->journal_fd < 0 || !lease ||
	    service->next_sequence == UINT64_MAX)
		return FHL_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.magic = FHL_MAGIC;
	record.version = FHL_VERSION;
	record.kind = kind;
	record.sequence = service->next_sequence++;
	memcpy(record.previous_digest, service->chain_digest, FHL_DIGEST_SIZE);
	record.lease = *lease;
	rc = digest_record(&record, digest);
	if (rc != FHL_OK)
		return rc;
	memcpy(record.record_digest, digest, FHL_DIGEST_SIZE);
	if (write_full(service->journal_fd, &record, sizeof(record)) != FHL_OK ||
	    fsync(service->journal_fd) != 0)
		return FHL_ERR_IO;
	memcpy(service->chain_digest, record.record_digest, FHL_DIGEST_SIZE);
	service->journal_records++;
	return FHL_OK;
}

static int upsert_lease(struct fhl_service *service,
			const struct fhl_lease *lease)
{
	int index;

	if (!service || !lease)
		return FHL_ERR_ARGUMENT;
	index = find_lease(service, lease->lease_id);
	if (index >= 0) {
		service->leases[index] = *lease;
		return FHL_OK;
	}
	if (service->count >= FHL_MAX_LEASES)
		return FHL_ERR_FULL;
	service->leases[service->count++] = *lease;
	return FHL_OK;
}

int fhl_replay(struct fhl_service *service)
{
	struct fhl_record record;
	uint8_t chain[FHL_DIGEST_SIZE] = { 0 };
	size_t received;
	int rc;

	if (!service || service->journal_fd < 0)
		return FHL_ERR_ARGUMENT;
	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FHL_ERR_IO;
	service->count = 0;
	service->next_lease_id = 1;
	service->next_nonce = 1;
	service->next_sequence = 1;
	service->journal_records = 0;
	memset(service->chain_digest, 0, FHL_DIGEST_SIZE);
	for (;;) {
		rc = read_full(service->journal_fd, &record, sizeof(record), &received);
		if (rc != FHL_OK)
			return rc;
		if (received == 0)
			break;
		if (received != sizeof(record))
			return FHL_ERR_CORRUPT;
		rc = fhl_verify_record(&record, chain);
		if (rc != FHL_OK)
			return rc;
		if (upsert_lease(service, &record.lease) != FHL_OK)
			return FHL_ERR_FULL;
		memcpy(chain, record.record_digest, FHL_DIGEST_SIZE);
		memcpy(service->chain_digest, chain, FHL_DIGEST_SIZE);
		service->journal_records++;
		if (record.lease.lease_id >= service->next_lease_id)
			service->next_lease_id = record.lease.lease_id + 1U;
		if (record.lease.nonce >= service->next_nonce)
			service->next_nonce = record.lease.nonce + 1U;
		if (record.sequence >= service->next_sequence)
			service->next_sequence = record.sequence + 1U;
	}
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FHL_ERR_IO;
	return FHL_OK;
}

int fhl_open(struct fhl_service *service, const char *journal_path)
{
	if (!service || !journal_path || !journal_path[0] ||
	    strlen(journal_path) >= sizeof(service->journal_path))
		return FHL_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = -1;
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FHL_ERR_IO;
	memcpy(service->journal_path, journal_path, strlen(journal_path) + 1U);
	if (fhl_replay(service) != FHL_OK) {
		close(service->journal_fd);
		service->journal_fd = -1;
		return FHL_ERR_CORRUPT;
	}
	return FHL_OK;
}

void fhl_close(struct fhl_service *service)
{
	if (!service)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

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
		struct fhl_lease *out)
{
	struct fhl_lease lease;
	int rc;

	if (!service || !reason || !reason[0] || !out ||
	    objective_id == 0 || task_id == 0 || source_agent_id == 0 ||
	    source_generation == 0 || target_agent_id == 0 ||
	    target_generation == 0 || coordinator_generation == 0 ||
	    issued_ns == 0 || expires_ns <= issued_ns ||
	    (flags & ~FHL_FLAGS_ALL) ||
	    (required_capability_mask & ~source_capability_mask) ||
	    (required_capability_mask & ~target_capability_mask) ||
	    service->count >= FHL_MAX_LEASES || service->next_lease_id == UINT64_MAX ||
	    service->next_nonce == UINT64_MAX || strlen(reason) >= FHL_MAX_REASON)
		return FHL_ERR_ARGUMENT;
	if (require_approval > 1U)
		return FHL_ERR_POLICY;
	memset(&lease, 0, sizeof(lease));
	lease.lease_id = service->next_lease_id++;
	lease.objective_id = objective_id;
	lease.task_id = task_id;
	lease.source_agent_id = source_agent_id;
	lease.source_generation = source_generation;
	lease.source_capability_mask = source_capability_mask;
	lease.target_agent_id = target_agent_id;
	lease.target_generation = target_generation;
	lease.target_capability_mask = target_capability_mask;
	lease.coordinator_generation = coordinator_generation;
	lease.required_capability_mask = required_capability_mask;
	lease.issued_ns = issued_ns;
	lease.expires_ns = expires_ns;
	lease.nonce = service->next_nonce++;
	lease.state = require_approval ? FHL_STATE_PROPOSED : FHL_STATE_APPROVED;
	lease.require_approval = require_approval;
	lease.flags = flags;
	if (context_digest)
		memcpy(lease.context_digest, context_digest, FHL_DIGEST_SIZE);
	else
		memset(lease.context_digest, 0, FHL_DIGEST_SIZE);
	rc = digest_bytes(reason, strlen(reason), lease.reason_digest);
	if (rc != FHL_OK)
		return rc;
	rc = digest_lease(&lease, lease.lease_digest);
	if (rc != FHL_OK)
		return rc;
	rc = append_record(service, FHL_KIND_PROPOSE, &lease);
	if (rc != FHL_OK)
		return rc;
	if (upsert_lease(service, &lease) != FHL_OK)
		return FHL_ERR_FULL;
	*out = lease;
	return FHL_OK;
}

int fhl_approve(struct fhl_service *service, uint64_t lease_id,
		uint64_t approver_agent_id, uint64_t approver_generation,
		uint64_t now_ns, const uint8_t approval_digest[FHL_DIGEST_SIZE],
		struct fhl_lease *out)
{
	struct fhl_lease lease;
	int index;
	int rc;

	if (!service || !out || !approval_digest || approver_agent_id == 0 ||
	    approver_generation == 0 || now_ns == 0)
		return FHL_ERR_ARGUMENT;
	index = find_lease(service, lease_id);
	if (index < 0)
		return FHL_ERR_NOT_FOUND;
	lease = service->leases[index];
	if (lease.state != FHL_STATE_PROPOSED)
		return FHL_ERR_STATE;
	if (now_ns >= lease.expires_ns)
		return FHL_ERR_EXPIRED;
	lease.approval_agent_id = approver_agent_id;
	lease.approval_generation = approver_generation;
	lease.approved_ns = now_ns;
	lease.state = FHL_STATE_APPROVED;
	lease.flags |= FHL_FLAG_OPERATOR_APPROVAL;
	memcpy(lease.approval_digest, approval_digest, FHL_DIGEST_SIZE);
	rc = digest_lease(&lease, lease.lease_digest);
	if (rc != FHL_OK)
		return rc;
	rc = append_record(service, FHL_KIND_APPROVE, &lease);
	if (rc != FHL_OK)
		return rc;
	service->leases[index] = lease;
	*out = lease;
	return FHL_OK;
}

int fhl_consume(struct fhl_service *service, uint64_t lease_id,
		uint64_t target_agent_id, uint64_t target_generation,
		uint64_t target_capability_mask, uint64_t nonce, uint64_t now_ns,
		struct fhl_receipt *out)
{
	struct fhl_lease lease;
	struct fhl_receipt receipt;
	int index;
	int rc;

	if (!service || !out || lease_id == 0 || target_agent_id == 0 ||
	    target_generation == 0 || nonce == 0 || now_ns == 0)
		return FHL_ERR_ARGUMENT;
	index = find_lease(service, lease_id);
	if (index < 0)
		return FHL_ERR_NOT_FOUND;
	lease = service->leases[index];
	if (lease.state != FHL_STATE_APPROVED)
		return FHL_ERR_STATE;
	if (now_ns >= lease.expires_ns)
		return FHL_ERR_EXPIRED;
	if (lease.target_agent_id != target_agent_id ||
	    lease.target_generation != target_generation)
		return FHL_ERR_GENERATION;
	if ((lease.required_capability_mask & target_capability_mask) !=
	    lease.required_capability_mask)
		return FHL_ERR_CAPABILITY;
	if (lease.nonce != nonce)
		return FHL_ERR_REPLAY;
	lease.state = FHL_STATE_CONSUMED;
	rc = digest_lease(&lease, lease.lease_digest);
	if (rc != FHL_OK)
		return rc;
	rc = append_record(service, FHL_KIND_CONSUME, &lease);
	if (rc != FHL_OK)
		return rc;
	service->leases[index] = lease;
	memset(&receipt, 0, sizeof(receipt));
	receipt.receipt_id = service->next_sequence;
	receipt.lease_id = lease.lease_id;
	receipt.objective_id = lease.objective_id;
	receipt.task_id = lease.task_id;
	receipt.source_agent_id = lease.source_agent_id;
	receipt.target_agent_id = lease.target_agent_id;
	receipt.sequence = service->next_sequence;
	receipt.state = lease.state;
	receipt.status = FHL_OK;
	receipt.capability_mask = lease.required_capability_mask;
	memcpy(receipt.lease_digest, lease.lease_digest, FHL_DIGEST_SIZE);
	rc = digest_receipt(&receipt, receipt.receipt_digest);
	if (rc != FHL_OK)
		return rc;
	*out = receipt;
	return FHL_OK;
}

static int mark_state(struct fhl_service *service, uint64_t lease_id,
		      uint32_t state, uint16_t kind, struct fhl_lease *out)
{
	struct fhl_lease lease;
	int index;
	int rc;

	index = find_lease(service, lease_id);
	if (index < 0)
		return FHL_ERR_NOT_FOUND;
	lease = service->leases[index];
	lease.state = state;
	rc = digest_lease(&lease, lease.lease_digest);
	if (rc != FHL_OK)
		return rc;
	rc = append_record(service, kind, &lease);
	if (rc != FHL_OK)
		return rc;
	service->leases[index] = lease;
	if (out)
		*out = lease;
	return FHL_OK;
}

int fhl_revoke(struct fhl_service *service, uint64_t lease_id,
		uint64_t now_ns, struct fhl_lease *out)
{
	struct fhl_lease lease;
	int index;

	if (!service || !out || now_ns == 0)
		return FHL_ERR_ARGUMENT;
	index = find_lease(service, lease_id);
	if (index < 0)
		return FHL_ERR_NOT_FOUND;
	lease = service->leases[index];
	if (lease.state == FHL_STATE_CONSUMED || lease.state == FHL_STATE_REVOKED ||
	    lease.state == FHL_STATE_EXPIRED)
		return FHL_ERR_STATE;
	return mark_state(service, lease_id, FHL_STATE_REVOKED, FHL_KIND_REVOKE, out);
}

int fhl_expire(struct fhl_service *service, uint64_t now_ns,
		uint32_t *expired_count)
{
	uint32_t count = 0;
	size_t i;

	if (!service || !expired_count || now_ns == 0)
		return FHL_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++) {
		uint32_t state = service->leases[i].state;
		if ((state != FHL_STATE_PROPOSED && state != FHL_STATE_APPROVED) ||
		    service->leases[i].expires_ns > now_ns)
			continue;
		if (mark_state(service, service->leases[i].lease_id,
			       FHL_STATE_EXPIRED, FHL_KIND_EXPIRE, NULL) != FHL_OK)
			return FHL_ERR_IO;
		count++;
	}
	*expired_count = count;
	return FHL_OK;
}

int fhl_query(const struct fhl_service *service, uint64_t lease_id,
		struct fhl_lease *out)
{
	int index;

	if (!service || !out || lease_id == 0)
		return FHL_ERR_ARGUMENT;
	index = find_lease(service, lease_id);
	if (index < 0)
		return FHL_ERR_NOT_FOUND;
	*out = service->leases[index];
	return fhl_verify_lease(out);
}

int fhl_query_attestation(const struct fhl_service *service,
		struct fhl_attestation *out)
{
	size_t i;

	if (!service || !out)
		return FHL_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->next_lease_id = service->next_lease_id;
	out->next_nonce = service->next_nonce;
	out->next_sequence = service->next_sequence;
	out->journal_records = service->journal_records;
	memcpy(out->chain_digest, service->chain_digest, FHL_DIGEST_SIZE);
	for (i = 0; i < service->count; i++) {
		switch (service->leases[i].state) {
		case FHL_STATE_PROPOSED:
			out->proposed++;
			break;
		case FHL_STATE_APPROVED:
			out->approved++;
			break;
		case FHL_STATE_CONSUMED:
			out->consumed++;
			break;
		case FHL_STATE_REVOKED:
			out->revoked++;
			break;
		case FHL_STATE_EXPIRED:
			out->expired++;
			break;
		default:
			return FHL_ERR_CORRUPT;
		}
	}
	return FHL_OK;
}
