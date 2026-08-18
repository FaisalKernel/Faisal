#include "../../faisal-handoff-lease/faisal_handoff_lease.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void digest_fill(uint8_t digest[FHL_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FHL_DIGEST_SIZE);
}

int main(void)
{
	const char *journal = "/tmp/faisal-handoff-lease-selftest.journal";
	const char *corrupt_journal = "/tmp/faisal-handoff-lease-corrupt.journal";
	struct fhl_service service;
	struct fhl_lease lease;
	struct fhl_lease approved;
	struct fhl_lease queried;
	struct fhl_lease revoked;
	struct fhl_receipt receipt;
	struct fhl_attestation attestation;
	uint8_t context_digest[FHL_DIGEST_SIZE];
	uint8_t approval_digest[FHL_DIGEST_SIZE];
	uint32_t expired;
	int fd;

	digest_fill(context_digest, 0x11U);
	digest_fill(approval_digest, 0x22U);
	unlink(journal);
	unlink(corrupt_journal);
	assert(fhl_open(&service, journal) == FHL_OK);
	assert(fhl_propose(&service, 1U, 2U, 10U, 1U, 0x3U, 20U, 1U, 0x3U,
			   7U, 0x1U, 100U, 1000U, 1U,
			   FHL_FLAG_MODEL_PROPOSAL | FHL_FLAG_VERIFIED_CONTEXT,
			   "delegate research", context_digest, &lease) == FHL_OK);
	assert(lease.state == FHL_STATE_PROPOSED);
	assert(fhl_verify_lease(&lease) == FHL_OK);
	assert(fhl_consume(&service, lease.lease_id, 20U, 1U, 0x3U,
			  lease.nonce, 200U, &receipt) == FHL_ERR_STATE);
	assert(fhl_approve(&service, lease.lease_id, 99U, 4U, 250U,
			  approval_digest, &approved) == FHL_OK);
	assert(approved.state == FHL_STATE_APPROVED);
	assert(fhl_verify_lease(&approved) == FHL_OK);
	assert(fhl_consume(&service, approved.lease_id, 20U, 1U, 0x3U,
			  approved.nonce + 1U, 300U, &receipt) == FHL_ERR_REPLAY);
	assert(fhl_consume(&service, approved.lease_id, 20U, 2U, 0x3U,
			  approved.nonce, 300U, &receipt) == FHL_ERR_GENERATION);
	assert(fhl_consume(&service, approved.lease_id, 20U, 1U, 0x2U,
			  approved.nonce, 300U, &receipt) == FHL_ERR_CAPABILITY);
	assert(fhl_consume(&service, approved.lease_id, 20U, 1U, 0x3U,
			  approved.nonce, 300U, &receipt) == FHL_OK);
	assert(receipt.state == FHL_STATE_CONSUMED);
	assert(fhl_verify_receipt(&receipt) == FHL_OK);
	assert(fhl_consume(&service, approved.lease_id, 20U, 1U, 0x3U,
			  approved.nonce, 301U, &receipt) == FHL_ERR_STATE);
	assert(fhl_query(&service, approved.lease_id, &queried) == FHL_OK);
	assert(queried.state == FHL_STATE_CONSUMED);
	assert(fhl_propose(&service, 1U, 3U, 10U, 1U, 0x1U, 30U, 1U, 0x1U,
			   7U, 0x1U, 400U, 500U, 1U, 0U, "expire me",
			   context_digest, &lease) == FHL_OK);
	assert(fhl_expire(&service, 600U, &expired) == FHL_OK);
	assert(expired == 1U);
	assert(fhl_approve(&service, lease.lease_id, 99U, 4U, 601U,
			  approval_digest, &approved) == FHL_ERR_STATE);
	assert(fhl_propose(&service, 1U, 4U, 10U, 1U, 0x1U, 40U, 1U, 0x1U,
			   7U, 0x1U, 700U, 1500U, 1U, 0U, "revoke me",
			   context_digest, &lease) == FHL_OK);
	assert(fhl_revoke(&service, lease.lease_id, 800U, &revoked) == FHL_OK);
	assert(revoked.state == FHL_STATE_REVOKED);
	assert(fhl_revoke(&service, revoked.lease_id, 801U, &revoked) == FHL_ERR_STATE);
	assert(fhl_propose(&service, 1U, 5U, 10U, 1U, 0x1U, 50U, 1U, 0x1U,
			   7U, 0x1U, 900U, 1500U, 0U, 0U, "direct consume",
			   context_digest, &lease) == FHL_OK);
	assert(lease.state == FHL_STATE_APPROVED);
	assert(fhl_consume(&service, lease.lease_id, 50U, 1U, 0x1U,
			  lease.nonce, 901U, &receipt) == FHL_OK);
	assert(fhl_query_attestation(&service, &attestation) == FHL_OK);
	assert(attestation.consumed == 2U);
	assert(attestation.expired == 1U);
	assert(attestation.revoked == 1U);
	fhl_close(&service);
	assert(fhl_open(&service, journal) == FHL_OK);
	assert(fhl_query_attestation(&service, &attestation) == FHL_OK);
	assert(attestation.consumed == 2U && attestation.expired == 1U &&
	       attestation.revoked == 1U);
	fhl_close(&service);
	assert(fhl_open(&service, corrupt_journal) == FHL_OK);
	assert(fhl_propose(&service, 2U, 2U, 11U, 1U, 0x1U, 21U, 1U, 0x1U,
			   8U, 0x1U, 100U, 1000U, 1U, 0U, "corrupt",
			   context_digest, &lease) == FHL_OK);
	fhl_close(&service);
	fd = open(corrupt_journal, O_RDWR);
	assert(fd >= 0);
	assert(lseek(fd, -1, SEEK_END) >= 0);
	assert(write(fd, "X", 1U) == 1);
	close(fd);
	assert(fhl_open(&service, corrupt_journal) == FHL_ERR_CORRUPT);
	unlink(journal);
	unlink(corrupt_journal);
	printf("FHL_HANDOFF_LEASE_SELFTEST_OK cases=31 consumed=2 expired=1 revoked=1 replay=verified\n");
	return 0;
}
