#include "../../faisal-handoff-lease/faisal_handoff_lease.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void fill_digest(uint8_t digest[FHL_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FHL_DIGEST_SIZE);
}

int main(void)
{
	const char *journal = "/tmp/faisal-handoff-lease-fuzz.journal";
	struct fhl_service service;
	struct fhl_lease lease;
	struct fhl_lease approved;
	struct fhl_receipt receipt;
	uint8_t context_digest[FHL_DIGEST_SIZE];
	uint8_t approval_digest[FHL_DIGEST_SIZE];
	uint32_t rejected = 0;
	uint32_t accepted = 0;
	uint32_t i;

	fill_digest(context_digest, 0x31U);
	fill_digest(approval_digest, 0x32U);
	unlink(journal);
	assert(fhl_open(&service, journal) == FHL_OK);
	for (i = 0; i < 10000U; i++) {
		int rc;
		uint64_t now = 100U + i;

		switch (i % 8U) {
		case 0U:
			rc = fhl_propose(&service, 0U, 2U, 10U, 1U, 0x1U,
					20U, 1U, 0x1U, 7U, 0x1U, now,
					now + 100U, 1U, 0U, "invalid", context_digest,
					&lease);
			assert(rc == FHL_ERR_ARGUMENT);
			rejected++;
			break;
		case 1U:
			rc = fhl_propose(&service, 1U, 2U, 10U, 1U, 0x1U,
					20U, 1U, 0x1U, 7U, 0x2U, now,
					now + 100U, 1U, 0U, "capability", context_digest,
					&lease);
			assert(rc == FHL_ERR_ARGUMENT);
			rejected++;
			break;
		case 2U:
			rc = fhl_propose(&service, 1U, 2U, 10U, 1U, 0x1U,
					20U, 1U, 0x1U, 7U, 0x1U, now,
					now, 1U, 0U, "expiry", context_digest, &lease);
			assert(rc == FHL_ERR_ARGUMENT);
			rejected++;
			break;
		case 3U:
			rc = fhl_propose(&service, 1U, 2U, 10U, 1U, 0x1U,
					20U, 1U, 0x1U, 7U, 0x1U, now,
					now + 100U, 2U, 0U, "policy", context_digest,
					&lease);
			assert(rc == FHL_ERR_POLICY);
			rejected++;
			break;
		case 4U:
			rc = fhl_propose(&service, 1U, 2U, 10U, 1U, 0x1U,
					20U, 1U, 0x1U, 7U, 0x1U, now,
					now + 100U, 1U, FHL_FLAGS_ALL | (1U << 7),
					"flags", context_digest, &lease);
			assert(rc == FHL_ERR_ARGUMENT);
			rejected++;
			break;
		case 5U:
			if (accepted < 64U) {
				rc = fhl_propose(&service, 100U + accepted,
						200U + accepted, 10U, 1U, 0x1U,
						20U, 1U, 0x1U, 7U, 0x1U,
						now, now + 100000U, 1U, 0U,
						"valid", context_digest, &lease);
				assert(rc == FHL_OK);
				assert(fhl_approve(&service, lease.lease_id, 99U, 1U,
						now + 1U, approval_digest, &approved) == FHL_OK);
				assert(fhl_consume(&service, approved.lease_id, 20U, 1U,
						0x1U, approved.nonce, now + 2U,
						&receipt) == FHL_OK);
				accepted++;
			} else {
				rc = fhl_consume(&service, 0U, 20U, 1U, 0x1U, 1U,
						now, &receipt);
				assert(rc == FHL_ERR_ARGUMENT);
				rejected++;
			}
			break;
		case 6U:
			rc = fhl_consume(&service, UINT64_MAX, 20U, 1U, 0x1U, 1U,
					now, &receipt);
			assert(rc == FHL_ERR_NOT_FOUND);
			rejected++;
			break;
		default:
			rc = fhl_approve(&service, UINT64_MAX, 99U, 1U, now,
					approval_digest, &approved);
			assert(rc == FHL_ERR_NOT_FOUND);
			rejected++;
			break;
		}
	}
	fhl_close(&service);
	unlink(journal);
	printf("FHL_HANDOFF_LEASE_FUZZ_OK iterations=10000 rejected=%u accepted=%u\n",
	       rejected, accepted);
	return 0;
}
