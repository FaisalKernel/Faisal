#include "../../faisal-handoff-lease/faisal_handoff_lease.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;

	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void fill_digest(uint8_t digest[FHL_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value, FHL_DIGEST_SIZE);
}

int main(void)
{
	const char *journal = "/tmp/faisal-handoff-lease-benchmark.journal";
	struct fhl_service service;
	struct fhl_lease lease;
	struct fhl_receipt receipt;
	uint8_t context_digest[FHL_DIGEST_SIZE];
	uint8_t approval_digest[FHL_DIGEST_SIZE];
	const uint64_t rounds = 100U;
	uint64_t start;
	uint64_t elapsed;
	uint64_t i;

	fill_digest(context_digest, 0x41U);
	fill_digest(approval_digest, 0x42U);
	unlink(journal);
	assert(fhl_open(&service, journal) == FHL_OK);
	start = now_ns();
	for (i = 0; i < rounds; i++) {
		uint64_t base = 1000U + i * 10U;
		assert(fhl_propose(&service, 100U + i, 200U + i,
				   1U, 1U, 0x3U, 2U, 1U, 0x3U,
				   9U, 0x1U, base, base + 100000U,
				   1U, FHL_FLAG_VERIFIED_CONTEXT,
				   "benchmark handoff", context_digest, &lease) == FHL_OK);
		assert(fhl_approve(&service, lease.lease_id, 99U, 1U,
				   base + 1U, approval_digest, &lease) == FHL_OK);
		assert(fhl_consume(&service, lease.lease_id, 2U, 1U, 0x3U,
				   lease.nonce, base + 2U, &receipt) == FHL_OK);
		assert(fhl_verify_receipt(&receipt) == FHL_OK);
	}
	elapsed = now_ns() - start;
	printf("FHL_HANDOFF_LEASE_BENCHMARK_OK rounds=%" PRIu64
	       " transitions=%" PRIu64 " elapsed_ns=%" PRIu64
	       " ns_per_transition=%.2f durability=fsync_per_transition\n",
	       rounds, rounds * 3U, elapsed,
	       (double)elapsed / (double)(rounds * 3U));
	fhl_close(&service);
	unlink(journal);
	return 0;
}
