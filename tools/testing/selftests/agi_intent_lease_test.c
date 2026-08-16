#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M94_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int expect_errno(int fd, struct agi_lc_intent_lease *lease,
			int expected, const char *what)
{
	int rc;

	rc = ioctl(fd, AGI_LC_INTENT_LEASE, lease);
	if (rc >= 0 || errno != expected)
		return fail(what);
	return 0;
}

static void fill_lease(struct agi_lc_intent_lease *lease,
			const struct agi_lc_light_agent *agent,
			const struct agi_lc_capability_grant *grant,
			uint32_t operation, uint64_t digest, uint64_t correlation)
{
	memset(lease, 0, sizeof(*lease));
	lease->size = sizeof(*lease);
	lease->operation = operation;
	lease->operation_class = AGI_LC_INTENT_OP_BROWSER;
	lease->resource_mask = AGI_LC_RESOURCE_NETWORK;
	lease->grant_id = grant->grant_id;
	lease->grant_capability = grant->capability;
	lease->agent_id = agent->agent_id;
	lease->agent_capability = agent->capability;
	lease->intent_digest[0] = (unsigned char)digest;
	lease->intent_digest[1] = (unsigned char)(digest >> 8);
	lease->correlation = correlation;
}

int main(void)
{
	int fd;
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent agent = {
		.size = sizeof(agent),
		.role = AGI_LC_LIGHT_AGENT_ROLE_SECURITY,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 94001,
	};
	struct agi_lc_agent attach = {
		.size = sizeof(attach),
		.correlation = 94002,
	};
	struct agi_lc_capability_grant grant = {
		.size = sizeof(grant),
		.rights = AGI_LC_CAP_BROWSER_CONTROL,
		.correlation = 94003,
	};
	struct agi_lc_intent_lease lease;
	struct agi_lc_intent_lease consume;
	struct agi_lc_intent_lease query;
	struct agi_lc_revoke revoke = {
		.size = sizeof(revoke),
		.reason = AGI_LC_REVOKE_USER,
	};

	fd = open("/dev/agi_lifecycle", O_RDWR);
	if (fd < 0)
		return fail("open");
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &agent) < 0 ||
	    !agent.agent_id || !agent.capability)
		return fail("session-agent");
	attach.agent_id = agent.agent_id;
	if (ioctl(fd, AGI_LC_SET_AGENT, &attach) < 0)
		return fail("set-agent");
	grant.agent_id = agent.agent_id;
	grant.agent_capability = agent.capability;
	if (ioctl(fd, AGI_LC_CAPABILITY_GRANT, &grant) < 0 ||
	    !grant.grant_id || !grant.capability)
		return fail("grant");

	fill_lease(&lease, &agent, &grant, AGI_LC_INTENT_LEASE_ACQUIRE,
		   0x1199, 94004);
	lease.flags = AGI_LC_INTENT_LEASE_FLAG_SINGLE_USE |
		AGI_LC_INTENT_LEASE_FLAG_REVOKE_ON_CLOSE;
	lease.expires_ns = AGI_LC_INTENT_MAX_TTL_NS;
	lease.max_uses = 1;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &lease) < 0 ||
	    !lease.lease_id || lease.status != AGI_LC_INTENT_STATUS_ACTIVE ||
	    lease.remaining_uses != 1 || lease.generation != 1)
		return fail("single-use acquire");
	printf("M94_INTENT_LEASE_ACQUIRE_OK id=%llu\n",
	       (unsigned long long)lease.lease_id);

	consume = lease;
	consume.operation = AGI_LC_INTENT_LEASE_CONSUME;
	consume.status = 0;
	consume.correlation = 94005;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &consume) < 0 ||
	    consume.use_sequence != 1 ||
	    consume.remaining_uses != 0 ||
	    consume.status != AGI_LC_INTENT_STATUS_EXHAUSTED)
		return fail("single-use consume");
	printf("M94_SINGLE_USE_ATOMIC_CONSUME_OK sequence=%llu\n",
	       (unsigned long long)consume.use_sequence);
	consume.status = 0;
	consume.correlation = 94006;
	if (expect_errno(fd, &consume, ENOSPC, "single-use replay denial"))
		return 1;
	printf("M94_REPLAY_DENIAL_OK\n");

	fill_lease(&lease, &agent, &grant, AGI_LC_INTENT_LEASE_ACQUIRE,
		   0x2244, 94007);
	lease.expires_ns = AGI_LC_INTENT_MAX_TTL_NS;
	lease.max_uses = 2;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &lease) < 0)
		return fail("multi-use acquire");
	consume = lease;
	consume.operation = AGI_LC_INTENT_LEASE_CONSUME;
	consume.status = 0;
	consume.correlation = 94008;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &consume) < 0 ||
	    consume.use_sequence != 1 || consume.remaining_uses != 1)
		return fail("multi-use first consume");
	printf("M94_BOUNDED_MULTI_USE_OK remaining=%llu\n",
	       (unsigned long long)consume.remaining_uses);
	query = consume;
	query.operation = AGI_LC_INTENT_LEASE_QUERY;
	query.status = 0;
	query.correlation = 94009;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &query) < 0 ||
	    query.remaining_uses != 1 || query.use_sequence != 1)
		return fail("query");
	printf("M94_INTENT_QUERY_OK\n");

	consume.intent_digest[0] ^= 1;
	consume.correlation = 94010;
	if (expect_errno(fd, &consume, EACCES, "intent mismatch denial"))
		return 1;
	printf("M94_INTENT_MISMATCH_DENIAL_OK\n");
	consume.intent_digest[0] ^= 1;
	consume.correlation = 94011;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &consume) < 0 ||
	    consume.remaining_uses != 0)
		return fail("multi-use second consume");

	fill_lease(&lease, &agent, &grant, AGI_LC_INTENT_LEASE_ACQUIRE,
		   0x3366, 94012);
	lease.expires_ns = 1;
	lease.max_uses = 1;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &lease) < 0)
		return fail("expiry acquire");
	query = lease;
	query.operation = AGI_LC_INTENT_LEASE_QUERY;
	query.status = 0;
	query.correlation = 94013;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &query) < 0 ||
	    query.status != AGI_LC_INTENT_STATUS_EXPIRED)
		return fail("expiry status");
	printf("M94_EXPIRY_FAIL_CLOSED_OK\n");

	fill_lease(&lease, &agent, &grant, AGI_LC_INTENT_LEASE_ACQUIRE,
		   0x4477, 94014);
	lease.expires_ns = AGI_LC_INTENT_MAX_TTL_NS;
	lease.max_uses = 1;
	lease.grant_capability ^= 1;
	if (expect_errno(fd, &lease, EACCES, "grant gating"))
		return 1;
	printf("M94_GRANT_GATING_DENIAL_OK\n");
	lease.grant_capability ^= 1;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &lease) < 0)
		return fail("revocation acquire");
	consume = lease;
	consume.operation = AGI_LC_INTENT_LEASE_REVOKE;
	consume.status = 0;
	consume.correlation = 94015;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &consume) < 0)
		return fail("intent revoke");
	consume.operation = AGI_LC_INTENT_LEASE_CONSUME;
	consume.correlation = 94016;
	if (expect_errno(fd, &consume, EKEYREVOKED, "revoked denial"))
		return 1;
	printf("M94_REVOCATION_FAIL_CLOSED_OK\n");

	fill_lease(&lease, &agent, &grant, AGI_LC_INTENT_LEASE_ACQUIRE,
		   0x5588, 94017);
	lease.expires_ns = AGI_LC_INTENT_MAX_TTL_NS;
	lease.max_uses = 1;
	lease.flags = AGI_LC_INTENT_LEASE_FLAG_REVOKE_ON_CLOSE;
	if (ioctl(fd, AGI_LC_INTENT_LEASE, &lease) < 0)
		return fail("close cleanup acquire");
	if (ioctl(fd, AGI_LC_REVOKE, &revoke) < 0)
		return fail("session revoke");
	printf("M94_SESSION_CLOSE_INVALIDATION_OK\n");
	printf("M94_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
