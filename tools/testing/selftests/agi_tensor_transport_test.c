// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "TRANSPORT_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int drain(int fd)
{
	struct agi_lc_record record;
	return read(fd, &record, sizeof(record)) == sizeof(record) ? 0 : -1;
}

int main(void)
{
	int fd, backing;
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent agent = {
		.size = sizeof(agent),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.correlation = 66001,
	};
	struct agi_lc_agent set_agent;
	struct agi_lc_memory_region region = {
		.size = sizeof(region),
		.flags = AGI_LC_MEMORY_REGION_WORKING | AGI_LC_MEMORY_REGION_SHARED,
		.access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE,
		.size_bytes = 16384,
		.correlation = 66002,
	};
	struct agi_lc_tensor_policy tensor = {
		.size = sizeof(tensor),
		.operation = AGI_LC_TENSOR_POLICY_SET,
		.rank = 1,
		.element_size = 4,
		.preferred_numa_node = AGI_LC_TENSOR_NUMA_ANY,
		.tier_mask = AGI_LC_TENSOR_TIER_DDR,
		.total_bytes = 16384,
		.alignment = 4096,
		.dimensions = { 4096 },
		.strides = { 4 },
		.correlation = 66003,
	};
	struct agi_lc_tensor_transport transport = {
		.size = sizeof(transport),
		.operation = AGI_LC_TENSOR_TRANSPORT_REGISTER,
		.transport_kind = AGI_LC_TRANSPORT_DMA_BUF,
		.collective_kind = AGI_LC_TRANSPORT_ALLREDUCE,
		.direction = AGI_LC_TRANSPORT_SEND,
		.participants = 2,
		.participant_index = 0,
		.source_device_id = 1,
		.target_device_id = 2,
		.bytes = 16384,
		.chunk_bytes = 4096,
		.correlation = 66004,
	};
	struct agi_lc_tensor_transport query, revoke, bad, zero_copy;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &agent) < 0 ||
	    !agent.agent_id || !agent.capability)
		return fail("session");
	memset(&set_agent, 0, sizeof(set_agent));
	set_agent.size = sizeof(set_agent);
	set_agent.agent_id = agent.agent_id;
	set_agent.correlation = 66005;
	if (ioctl(fd, AGI_LC_SET_AGENT, &set_agent) < 0)
		return fail("set agent");
	backing = syscall(SYS_memfd_create, "faisal-transport", MFD_ALLOW_SEALING);
	if (backing < 0 || ftruncate(backing, region.size_bytes) < 0)
		return fail("backing");
	region.backing_fd = backing;
	if (ioctl(fd, AGI_LC_MEMORY_REGION_CREATE, &region) < 0 ||
	    drain(fd) < 0)
		return fail("memory region");
	tensor.region_id = region.region_id;
	tensor.capability = region.capability;
	if (ioctl(fd, AGI_LC_TENSOR_POLICY, &tensor) < 0 ||
	    drain(fd) < 0 || !tensor.generation)
		return fail("tensor policy");
	transport.region_id = region.region_id;
	transport.region_capability = region.capability;
	transport.region_generation = tensor.generation;
	if (ioctl(fd, AGI_LC_TENSOR_TRANSPORT, &transport) < 0 ||
	    transport.state != AGI_LC_TRANSPORT_STATE_ACTIVE ||
	    !transport.transport_id || !transport.capability)
		return fail("transport register");
	printf("M66_TRANSPORT_REGISTER_OK id=%llu\n",
	       (unsigned long long)transport.transport_id);
	query = transport;
	query.operation = AGI_LC_TENSOR_TRANSPORT_QUERY;
	query.region_id = 0;
	query.region_capability = 0;
	query.region_generation = 0;
	query.source_device_id = 0;
	query.target_device_id = 0;
	query.bytes = 0;
	query.chunk_bytes = 0;
	query.participants = 0;
	query.participant_index = 0;
	query.correlation = 66006;
	if (ioctl(fd, AGI_LC_TENSOR_TRANSPORT, &query) < 0 ||
	    query.state != AGI_LC_TRANSPORT_STATE_ACTIVE ||
	    query.transport_id != transport.transport_id)
		return fail("transport query");
	printf("M66_TRANSPORT_QUERY_OK\n");
	bad = query;
	bad.capability ^= 1;
	bad.correlation = 66007;
	if (ioctl(fd, AGI_LC_TENSOR_TRANSPORT, &bad) >= 0 || errno != EACCES)
		return fail("stale tensor capability rejection");
	printf("M66_STALE_CAPABILITY_REJECT_OK\n");
	zero_copy = transport;
	zero_copy.operation = AGI_LC_TENSOR_TRANSPORT_REGISTER;
	zero_copy.flags = AGI_LC_TRANSPORT_REQUIRE_ZERO_COPY;
	zero_copy.transport_id = 0;
	zero_copy.capability = 0;
	zero_copy.generation = 0;
	zero_copy.state = 0;
	zero_copy.status = 0;
	zero_copy.completion_sequence = 0;
	zero_copy.correlation = 66008;
	if (ioctl(fd, AGI_LC_TENSOR_TRANSPORT, &zero_copy) >= 0 ||
	    errno != EOPNOTSUPP)
		return fail("unsupported zero-copy claim");
	printf("M66_ZERO_COPY_BOUNDARY_OK\n");
	revoke = transport;
	revoke.operation = AGI_LC_TENSOR_TRANSPORT_REVOKE;
	revoke.region_id = 0;
	revoke.region_capability = 0;
	revoke.region_generation = 0;
	revoke.source_device_id = 0;
	revoke.target_device_id = 0;
	revoke.bytes = 0;
	revoke.chunk_bytes = 0;
	revoke.participants = 0;
	revoke.participant_index = 0;
	revoke.correlation = 66009;
	if (ioctl(fd, AGI_LC_TENSOR_TRANSPORT, &revoke) < 0 ||
	    revoke.state != AGI_LC_TRANSPORT_STATE_REVOKED)
		return fail("transport revoke");
	printf("M66_TRANSPORT_REVOKE_OK\nM66_SELFTEST_EXIT=0\n");
	close(backing);
	close(fd);
	return 0;
}
