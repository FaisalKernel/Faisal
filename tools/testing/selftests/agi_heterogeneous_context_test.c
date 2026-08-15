// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M68_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 68001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	agent.agent_id = light.agent_id;
	agent.correlation = 68002;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

int main(void)
{
	int fd, backing;
	struct agi_lc_memory_region region = {
		.size = sizeof(region),
		.flags = AGI_LC_MEMORY_REGION_WORKING,
		.backing_fd = -1,
		.access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE,
		.size_bytes = 4096,
		.correlation = 68003,
	};
	struct agi_lc_compute_context ctx = {
		.size = sizeof(ctx),
		.operation = AGI_LC_CONTEXT_CREATE,
		.device_mask = AGI_LC_CONTEXT_DEVICE_ALL,
		.requested_fabric = AGI_LC_CONTEXT_FABRIC_ALL,
		.correlation = 68004,
	};
	struct agi_lc_compute_context query, bad, bind, unbind, gpu;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (setup_session(fd) < 0)
		return fail("session");
	backing = open("/tmp/faisal-m68-region", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
	if (backing < 0 || ftruncate(backing, 4096) < 0)
		return fail("backing file");
	region.backing_fd = backing;
	if (ioctl(fd, AGI_LC_MEMORY_REGION_CREATE, &region) < 0 ||
	    !region.region_id || !region.capability || region.generation != 1)
		return fail("memory region");
	printf("M68_MEMORY_REGION_OK id=%llu bytes=%llu\n",
	       (unsigned long long)region.region_id,
	       (unsigned long long)region.size_bytes);
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &ctx) < 0 ||
	    ctx.state != AGI_LC_CONTEXT_STATE_ACTIVE || !ctx.context_id ||
	    !ctx.context_capability ||
	    ctx.active_device_mask != AGI_LC_CONTEXT_DEVICE_CPU ||
	    ctx.unsupported_device_mask !=
		(AGI_LC_CONTEXT_DEVICE_GPU | AGI_LC_CONTEXT_DEVICE_NPU |
		 AGI_LC_CONTEXT_DEVICE_IO) ||
	    ctx.provider_kind != AGI_LC_CONTEXT_PROVIDER_CPU ||
	    ctx.address_space_mode != AGI_LC_CONTEXT_ADDRESS_SPACE_PROCESS ||
	    !(ctx.active_fabric & AGI_LC_CONTEXT_FABRIC_CPU) ||
	    !(ctx.active_fabric & AGI_LC_CONTEXT_FABRIC_DMA_BUF) ||
	    !(ctx.active_fabric & AGI_LC_CONTEXT_FABRIC_DMA_ENGINE) ||
	    !(ctx.active_fabric & AGI_LC_CONTEXT_FABRIC_IOMMU_SVA) ||
	    !(ctx.unsupported_fabric & AGI_LC_CONTEXT_FABRIC_HMM) ||
	    !(ctx.unsupported_fabric & AGI_LC_CONTEXT_FABRIC_UACCE))
		return fail("context negotiation");
	printf("M68_CONTEXT_NEGOTIATION_OK active_fabric=0x%llx\n",
	       (unsigned long long)ctx.active_fabric);
	query = ctx;
	query.operation = AGI_LC_CONTEXT_GET;
	query.correlation = 68005;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &query) < 0 ||
	    query.context_id != ctx.context_id ||
	    query.active_device_mask != AGI_LC_CONTEXT_DEVICE_CPU)
		return fail("context query");
	printf("M68_CONTEXT_QUERY_OK\n");
	bad = query;
	bad.operation = AGI_LC_CONTEXT_GET;
	bad.context_capability ^= 1;
	bad.correlation = 68006;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &bad) >= 0 || errno != EACCES)
		return fail("stale context capability rejection");
	printf("M68_STALE_CONTEXT_CAPABILITY_REJECT_OK\n");
	bind = ctx;
	bind.operation = AGI_LC_CONTEXT_BIND_REGION;
	bind.region_id = region.region_id;
	bind.region_capability = region.capability;
	bind.region_access = region.access;
	bind.correlation = 68007;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &bind) < 0 ||
	    bind.bound_regions != 1 || bind.bytes_accounted != region.size_bytes)
		return fail("context region bind");
	printf("M68_CONTEXT_BIND_OK accounted=%llu\n",
	       (unsigned long long)bind.bytes_accounted);
	unbind = bind;
	unbind.operation = AGI_LC_CONTEXT_UNBIND_REGION;
	unbind.correlation = 68008;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &unbind) < 0 ||
	    unbind.bound_regions != 0 || unbind.bytes_accounted != 0)
		return fail("context region unbind");
	printf("M68_CONTEXT_UNBIND_OK\n");
	gpu = ctx;
	gpu.operation = AGI_LC_CONTEXT_CREATE;
	gpu.context_id = 0;
	gpu.context_capability = 0;
	gpu.state = 0;
	gpu.generation = 0;
	gpu.requested_fabric = AGI_LC_CONTEXT_FABRIC_ALL;
	gpu.device_mask = AGI_LC_CONTEXT_DEVICE_GPU;
	gpu.active_device_mask = 0;
	gpu.unsupported_device_mask = 0;
	gpu.active_fabric = 0;
	gpu.unsupported_fabric = 0;
	gpu.address_space_mode = 0;
	gpu.provider_kind = 0;
	gpu.bytes_accounted = 0;
	gpu.transfer_bytes = 0;
	gpu.compute_ns = 0;
	gpu.state_sequence = 0;
	gpu.correlation = 68009;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &gpu) < 0 ||
	    gpu.active_device_mask != 0 ||
	    gpu.unsupported_device_mask != AGI_LC_CONTEXT_DEVICE_GPU ||
	    gpu.provider_kind != AGI_LC_CONTEXT_PROVIDER_NONE ||
	    gpu.address_space_mode != AGI_LC_CONTEXT_ADDRESS_SPACE_NONE)
		return fail("unsupported GPU context");
	printf("M68_GPU_PROVIDER_BOUNDARY_OK\n");
	gpu.operation = AGI_LC_CONTEXT_CLOSE;
	gpu.correlation = 68010;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &gpu) < 0 ||
	    gpu.state != AGI_LC_CONTEXT_STATE_CLOSED)
		return fail("gpu context close request");
	ctx.operation = AGI_LC_CONTEXT_CLOSE;
	ctx.correlation = 68011;
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &ctx) < 0 ||
	    ctx.state != AGI_LC_CONTEXT_STATE_CLOSED)
		return fail("context close");
	printf("M68_CONTEXT_CLOSE_OK\nM68_SELFTEST_EXIT=0\n");
	close(backing);
	unlink("/tmp/faisal-m68-region");
	close(fd);
	return 0;
}
