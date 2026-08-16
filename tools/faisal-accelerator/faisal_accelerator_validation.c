#define _GNU_SOURCE
#include "faisal_accelerator_validation.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fail_close(struct m79_service *service)
{
	m79_close(service);
	return -1;
}

static int fail_stage(struct m79_service *service, const char *stage)
{
	fprintf(stderr, "M79_RUN_FAIL:%s errno=%d\\n", stage, errno);
	return fail_close(service);
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 79001,
	};
	struct agi_lc_agent selected = { .size = sizeof(selected) };
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	selected.agent_id = light.agent_id;
	selected.correlation = 79002;
	return ioctl(fd, AGI_LC_SET_AGENT, &selected);
}

static int drain_record(int fd)
{
	struct agi_lc_record record;
	ssize_t n = read(fd, &record, sizeof(record));
	return n == (ssize_t)sizeof(record) ? 0 : -1;
}

int m79_open(struct m79_service *service)
{
	if (!service)
		return -1;
	memset(service, 0, sizeof(*service));
	service->kernel_fd = -1;
	service->backing_fd = -1;
	service->kernel_fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (service->kernel_fd < 0 || setup_session(service->kernel_fd) < 0)
		return fail_close(service);
	return 0;
}

void m79_close(struct m79_service *service)
{
	if (!service)
		return;
	if (service->context.context_id) {
		struct agi_lc_compute_context close_context = service->context;
		close_context.operation = AGI_LC_CONTEXT_CLOSE;
		close_context.correlation = 79090;
		ioctl(service->kernel_fd, AGI_LC_COMPUTE_CONTEXT, &close_context);
	}
	if (service->transport.transport_id) {
		struct agi_lc_tensor_transport revoke = service->transport;
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
		revoke.correlation = 79091;
		ioctl(service->kernel_fd, AGI_LC_TENSOR_TRANSPORT, &revoke);
	}
	if (service->backing_fd >= 0)
		close(service->backing_fd);
	if (service->kernel_fd >= 0)
		close(service->kernel_fd);
	service->backing_fd = -1;
	service->kernel_fd = -1;
}

int m79_validate_provider_evidence(const struct m79_provider_evidence *evidence)
{
	if (!evidence || evidence->reserved ||
	    strnlen(evidence->provider_name, M79_PROVIDER_NAME_MAX) >=
		M79_PROVIDER_NAME_MAX)
		return -1;
	if (evidence->provider_state == M79_PROVIDER_UNSUPPORTED)
		return evidence->provider_name[0] || evidence->device_mask ||
		       evidence->fabric_mask || evidence->provider_kind ||
		       evidence->address_space_mode || evidence->flags ||
		       evidence->provider_device_id ? -1 : 0;
	if (evidence->provider_state != M79_PROVIDER_AVAILABLE ||
	    !evidence->provider_name[0] || !evidence->device_mask ||
	    !evidence->provider_device_id ||
	    (evidence->device_mask & ~AGI_LC_CONTEXT_DEVICE_ALL) ||
	    (evidence->fabric_mask & ~AGI_LC_CONTEXT_FABRIC_ALL))
		return -1;
	return 0;
}

int m79_discover_provider(struct m79_provider_evidence *evidence)
{
	struct stat device_stat;
	struct stat class_stat;
	if (!evidence)
		return -1;
	memset(evidence, 0, sizeof(*evidence));
	if (stat("/dev/accel/accel0", &device_stat) == 0 &&
	    stat("/sys/class/accel/accel0", &class_stat) == 0) {
		evidence->provider_state = M79_PROVIDER_AVAILABLE;
		strncpy(evidence->provider_name, "linux-accel-device",
			sizeof(evidence->provider_name) - 1);
		evidence->device_mask = AGI_LC_CONTEXT_DEVICE_GPU;
		evidence->provider_kind = AGI_LC_CONTEXT_PROVIDER_NONE;
		evidence->provider_device_id = 1;
		return 0;
	}
	evidence->provider_state = M79_PROVIDER_UNSUPPORTED;
	return 0;
}

static int create_region(struct m79_service *service)
{
	struct agi_lc_memory_region *region = &service->region;
	memset(region, 0, sizeof(*region));
	service->backing_fd = syscall(SYS_memfd_create, "faisal-m79-region",
					 MFD_CLOEXEC);
	if (service->backing_fd < 0 || ftruncate(service->backing_fd, 4096) < 0)
		return -1;
	region->size = sizeof(*region);
	region->flags = AGI_LC_MEMORY_REGION_WORKING | AGI_LC_MEMORY_REGION_SHARED;
	region->backing_fd = service->backing_fd;
	region->access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE;
	region->size_bytes = 4096;
	region->correlation = 79003;
	if (ioctl(service->kernel_fd, AGI_LC_MEMORY_REGION_CREATE, region) < 0 ||
	    !region->region_id || !region->capability || drain_record(service->kernel_fd) < 0)
		return -1;
	return 0;
}

int m79_run(struct m79_service *service,
	    const struct m79_provider_evidence *evidence)
{
	struct agi_lc_tensor_policy tensor;
	struct agi_lc_adaptive_memory_policy adaptive;
	struct agi_lc_graph_node node;
	struct agi_lc_resource_snapshot snapshot;
	if (!service || !evidence || m79_validate_provider_evidence(evidence) != 0)
		return -1;
	service->report.provider_state = evidence->provider_state;
	if (create_region(service) != 0)
		return fail_stage(service, "region");
	service->report.region_id = service->region.region_id;
	service->report.region_capability = service->region.capability;
	memset(&service->context, 0, sizeof(service->context));
	service->context.size = sizeof(service->context);
	service->context.operation = AGI_LC_CONTEXT_CREATE;
	service->context.device_mask = AGI_LC_CONTEXT_DEVICE_ALL;
	service->context.requested_fabric = AGI_LC_CONTEXT_FABRIC_ALL;
	service->context.correlation = 79004;
	if (ioctl(service->kernel_fd, AGI_LC_COMPUTE_CONTEXT, &service->context) < 0 ||
	    !service->context.context_id || !service->context.context_capability)
		return fail_stage(service, "context");
	service->report.active_device_mask = service->context.active_device_mask;
	service->report.unsupported_device_mask = service->context.unsupported_device_mask;
	service->report.active_fabric = service->context.active_fabric;
	service->report.unsupported_fabric = service->context.unsupported_fabric;
	if (evidence->provider_state == M79_PROVIDER_AVAILABLE &&
	    !(service->context.active_device_mask & evidence->device_mask)) {
		service->report.provider_state = M79_PROVIDER_REJECTED;
		return fail_stage(service, "provider-mismatch");
	}
	service->report.context_id = service->context.context_id;
	service->report.context_capability = service->context.context_capability;
	memset(&tensor, 0, sizeof(tensor));
	tensor.size = sizeof(tensor);
	tensor.operation = AGI_LC_TENSOR_POLICY_SET;
	tensor.region_id = service->region.region_id;
	tensor.capability = service->region.capability;
	tensor.rank = 1;
	tensor.element_size = 4;
	tensor.preferred_numa_node = AGI_LC_TENSOR_NUMA_ANY;
	tensor.tier_mask = AGI_LC_TENSOR_TIER_DDR;
	tensor.total_bytes = 4096;
	tensor.alignment = 4096;
	tensor.dimensions[0] = 1024;
	tensor.strides[0] = 4;
	tensor.correlation = 79005;
	if (ioctl(service->kernel_fd, AGI_LC_TENSOR_POLICY, &tensor) < 0 ||
	    drain_record(service->kernel_fd) < 0 || !tensor.generation)
		return fail_stage(service, "tensor-policy");
	memset(&adaptive, 0, sizeof(adaptive));
	adaptive.size = sizeof(adaptive);
	adaptive.operation = AGI_LC_ADAPTIVE_MEMORY_POLICY_SET;
	adaptive.flags = AGI_LC_ADAPTIVE_MEMORY_FLAG_TIER_AWARE;
	adaptive.action = AGI_LC_ADAPTIVE_MEMORY_ACTION_MIGRATE_HOT;
	adaptive.provider_mask = AGI_LC_ADAPTIVE_MEMORY_PROVIDER_ALL;
	adaptive.region_id = service->region.region_id;
	adaptive.capability = service->region.capability;
	adaptive.sample_interval_ns = 10ULL * 1000ULL * 1000ULL;
	adaptive.aggregation_interval_ns = 100ULL * 1000ULL * 1000ULL;
	adaptive.apply_interval_ns = 1000ULL * 1000ULL * 1000ULL;
	adaptive.max_overhead_ppm = 40000;
	adaptive.max_bytes_per_interval = 4096;
	adaptive.correlation = 790051;
	if (ioctl(service->kernel_fd, AGI_LC_ADAPTIVE_MEMORY_POLICY, &adaptive) < 0 ||
		adaptive.status != AGI_LC_ADAPTIVE_MEMORY_STATUS_OBSERVE_ONLY ||
		adaptive.unsupported_provider_mask != AGI_LC_ADAPTIVE_MEMORY_PROVIDER_ALL ||
		!adaptive.generation || drain_record(service->kernel_fd) < 0)
		return fail_stage(service, "adaptive-memory-set");
	adaptive.flags |= AGI_LC_ADAPTIVE_MEMORY_FLAG_PROVIDER_REQUIRED;
	if (ioctl(service->kernel_fd, AGI_LC_ADAPTIVE_MEMORY_POLICY, &adaptive) >= 0 ||
		errno != EOPNOTSUPP)
		return fail_stage(service, "adaptive-memory-provider-gate");
	adaptive.flags = AGI_LC_ADAPTIVE_MEMORY_FLAG_TIER_AWARE;
	adaptive.operation = AGI_LC_ADAPTIVE_MEMORY_POLICY_GET;
	adaptive.action = 0;
	adaptive.provider_mask = 0;
	adaptive.sample_interval_ns = 0;
	adaptive.aggregation_interval_ns = 0;
	adaptive.apply_interval_ns = 0;
	adaptive.max_overhead_ppm = 0;
	adaptive.max_bytes_per_interval = 0;
	if (ioctl(service->kernel_fd, AGI_LC_ADAPTIVE_MEMORY_POLICY, &adaptive) < 0 ||
		adaptive.status != AGI_LC_ADAPTIVE_MEMORY_STATUS_OBSERVE_ONLY ||
		adaptive.unsupported_provider_mask != AGI_LC_ADAPTIVE_MEMORY_PROVIDER_ALL ||
		!adaptive.generation)
		return fail_stage(service, "adaptive-memory-get");
	adaptive.operation = AGI_LC_ADAPTIVE_MEMORY_POLICY_CLEAR;
	adaptive.flags = 0;
	adaptive.action = 0;
	adaptive.status = 0;
	adaptive.provider_mask = 0;
	adaptive.sample_interval_ns = 0;
	adaptive.aggregation_interval_ns = 0;
	adaptive.apply_interval_ns = 0;
	adaptive.max_overhead_ppm = 0;
	adaptive.max_bytes_per_interval = 0;
	adaptive.generation = 0;
	adaptive.unsupported_provider_mask = 0;
	adaptive.correlation = 790052;
	if (ioctl(service->kernel_fd, AGI_LC_ADAPTIVE_MEMORY_POLICY, &adaptive) < 0 ||
		drain_record(service->kernel_fd) < 0 || !adaptive.generation)
		return fail_stage(service, "adaptive-memory-clear");
	tensor.generation = adaptive.generation;
	memset(&service->transport, 0, sizeof(service->transport));

	service->transport.size = sizeof(service->transport);
	service->transport.operation = AGI_LC_TENSOR_TRANSPORT_REGISTER;
	service->transport.transport_kind = AGI_LC_TRANSPORT_DMA_BUF;
	service->transport.collective_kind = AGI_LC_TRANSPORT_ALLREDUCE;
	service->transport.direction = AGI_LC_TRANSPORT_SEND;
	service->transport.participants = 2;
	service->transport.source_device_id = 1;
	service->transport.target_device_id = 2;
	service->transport.bytes = 4096;
	service->transport.chunk_bytes = 4096;
	service->transport.region_id = service->region.region_id;
	service->transport.region_capability = service->region.capability;
	service->transport.region_generation = tensor.generation;
	service->transport.correlation = 79006;
	if (ioctl(service->kernel_fd, AGI_LC_TENSOR_TRANSPORT, &service->transport) < 0 ||
	    service->transport.state != AGI_LC_TRANSPORT_STATE_ACTIVE ||
	    !service->transport.transport_id || !service->transport.capability)
		return fail_stage(service, "tensor-transport");
	service->report.transport_id = service->transport.transport_id;
	service->report.transport_capability = service->transport.capability;
	memset(&node, 0, sizeof(node));
	node.size = sizeof(node);
	node.operation = AGI_LC_GRAPH_NODE_CREATE;
	node.graph_id = 7901;
	node.node_id = 1;
	node.workload = AGI_LC_WORKLOAD_INFERENCE;
	node.device_mask = AGI_LC_GRAPH_DEVICE_CPU;
	node.queue_class = 1;
	node.priority = 700;
	node.latency_sensitive = 1;
	node.expected_runtime_ns = 1000;
	node.correlation = 79007;
	if (ioctl(service->kernel_fd, AGI_LC_GRAPH_NODE, &node) < 0)
		return fail_stage(service, "graph-node");
	memset(&service->telemetry, 0, sizeof(service->telemetry));
	service->telemetry.size = sizeof(service->telemetry);
	service->telemetry.operation = AGI_LC_GRAPH_TELEMETRY_BEGIN;
	service->telemetry.flags = AGI_LC_GRAPH_TELEMETRY_FLAG_CONTEXT |
		AGI_LC_GRAPH_TELEMETRY_FLAG_TENSOR;
	service->telemetry.device_mask = AGI_LC_GRAPH_DEVICE_CPU;
	service->telemetry.graph_id = node.graph_id;
	service->telemetry.node_id = node.node_id;
	service->telemetry.context_id = service->context.context_id;
	service->telemetry.context_capability = service->context.context_capability;
	service->telemetry.tensor_region_id = service->region.region_id;
	service->telemetry.tensor_capability = service->region.capability;
	service->telemetry.transport_id = 0;
	service->telemetry.transport_capability = 0;
	service->telemetry.operator_kind = 12;
	service->telemetry.correlation = 79008;
	if (ioctl(service->kernel_fd, AGI_LC_GRAPH_TELEMETRY, &service->telemetry) < 0 ||
	    service->telemetry.state != AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE ||
	    !service->telemetry.telemetry_id || !service->telemetry.telemetry_capability)
		return fail_stage(service, "telemetry-begin");
	service->report.telemetry_id = service->telemetry.telemetry_id;
	service->report.telemetry_capability = service->telemetry.telemetry_capability;
	service->telemetry.operation = AGI_LC_GRAPH_TELEMETRY_END;
	service->telemetry.status = 0;
	service->telemetry.observed_runtime_ns = 1000;
	service->telemetry.bytes_in = 4096;
	service->telemetry.bytes_out = 4096;
	service->telemetry.correlation = 79009;
	if (ioctl(service->kernel_fd, AGI_LC_GRAPH_TELEMETRY, &service->telemetry) < 0 ||
	    service->telemetry.state != AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE)
		return fail_stage(service, "telemetry-end");
	service->report.telemetry_state = service->telemetry.state;
	service->report.provider_sequence = service->telemetry.provider_sequence;
	memset(&snapshot, 0, sizeof(snapshot));
	snapshot.size = sizeof(snapshot);
	snapshot.correlation = 79010;
	if (ioctl(service->kernel_fd, AGI_LC_GET_RESOURCE_SNAPSHOT, &snapshot) < 0)
		return fail_stage(service, "resource-snapshot");
	service->snapshot = snapshot;
	service->report.resource_measured_mask = snapshot.measured_mask;
	service->report.resource_unavailable_mask = snapshot.unavailable_mask;
	service->report.resource_unsupported_mask = snapshot.unsupported_mask;
	memset(&service->power, 0, sizeof(service->power));
	service->power.size = sizeof(service->power);
	service->power.operation = AGI_LC_POWER_POLICY_SET;
	service->power.flags = AGI_LC_POWER_POLICY_FLAG_CPU_LATENCY_QOS;
	service->power.profile = AGI_LC_POWER_PROFILE_INFERENCE;
	service->power.requested_features = AGI_LC_POWER_POLICY_FEATURE_CPU_LATENCY_QOS |
		AGI_LC_POWER_POLICY_FEATURE_DEVICE_WAKE_LATENCY |
		AGI_LC_POWER_POLICY_FEATURE_POWER_BUDGET;
	service->power.min_cpu_util = 128;
	service->power.max_cpu_util = 900;
	service->power.cpu_latency_us = 1000;
	service->power.power_budget_uw = 1000000;
	service->power.power_window_us = 10000;
	service->power.correlation = 79011;
	if (ioctl(service->kernel_fd, AGI_LC_POWER_POLICY, &service->power) < 0 ||
	    !service->power.policy_id || !service->power.capability)
		return fail_stage(service, "power-policy");
	service->report.power_policy_id = service->power.policy_id;
	service->report.power_capability = service->power.capability;
	return 0;
}

int m79_test_metadata_fuzz(const struct m79_provider_evidence *evidence)
{
	struct m79_provider_evidence mutated;
	unsigned int i;
	if (!evidence || m79_validate_provider_evidence(evidence) != 0)
		return -1;
	for (i = 0; i < M79_FUZZ_CASES; i++) {
		mutated = *evidence;
		switch (i % 6) {
		case 0:
			mutated.reserved = 1;
			break;
		case 1:
			mutated.provider_state = 99;
			break;
		case 2:
			mutated.device_mask = AGI_LC_CONTEXT_DEVICE_ALL << 1;
			break;
		case 3:
			mutated.provider_device_id = 1;
			break;
		case 4:
			mutated.provider_name[0] = 'x';
			mutated.provider_state = M79_PROVIDER_UNSUPPORTED;
			break;
		default:
			mutated.provider_name[0] = 'x';
			break;
		}
		if (m79_validate_provider_evidence(&mutated) == 0)
			return -1;
	}
	return 0;
}

int m79_test_stale_capabilities(struct m79_service *service)
{
	struct agi_lc_compute_context context;
	struct agi_lc_tensor_transport transport;
	struct agi_lc_graph_telemetry telemetry;
	if (!service || service->kernel_fd < 0)
		return -1;
	context = service->context;
	context.operation = AGI_LC_CONTEXT_GET;
	context.context_capability ^= 1;
	context.correlation = 79020;
	if (ioctl(service->kernel_fd, AGI_LC_COMPUTE_CONTEXT, &context) >= 0 ||
	    errno != EACCES)
		return -1;
	transport = service->transport;
	transport.operation = AGI_LC_TENSOR_TRANSPORT_QUERY;
	transport.capability ^= 1;
	transport.region_id = 0;
	transport.region_capability = 0;
	transport.region_generation = 0;
	transport.correlation = 79021;
	if (ioctl(service->kernel_fd, AGI_LC_TENSOR_TRANSPORT, &transport) >= 0 ||
	    errno != EACCES)
		return -1;
	memset(&telemetry, 0, sizeof(telemetry));
	telemetry.size = sizeof(telemetry);
	telemetry.operation = AGI_LC_GRAPH_TELEMETRY_QUERY;
	telemetry.telemetry_id = service->telemetry.telemetry_id;
	telemetry.telemetry_capability = service->telemetry.telemetry_capability ^ 1;
	telemetry.correlation = 79022;
	if (ioctl(service->kernel_fd, AGI_LC_GRAPH_TELEMETRY, &telemetry) >= 0 ||
	    errno != EACCES)
		return -1;
	return 0;
}
