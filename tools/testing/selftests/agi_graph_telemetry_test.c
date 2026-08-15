// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "M69_FAIL:%s:%s\n", what, strerror(errno));
	return 1;
}

static int setup_session(int fd)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_TESTER,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.correlation = 69001,
	};
	struct agi_lc_agent agent = { .size = sizeof(agent) };

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		return -1;
	agent.agent_id = light.agent_id;
	agent.correlation = 69002;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

int main(void)
{
	int fd, backing, flags;
	struct agi_lc_graph_node node = {
		.size = sizeof(node),
		.operation = AGI_LC_GRAPH_NODE_CREATE,
		.graph_id = 6901,
		.node_id = 1,
		.workload = AGI_LC_WORKLOAD_INFERENCE,
		.device_mask = AGI_LC_GRAPH_DEVICE_CPU,
		.queue_class = 1,
		.priority = 900,
		.latency_sensitive = 1,
		.expected_runtime_ns = 1000,
		.correlation = 69003,
	};
	struct agi_lc_memory_region region = {
		.size = sizeof(region),
		.flags = AGI_LC_MEMORY_REGION_WORKING,
		.backing_fd = -1,
		.access = AGI_LC_MEMORY_ACCESS_READ | AGI_LC_MEMORY_ACCESS_WRITE,
		.size_bytes = 4096,
		.correlation = 69004,
	};
	struct agi_lc_compute_context context = {
		.size = sizeof(context),
		.operation = AGI_LC_CONTEXT_CREATE,
		.device_mask = AGI_LC_CONTEXT_DEVICE_CPU,
		.correlation = 69005,
	};
	struct agi_lc_graph_telemetry begin = {
		.size = sizeof(begin),
		.operation = AGI_LC_GRAPH_TELEMETRY_BEGIN,
		.flags = AGI_LC_GRAPH_TELEMETRY_FLAG_CONTEXT |
			AGI_LC_GRAPH_TELEMETRY_FLAG_TENSOR,
		.device_mask = AGI_LC_GRAPH_DEVICE_CPU,
		.graph_id = 6901,
		.node_id = 1,
		.operator_kind = 12,
		.correlation = 69006,
	};
	struct agi_lc_graph_telemetry query, bad, anomaly, end;
	struct agi_lc_record record;
	ssize_t n;
	int found_event = 0;
	int i;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open");
	if (setup_session(fd) < 0)
		return fail("session");
	if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
	    node.state != AGI_LC_GRAPH_STATE_READY)
		return fail("graph node");
	backing = open("/tmp/faisal-m69-region", O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
	if (backing < 0 || ftruncate(backing, 4096) < 0)
		return fail("backing file");
	region.backing_fd = backing;
	if (ioctl(fd, AGI_LC_MEMORY_REGION_CREATE, &region) < 0 ||
	    !region.region_id || !region.capability)
		return fail("memory region");
	if (ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &context) < 0 ||
	    !context.context_id || !context.context_capability)
		return fail("compute context");
	begin.context_id = context.context_id;
	begin.context_capability = context.context_capability;
	begin.tensor_region_id = region.region_id;
	begin.tensor_capability = region.capability;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &begin) < 0 ||
	    begin.state != AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE ||
	    !begin.telemetry_id || !begin.telemetry_capability ||
	    !begin.start_ns || begin.agent_id == 0 || begin.task_id == 0 ||
	    begin.dependency_count != 0 || begin.device_mask != AGI_LC_GRAPH_DEVICE_CPU)
		return fail("telemetry begin");
	printf("M69_TELEMETRY_BEGIN_OK id=%llu start=%llu\n",
	       (unsigned long long)begin.telemetry_id,
	       (unsigned long long)begin.start_ns);
	memset(&query, 0, sizeof(query));
	query.size = sizeof(query);
	query.operation = AGI_LC_GRAPH_TELEMETRY_QUERY;
	query.telemetry_id = begin.telemetry_id;
	query.telemetry_capability = begin.telemetry_capability;
	query.correlation = 69007;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &query) < 0 ||
	    query.state != AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE ||
	    query.graph_id != begin.graph_id || query.node_id != begin.node_id)
		return fail("telemetry query");
	printf("M69_TELEMETRY_QUERY_OK\n");
	memset(&bad, 0, sizeof(bad));
	bad.size = sizeof(bad);
	bad.operation = AGI_LC_GRAPH_TELEMETRY_QUERY;
	bad.telemetry_id = begin.telemetry_id;
	bad.telemetry_capability = begin.telemetry_capability ^ 1;
	bad.correlation = 69008;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &bad) >= 0 || errno != EACCES)
		return fail("stale telemetry capability rejection");
	printf("M69_STALE_TELEMETRY_CAPABILITY_REJECT_OK\n");
	anomaly = begin;
	anomaly.operation = AGI_LC_GRAPH_TELEMETRY_ANOMALY;
	anomaly.flags = AGI_LC_GRAPH_TELEMETRY_FLAG_ANOMALY;
	anomaly.context_id = 0;
	anomaly.context_capability = 0;
	anomaly.tensor_region_id = 0;
	anomaly.tensor_capability = 0;
	anomaly.anomaly_score = 420000;
	anomaly.anomaly_flags = 3;
	anomaly.correlation = 69009;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &anomaly) < 0 ||
	    anomaly.state != AGI_LC_GRAPH_TELEMETRY_STATE_ACTIVE ||
	    anomaly.anomaly_score != 420000 || anomaly.anomaly_flags != 3)
		return fail("anomaly signal");
	printf("M69_ANOMALY_SIGNAL_OK score=%u\n", anomaly.anomaly_score);
	end = begin;
	end.operation = AGI_LC_GRAPH_TELEMETRY_END;
	end.flags = AGI_LC_GRAPH_TELEMETRY_FLAG_CONTEXT |
		AGI_LC_GRAPH_TELEMETRY_FLAG_TENSOR |
		AGI_LC_GRAPH_TELEMETRY_FLAG_PROVIDER_MEASURED;
	end.status = 0;
	end.queue_delay_ns = 17;
	end.observed_runtime_ns = 999;
	end.bytes_in = 4096;
	end.bytes_out = 4096;
	end.provider_sequence = 77;
	end.correlation = 69010;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &end) < 0 ||
	    end.state != AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE ||
	    !end.end_ns || !end.duration_ns || end.queue_delay_ns != 17 ||
	    end.observed_runtime_ns != 999 || end.bytes_in != 4096 ||
	    end.bytes_out != 4096 || end.provider_sequence != 77)
		return fail("telemetry end");
	printf("M69_TELEMETRY_END_OK duration=%llu\n",
	       (unsigned long long)end.duration_ns);
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	for (i = 0; i < 64; i++) {
		n = read(fd, &record, sizeof(record));
		if (n != (ssize_t)sizeof(record)) {
			if (n < 0 && (errno == EAGAIN || errno == EINTR))
				continue;
			break;
		}
		if (record.type == AGI_LC_EVENT_GRAPH_OPERATION &&
		    record.metadata == begin.telemetry_id) {
			found_event = 1;
			break;
		}
	}
	if (!found_event)
		return fail("graph telemetry event delivery");
	printf("M69_GRAPH_EVENT_DELIVERY_OK\n");
	memset(&end, 0, sizeof(end));
	end.size = sizeof(end);
	end.operation = AGI_LC_GRAPH_TELEMETRY_QUERY;
	end.telemetry_id = begin.telemetry_id;
	end.telemetry_capability = begin.telemetry_capability;
	end.flags = 0;
	end.status = 0;
	end.device_mask = 0;
	end.context_id = 0;
	end.context_capability = 0;
	end.tensor_region_id = 0;
	end.tensor_capability = 0;
	end.graph_id = 0;
	end.node_id = 0;
	end.operator_kind = 0;
	end.dependency_count = 0;
	end.start_ns = 0;
	end.end_ns = 0;
	end.duration_ns = 0;
	end.queue_delay_ns = 0;
	end.observed_runtime_ns = 0;
	end.bytes_in = 0;
	end.bytes_out = 0;
	end.provider_sequence = 0;
	end.anomaly_score = 0;
	end.anomaly_flags = 0;
	end.generation = 0;
	end.correlation = 69011;
	if (ioctl(fd, AGI_LC_GRAPH_TELEMETRY, &end) < 0 ||
	    end.state != AGI_LC_GRAPH_TELEMETRY_STATE_COMPLETE ||
	    end.bytes_in != 4096 || end.anomaly_score != 420000)
		return fail("completed telemetry query");
	printf("M69_COMPLETED_QUERY_OK\nM69_SELFTEST_EXIT=0\n");
	context.operation = AGI_LC_CONTEXT_CLOSE;
	context.correlation = 69012;
	ioctl(fd, AGI_LC_COMPUTE_CONTEXT, &context);
	close(backing);
	unlink("/tmp/faisal-m69-region");
	close(fd);
	return 0;
}
