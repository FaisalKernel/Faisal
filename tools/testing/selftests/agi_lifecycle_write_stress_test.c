/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FAISAL lifecycle write-side stress smoke.
 *
 * This test uses only valid UAPI requests. It intentionally fills the
 * per-session event ring through graph-node operations, then verifies that
 * bounded queue overflow returns an expected errno rather than an unexpected
 * signal-safe failure. It is qualification evidence, not production approval.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define WRITE_DEFAULT_NODES 64U
#define WRITE_GRAPH_ID 0x5747495354524553ULL

struct write_result {
	unsigned long calls;
	unsigned long accepted;
	unsigned long expected_rejected;
	unsigned long unexpected_errors;
};

static int expected_overflow_errno(int error)
{
	return error == EAGAIN || error == EBUSY || error == ENOSPC ||
		error == EINVAL || error == ENOENT || error == EPERM ||
		error == EPIPE || error == EOVERFLOW;
}

static int graph_call(int fd, struct agi_lc_graph_node *node,
			      struct write_result *result)
{
	int rc;

	errno = 0;
	rc = ioctl(fd, AGI_LC_GRAPH_NODE, node);
	result->calls++;
	if (rc == 0) {
		result->accepted++;
		return 0;
	}
	if (expected_overflow_errno(errno)) {
		result->expected_rejected++;
		return 0;
	}
	result->unexpected_errors++;
	return -1;
}

static void graph_node_init(struct agi_lc_graph_node *node, __u32 operation,
				    __u64 node_id)
{
	memset(node, 0, sizeof(*node));
	node->size = sizeof(*node);
	node->operation = operation;
	node->graph_id = WRITE_GRAPH_ID;
	node->node_id = node_id;
	node->device_mask = AGI_LC_GRAPH_DEVICE_CPU;
	node->queue_class = 0;
	node->priority = (__u32)(node_id % AGI_LC_SCHED_PRIORITY_MAX);
	node->correlation = node_id;
}

static unsigned long parse_nodes(const char *value)
{
	char *end;
	unsigned long nodes;

	errno = 0;
	nodes = strtoul(value, &end, 10);
	if (errno || !value[0] || *end || nodes == 0 || nodes > AGI_LC_GRAPH_MAX_NODES)
		return 0;
	return nodes;
}

int main(int argc, char **argv)
{
	struct agi_lc_create create = { 0 };
	struct write_result result = { 0 };
	const char *device = "/dev/agi_lifecycle";
	unsigned long nodes = WRITE_DEFAULT_NODES;
	unsigned long i;
	int fd;
	int rc;

	if (argc > 1)
		device = argv[1];
	if (argc > 2) {
		nodes = parse_nodes(argv[2]);
		if (!nodes) {
			fprintf(stderr, "invalid node count\n");
			return 2;
		}
	}

	fd = open(device, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open lifecycle device");
		return 2;
	}

	create.size = sizeof(create);
	rc = ioctl(fd, AGI_LC_CREATE, &create);
	if (rc < 0) {
		perror("AGI_LC_CREATE");
		close(fd);
		return 2;
	}
	if (ioctl(fd, AGI_LC_ATTACH_TASK, 0) < 0) {
		perror("AGI_LC_ATTACH_TASK");
		close(fd);
		return 2;
	}

	for (i = 1; i <= nodes; i++) {
		struct agi_lc_graph_node node;

		graph_node_init(&node, AGI_LC_GRAPH_NODE_CREATE, i);
		if (graph_call(fd, &node, &result) < 0)
			goto fail;
	}

	for (i = 1; i <= nodes; i++) {
		struct agi_lc_graph_node node;

		graph_node_init(&node, AGI_LC_GRAPH_NODE_CANCEL, i);
		if (graph_call(fd, &node, &result) < 0)
			goto fail;
	}

	if (close(fd) < 0) {
		perror("close lifecycle device");
		return 2;
	}

	printf("FAISAL_UAPI_WRITE_STRESS_OK calls=%lu accepted=%lu expected_rejected=%lu unexpected_errors=%lu nodes=%lu session_id=%llu\n",
	       result.calls, result.accepted, result.expected_rejected, result.unexpected_errors,
	       nodes, (unsigned long long)create.session_id);
	return result.unexpected_errors ? 1 : 0;

fail:
	fprintf(stderr, "unexpected graph ioctl errno=%d (%s)\n", errno, strerror(errno));
	close(fd);
	return 1;
}
