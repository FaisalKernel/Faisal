/* SPDX-License-Identifier: GPL-2.0 */
/*
 * FAISAL lifecycle graph fault-injection smoke.
 *
 * The test deliberately sends malformed or stale graph requests and verifies
 * fail-closed errno behavior, then exercises valid create/get/cancel paths.
 * Expected event-ring overflow is accepted only after the returned graph state
 * is checked, so an event-delivery failure cannot hide a state regression.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define GRAPH_ID 0x4641554c54475250ULL

struct fault_result {
	unsigned long checks;
	unsigned long expected_rejections;
	unsigned long unexpected;
};

static int expected_event_errno(int error)
{
	return error == EAGAIN || error == EBUSY;
}

static void node_init(struct agi_lc_graph_node *node, __u32 operation,
			      __u64 node_id)
{
	memset(node, 0, sizeof(*node));
	node->size = sizeof(*node);
	node->operation = operation;
	node->graph_id = GRAPH_ID;
	node->node_id = node_id;
	node->device_mask = AGI_LC_GRAPH_DEVICE_CPU;
	node->priority = 100;
	node->correlation = node_id;
}

static int expect_errno(int fd, struct agi_lc_graph_node *node, int expected,
			struct fault_result *result)
{
	int rc;

	errno = 0;
	rc = ioctl(fd, AGI_LC_GRAPH_NODE, node);
	result->checks++;
	if (rc >= 0 || errno != expected) {
		fprintf(stderr, "expected errno %d for operation=%u, rc=%d errno=%d\n",
			expected, node->operation, rc, errno);
		result->unexpected++;
		return -1;
	}
	result->expected_rejections++;
	return 0;
}

static int expect_state(int fd, struct agi_lc_graph_node *node,
			       __u32 state, struct fault_result *result)
{
	int rc;
	int error;

	errno = 0;
	rc = ioctl(fd, AGI_LC_GRAPH_NODE, node);
	error = errno;
	result->checks++;
	if (rc < 0 && !expected_event_errno(error)) {
		fprintf(stderr, "unexpected graph errno=%d operation=%u\n",
			error, node->operation);
		result->unexpected++;
		return -1;
	}
	if (node->state != state) {
		fprintf(stderr, "graph state=%u expected=%u operation=%u errno=%d\n",
			node->state, state, node->operation, error);
		result->unexpected++;
		return -1;
	}
	return 0;
}

int main(void)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_graph_node node;
	struct fault_result result = { 0 };
	int fd;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open");
		return 2;
	}
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 || !create.session_id) {
		perror("create");
		close(fd);
		return 2;
	}
	if (ioctl(fd, AGI_LC_ATTACH_TASK, 0) < 0) {
		perror("attach");
		close(fd);
		return 2;
	}

	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 1);
	node.size--;
	if (expect_errno(fd, &node, EINVAL, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 1);
	node.dependency_count = 1;
	node.dependencies[0] = 99;
	if (expect_errno(fd, &node, EINVAL, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 1);
	if (expect_state(fd, &node, AGI_LC_GRAPH_STATE_READY, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 1);
	if (expect_errno(fd, &node, EINVAL, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_GET, 99);
	if (expect_errno(fd, &node, ENOENT, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_COMPLETE, 1);
	if (expect_state(fd, &node, AGI_LC_GRAPH_STATE_COMPLETE, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_COMPLETE, 1);
	if (expect_errno(fd, &node, EINVAL, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_CANCEL, 1);
	if (expect_errno(fd, &node, EALREADY, &result) < 0)
		goto fail;

	node_init(&node, AGI_LC_GRAPH_NODE_GET, 1);
	if (expect_state(fd, &node, AGI_LC_GRAPH_STATE_COMPLETE, &result) < 0)
		goto fail;

	if (close(fd) < 0) {
		perror("close");
		return 2;
	}
	printf("FAISAL_GRAPH_FAULT_OK checks=%lu expected_rejections=%lu unexpected=%lu\n",
	       result.checks, result.expected_rejections, result.unexpected);
	return result.unexpected ? 1 : 0;

fail:
	close(fd);
	return 1;
}
