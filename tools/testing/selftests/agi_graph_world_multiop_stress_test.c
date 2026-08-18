#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define GRAPH_ID 0x46414953414c199ULL
#define COMPLETE_NODES 24U
#define CANCEL_NODES 8U

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M199_FAIL:%s rc=%d errno=%d\n", what, rc, errno);
	return 1;
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
	node->queue_class = 1;
	node->correlation = 199000 + node_id;
}

static int world_sync(int fd, __u64 *last_ack, unsigned int *queries)
{
	struct agi_lc_world_sync sync;

	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_QUERY;
	sync.correlation = 199500 + *queries;
	if (ioctl(fd, AGI_LC_WORLD_SYNC, &sync) < 0 || !sync.consumer_id)
		return -1;
	(*queries)++;
	if (sync.newest_sequence > *last_ack) {
		struct agi_lc_world_sync ack;

		memset(&ack, 0, sizeof(ack));
		ack.size = sizeof(ack);
		ack.operation = AGI_LC_WORLD_SYNC_ACK;
		ack.consumer_id = sync.consumer_id;
		ack.ack_sequence = sync.newest_sequence;
		ack.correlation = 199600 + *queries;
		if (ioctl(fd, AGI_LC_WORLD_SYNC, &ack) < 0)
			return -1;
		*last_ack = ack.ack_sequence;
	}
	return 0;
}

int main(void)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_world_subscription subscription;
	struct agi_lc_graph_node node;
	__u64 last_ack = 0;
	unsigned int queries = 0;
	unsigned int i;
	int fd;

	fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return fail("open", fd);
	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 || !create.session_id)
		return fail("create", fd);
	if (ioctl(fd, AGI_LC_ATTACH_TASK, 0) < 0)
		return fail("attach", fd);

	memset(&subscription, 0, sizeof(subscription));
	subscription.size = sizeof(subscription);
	subscription.class_mask = (1ULL << AGI_LC_WORLD_EVENT_MAX) - 1;
	subscription.min_priority = AGI_LC_WORLD_PRIORITY_LOW;
	subscription.queue_policy = AGI_LC_WORLD_QUEUE_DROP_LOW;
	subscription.correlation = 199001;
	if (ioctl(fd, AGI_LC_SET_WORLD_SUBSCRIPTION, &subscription) < 0)
		return fail("world subscription", fd);

	for (i = 1; i <= COMPLETE_NODES; i++) {
		node_init(&node, AGI_LC_GRAPH_NODE_CREATE, i);
		if (i > 1) {
			node.dependency_count = 1;
			node.dependencies[0] = i - 1;
		}
		if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
		    node.state != AGI_LC_GRAPH_STATE_READY)
			return fail("chained graph create", i);
		node_init(&node, AGI_LC_GRAPH_NODE_GET, i);
		if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
		    node.state != AGI_LC_GRAPH_STATE_READY)
			return fail("graph get before complete", i);
		node_init(&node, AGI_LC_GRAPH_NODE_COMPLETE, i);
		if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
		    node.state != AGI_LC_GRAPH_STATE_COMPLETE)
			return fail("chained graph complete", i);
		if ((i % 4) == 0 && world_sync(fd, &last_ack, &queries) < 0)
			return fail("interleaved world sync", i);
	}
	printf("M199_GRAPH_CHAIN_OK nodes=%u world_queries=%u\n",
	       COMPLETE_NODES, queries);

	for (i = 1; i <= CANCEL_NODES; i++) {
		__u64 node_id = COMPLETE_NODES + i;

		node_init(&node, AGI_LC_GRAPH_NODE_CREATE, node_id);
		if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
		    node.state != AGI_LC_GRAPH_STATE_READY)
			return fail("cancellation graph create", i);
		node_init(&node, AGI_LC_GRAPH_NODE_CANCEL, node_id);
		if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) < 0 ||
		    node.state != AGI_LC_GRAPH_STATE_CANCELLED)
			return fail("graph cancel", i);
		if ((i % 2) == 0 && world_sync(fd, &last_ack, &queries) < 0)
			return fail("cancellation world sync", i);
	}
	printf("M199_GRAPH_CANCEL_OK nodes=%u world_queries=%u\n",
	       CANCEL_NODES, queries);

	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 0x1000);
	node.size--;
	errno = 0;
	if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) == 0 || errno != EINVAL)
		return fail("malformed graph accepted", 0);
	node_init(&node, AGI_LC_GRAPH_NODE_CREATE, 0x1001);
	node.dependency_count = AGI_LC_GRAPH_MAX_DEPS + 1;
	errno = 0;
	if (ioctl(fd, AGI_LC_GRAPH_NODE, &node) == 0 || errno != EINVAL)
		return fail("dependency overflow accepted", 0);
	printf("M199_GRAPH_FAULT_GUARD_OK cases=2\n");

	if (world_sync(fd, &last_ack, &queries) < 0)
		return fail("final world sync", 0);
	printf("M199_WORLD_SYNC_INTERLEAVE_OK queries=%u ack=%llu\n", queries,
	       (unsigned long long)last_ack);
	printf("M199_SELFTEST_EXIT=0\n");
	close(fd);
	return 0;
}
