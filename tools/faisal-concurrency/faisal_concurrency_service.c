#include "faisal_concurrency_service.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct m81_worker {
	unsigned int index;
	int fd;
	struct agi_lc_light_agent source;
	struct agi_lc_light_agent target;
	struct agi_lc_ipc_channel channel;
	pthread_barrier_t ready;
	pthread_t consumer;
	atomic_int consumer_rc;
	atomic_int producer_done;
	uint32_t malformed_rejections;
	uint32_t capability_denials;
	uint32_t cancellation_passes;
	uint32_t live_sent;
	uint32_t live_received;
	uint32_t queue_pressure_events;
	uint32_t randomized_inputs;
	uint32_t random_state;
	int rc;
};

static int expect_errno(int expected)
{
	return errno == expected ? 0 : -1;
}

static int select_agent(int fd, uint64_t agent_id, uint64_t correlation)
{
	struct agi_lc_agent agent;
	memset(&agent, 0, sizeof(agent));
	agent.size = sizeof(agent);
	agent.agent_id = agent_id;
	agent.correlation = correlation;
	return ioctl(fd, AGI_LC_SET_AGENT, &agent);
}

static int register_agents(struct m81_worker *worker)
{
	struct agi_lc_create create;
	struct agi_lc_light_agent source;
	struct agi_lc_light_agent target;

	memset(&create, 0, sizeof(create));
	create.size = sizeof(create);
	if (ioctl(worker->fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(worker->fd, AGI_LC_ATTACH_TASK) < 0)
		return -1;

	memset(&source, 0, sizeof(source));
	source.size = sizeof(source);
	source.role = AGI_LC_LIGHT_AGENT_ROLE_PLANNER;
	source.workload = AGI_LC_WORKLOAD_PLANNING;
	source.priority = 256;
	source.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM;
	source.correlation = 81000 + worker->index * 10;
	if (ioctl(worker->fd, AGI_LC_LIGHT_AGENT_REGISTER, &source) < 0 ||
	    !source.agent_id || !source.capability)
		return -1;

	if (select_agent(worker->fd, source.agent_id, 81002 + worker->index * 10) < 0)
		return -1;
	memset(&target, 0, sizeof(target));
	target.size = sizeof(target);
	target.parent_agent = source.agent_id;
	target.parent_capability = source.capability;
	target.role = AGI_LC_LIGHT_AGENT_ROLE_VERIFIER;
	target.workload = AGI_LC_WORKLOAD_VERIFICATION;
	target.priority = 128;
	target.resource_mask = AGI_LC_RESOURCE_CPU | AGI_LC_RESOURCE_RAM;
	target.correlation = 81001 + worker->index * 10;
	if (ioctl(worker->fd, AGI_LC_LIGHT_AGENT_REGISTER, &target) < 0 ||
	    !target.agent_id || !target.capability ||
	    target.agent_id == source.agent_id)
		return -1;
	worker->source = source;
	worker->target = target;
	return 0;
}

static int create_channel(struct m81_worker *worker)
{
	struct agi_lc_ipc_channel channel;
	memset(&channel, 0, sizeof(channel));
	channel.size = sizeof(channel);
	channel.source_agent = worker->source.agent_id;
	channel.source_capability = worker->source.capability;
	channel.target_agent = worker->target.agent_id;
	channel.target_capability = worker->target.capability;
	channel.max_queue = M81_QUEUE_MAX;
	channel.correlation = 81003 + worker->index * 10;
	if (ioctl(worker->fd, AGI_LC_IPC_CHANNEL_CREATE, &channel) < 0 ||
	    !channel.channel_id || !channel.channel_capability)
		return -1;
	worker->channel = channel;
	return 0;
}

static uint32_t next_random(struct m81_worker *worker)
{
	uint32_t value = worker->random_state;
	value ^= value << 13;
	value ^= value >> 17;
	value ^= value << 5;
	worker->random_state = value;
	return value;
}

static void init_message(struct m81_worker *worker,
				 struct agi_lc_ipc_message *message,
				 uint32_t flags, uint32_t type, uint32_t sequence,
				 uint64_t correlation)
{
	char payload[64];
	uint32_t random_value;
	int length;

		memset(message, 0, sizeof(*message));
		message->size = sizeof(*message);
			random_value = next_random(worker);
	message->flags = flags;
	message->priority = random_value & AGI_LC_IPC_PRIORITY_MAX;
	message->type = type + (random_value & 1U);
	message->schema = 1 + ((random_value >> 1) & 3U);

		message->channel_id = worker->channel.channel_id;
		message->channel_capability = worker->channel.channel_capability;
		message->sender_agent = worker->source.agent_id;
		message->sender_capability = worker->source.capability;
		message->target_agent = worker->target.agent_id;
		message->target_capability = worker->target.capability;
		message->correlation = correlation;
		message->timeout_ns = 50000000ULL;
			snprintf(payload, sizeof(payload), "m81-w%u-%u-%08x", worker->index,
		 sequence, random_value);
	length = 8 + (int)((random_value >> 5) & 31U);
	if (length >= (int)sizeof(payload))
		length = (int)sizeof(payload) - 1;
	for (int i = 0; i < length; i++)
		payload[i] = (char)('a' + ((random_value + (uint32_t)i * 13U) % 26U));
	message->length = (uint32_t)length;
	memcpy(message->payload, payload, (size_t)length);
	worker->randomized_inputs++;

}

static int malformed_validation(struct m81_worker *worker)
{
	struct agi_lc_ipc_message message;
	unsigned int i;
	for (i = 0; i < M81_MALFORMED_CASES; i++) {
		memset(&message, 0, sizeof(message));
		message.size = sizeof(message) - 1;
		message.correlation = 81100 + worker->index * 100 + i;
		if (ioctl(worker->fd, AGI_LC_IPC_SEND, &message) == 0 ||
		    expect_errno(EINVAL))
			return -1;
		worker->malformed_rejections++;
	}
	return 0;
}

static int capability_validation(struct m81_worker *worker)
{
	struct agi_lc_ipc_message message;
	init_message(worker, &message, AGI_LC_IPC_MSG_NONBLOCK, 2, 1,
		     81200 + worker->index);
	message.sender_capability ^= 1ULL;
	if (ioctl(worker->fd, AGI_LC_IPC_SEND, &message) == 0 ||
	    expect_errno(EACCES))
		return -1;
	worker->capability_denials++;
	return 0;
}

static int cancellation_validation(struct m81_worker *worker)
{
	struct agi_lc_ipc_message messages[M81_CANCEL_MESSAGES];
	struct agi_lc_ipc_cancel cancel;
	unsigned int i;
	memset(messages, 0, sizeof(messages));
	for (i = 0; i < M81_CANCEL_MESSAGES; i++) {
		init_message(worker, &messages[i], AGI_LC_IPC_MSG_NONBLOCK, 3, i,
			     81300 + worker->index * 100 + i);
		if (ioctl(worker->fd, AGI_LC_IPC_SEND, &messages[i]) < 0)
			return -1;
	}
	for (i = 0; i < M81_CANCEL_MESSAGES; i += 2) {
		memset(&cancel, 0, sizeof(cancel));
		cancel.size = sizeof(cancel);
		cancel.flags = AGI_LC_CANCEL_NONBLOCK;
		cancel.channel_id = worker->channel.channel_id;
		cancel.channel_capability = worker->channel.channel_capability;
		cancel.sender_agent = worker->source.agent_id;
		cancel.sender_capability = worker->source.capability;
		cancel.message_id = messages[i].message_id;
		cancel.correlation = 81400 + worker->index * 100 + i;
		if (ioctl(worker->fd, AGI_LC_IPC_CANCEL, &cancel) < 0 ||
		    cancel.status != -ECANCELED)
			return -1;
		worker->cancellation_passes++;
	}
	return 0;
}

static int receive_one(struct m81_worker *worker, uint32_t *received)
{
	struct agi_lc_ipc_message message;
	memset(&message, 0, sizeof(message));
	message.size = sizeof(message);
	message.channel_id = worker->channel.channel_id;
	message.channel_capability = worker->channel.channel_capability;
	message.target_agent = worker->target.agent_id;
	message.target_capability = worker->target.capability;
	message.timeout_ns = 100000000ULL;
	message.correlation = 81500 + worker->index * 100 + *received;
	if (ioctl(worker->fd, AGI_LC_IPC_RECV, &message) < 0)
		return errno == EAGAIN || errno == ETIMEDOUT ? 1 : -1;
	if (!message.message_id || !message.length || message.type < 3 ||
	    message.sender_agent != worker->source.agent_id ||
	    message.target_agent != worker->target.agent_id)
		return -1;
	(*received)++;
	return 0;
}

static void *consumer_main(void *arg)
{
	struct m81_worker *worker = arg;
	uint32_t received = 0;
	uint32_t expected = M81_CANCEL_MESSAGES / 2 + M81_LIVE_MESSAGES;
	struct agi_lc_ipc_message denied;
	int rc = 0;

	if (ioctl(worker->fd, AGI_LC_ATTACH_TASK) < 0 ||
	    select_agent(worker->fd, worker->target.agent_id,
			 81600 + worker->index) < 0)
		rc = -1;
	if (!rc) {
		memset(&denied, 0, sizeof(denied));
		denied.size = sizeof(denied);
		denied.channel_id = worker->channel.channel_id;
		denied.channel_capability = worker->channel.channel_capability ^ 1ULL;
		denied.target_agent = worker->target.agent_id;
		denied.target_capability = worker->target.capability;
		denied.flags = AGI_LC_IPC_MSG_NONBLOCK;
		denied.correlation = 81601 + worker->index;
		if (ioctl(worker->fd, AGI_LC_IPC_RECV, &denied) == 0 ||
		    expect_errno(EACCES))
			rc = -1;
		else
			worker->capability_denials++;
	}
	pthread_barrier_wait(&worker->ready);
	while (!rc && received < expected) {
		int step = receive_one(worker, &received);
		if (step < 0) {
			rc = -1;
			break;
		}
		if (step > 0) {
			if (atomic_load_explicit(&worker->producer_done,
						memory_order_acquire)) {
				usleep(1000);
				step = receive_one(worker, &received);
				if (step > 0 || step < 0)
					rc = -1;
			}
		}
	}
	worker->live_received = received >= M81_CANCEL_MESSAGES / 2 ?
		received - M81_CANCEL_MESSAGES / 2 : 0;
	atomic_store_explicit(&worker->consumer_rc, rc, memory_order_release);
	return NULL;
}

static int live_validation(struct m81_worker *worker)
{
	uint32_t sent = 0;
	unsigned int attempts;
	while (sent < M81_LIVE_MESSAGES) {
		struct agi_lc_ipc_message message;
		init_message(worker, &message, AGI_LC_IPC_MSG_NONBLOCK, 4, sent,
			     81700 + worker->index * 100 + sent);
		for (attempts = 0; attempts < 10000; attempts++) {
			if (ioctl(worker->fd, AGI_LC_IPC_SEND, &message) == 0)
				break;
			if (errno != EAGAIN) {
				fprintf(stderr, "M81_SEND_FAIL worker=%u sent=%u errno=%d\n",
					worker->index, sent, errno);
				return -1;
			}
			worker->queue_pressure_events++;
			usleep(500);
		}
		if (attempts == 10000)
			return -1;
		sent++;
		worker->live_sent++;
	}
	return 0;
}

static void close_channel(struct m81_worker *worker)
{
	struct agi_lc_ipc_channel close_request;
	memset(&close_request, 0, sizeof(close_request));
	close_request.size = sizeof(close_request);
	close_request.channel_id = worker->channel.channel_id;
	close_request.channel_capability = worker->channel.channel_capability;
	close_request.source_agent = worker->source.agent_id;
	close_request.source_capability = worker->source.capability;
	close_request.correlation = 81800 + worker->index;
	(void)ioctl(worker->fd, AGI_LC_IPC_CHANNEL_CLOSE, &close_request);
}

static void *worker_main(void *arg)
{
	struct m81_worker *worker = arg;
	worker->random_state = 0x9e3779b9U ^ (worker->index * 0x45d9f3bU + 1U);
	worker->fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (worker->fd < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=open errno=%d\n", worker->index, errno);
		worker->rc = -1;
		return NULL;
	}
	if (register_agents(worker) < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=agents errno=%d\n", worker->index, errno);
		worker->rc = -1;
		close(worker->fd);
		return NULL;
	}
	if (create_channel(worker) < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=channel errno=%d\n", worker->index, errno);
		worker->rc = -1;
		close(worker->fd);
		return NULL;
	}
	if (malformed_validation(worker) < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=malformed errno=%d\n", worker->index, errno);
		worker->rc = -1;
		close_channel(worker);
		close(worker->fd);
		return NULL;
	}
	if (capability_validation(worker) < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=capability errno=%d\n", worker->index, errno);
		worker->rc = -1;
		close_channel(worker);
		close(worker->fd);
		return NULL;
	}
	if (cancellation_validation(worker) < 0) {
		fprintf(stderr, "M81_SETUP_FAIL worker=%u stage=cancellation errno=%d\n", worker->index, errno);
		worker->rc = -1;
		close_channel(worker);
		close(worker->fd);
		return NULL;
	}
	atomic_init(&worker->consumer_rc, -1);
	atomic_init(&worker->producer_done, 0);
	if (pthread_barrier_init(&worker->ready, NULL, 2) != 0 ||
	    pthread_create(&worker->consumer, NULL, consumer_main, worker) != 0) {
		worker->rc = -1;
		close_channel(worker);
		close(worker->fd);
		return NULL;
	}
	pthread_barrier_wait(&worker->ready);
	if (live_validation(worker) < 0)
		worker->rc = -1;
	atomic_store_explicit(&worker->producer_done, 1, memory_order_release);
	pthread_join(worker->consumer, NULL);
	if (atomic_load_explicit(&worker->consumer_rc, memory_order_acquire) != 0 ||
	    worker->live_received != M81_LIVE_MESSAGES)
		worker->rc = -1;
	pthread_barrier_destroy(&worker->ready);
	close_channel(worker);
	close(worker->fd);
	return NULL;
}

int m81_run(struct m81_report *report)
{
	struct m81_worker workers[M81_WORKERS];
	pthread_t threads[M81_WORKERS];
	unsigned int i;
	int rc = 0;
	if (!report)
		return -1;
	memset(report, 0, sizeof(*report));
	memset(workers, 0, sizeof(workers));
	for (i = 0; i < M81_WORKERS; i++) {
		workers[i].index = i;
		workers[i].fd = -1;
		if (pthread_create(&threads[i], NULL, worker_main, &workers[i]) != 0)
			rc = -1;
	}
	for (i = 0; i < M81_WORKERS; i++)
		pthread_join(threads[i], NULL);
	for (i = 0; i < M81_WORKERS; i++) {
		if (workers[i].rc != 0)
			report->failures++;
		else
			report->worker_passes++;
		report->malformed_rejections += workers[i].malformed_rejections;
		report->capability_denials += workers[i].capability_denials;
		report->cancellation_passes += workers[i].cancellation_passes;
		report->live_messages_sent += workers[i].live_sent;
		report->live_messages_received += workers[i].live_received;
		report->queue_pressure_events += workers[i].queue_pressure_events;
		report->randomized_inputs += workers[i].randomized_inputs;
	}
	report->workers = M81_WORKERS;
	return rc || report->failures ? -1 : 0;
}
