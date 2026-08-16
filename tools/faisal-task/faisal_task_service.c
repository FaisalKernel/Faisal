#define _GNU_SOURCE
#include "faisal_task_service.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct fts_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t record_size;
	uint64_t journal_sequence;
	uint64_t task_id;
	uint8_t task_digest[FTS_DIGEST_SIZE];
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return FTS_ERR_IO;
		}
		if (!written)
			return FTS_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return FTS_OK;
}

static int read_exact_or_eof(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t read_total = 0;

	while (read_total < length) {
		ssize_t received = read(fd, cursor + read_total,
					length - read_total);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			return FTS_ERR_IO;
		}
		if (!received)
			return read_total ? FTS_ERR_CORRUPT : 1;
		read_total += (size_t)received;
	}
	return FTS_OK;
}

static int digest_task(const struct fts_task *task,
		       uint8_t digest[FTS_DIGEST_SIZE])
{
	struct fts_task canonical = *task;
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = FTS_ERR_IO;

	if (!context)
		return FTS_ERR_IO;
	memset(canonical.objective_digest, 0, sizeof(canonical.objective_digest));
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, &canonical, sizeof(canonical)) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == FTS_DIGEST_SIZE)
		result = FTS_OK;
	EVP_MD_CTX_free(context);
	return result;
}

static uint64_t string_hash(const char *value)
{
	uint64_t hash = 1469598103934665603ULL;

	while (*value) {
		hash ^= (unsigned char)*value++;
		hash *= 1099511628211ULL;
	}
	return hash ? hash : 1;
}

static int copy_text(char *destination, size_t destination_size,
		     const char *source)
{
	size_t length;

	if (!destination || !destination_size || !source)
		return FTS_ERR_ARGUMENT;
	length = strnlen(source, destination_size);
	if (!length || length >= destination_size)
		return FTS_ERR_ARGUMENT;
	memcpy(destination, source, length + 1);
	return FTS_OK;
}

static int lock_service(struct fts_service *service)
{
	if (!service || !service->lock_initialized)
		return FTS_ERR_ARGUMENT;
	return pthread_mutex_lock(&service->lock) == 0 ? FTS_OK : FTS_ERR_STATE;
}

static void unlock_service(struct fts_service *service)
{
	(void)pthread_mutex_unlock(&service->lock);
}

static struct fts_task *find_task(struct fts_service *service, uint64_t task_id)
{
	size_t index;

	for (index = 0; index < service->task_count; index++)
		if (service->tasks[index].task_id == task_id)
			return &service->tasks[index];
	return NULL;
}

static const struct fts_task *find_task_const(const struct fts_service *service,
					       uint64_t task_id)
{
	size_t index;

	for (index = 0; index < service->task_count; index++)
		if (service->tasks[index].task_id == task_id)
			return &service->tasks[index];
	return NULL;
}

static struct fts_task *find_idempotency(struct fts_service *service,
					 const char *idempotency_key)
{
	uint64_t hash = string_hash(idempotency_key);
	size_t index;

	for (index = 0; index < service->task_count; index++)
		if (service->tasks[index].idempotency_hash == hash &&
		    strcmp(service->tasks[index].idempotency_key,
			   idempotency_key) == 0)
			return &service->tasks[index];
	return NULL;
}

static uint64_t backoff_ns(uint32_t retry_count)
{
	uint64_t seconds = 1ULL;
	uint32_t shift = retry_count > 20U ? 20U : retry_count;

	seconds <<= shift;
	if (seconds > FTS_MAX_BACKOFF_NS / 1000000000ULL)
		seconds = FTS_MAX_BACKOFF_NS / 1000000000ULL;
	return seconds * 1000000000ULL;
}

static int kernel_session_open(struct fts_service *service)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_info info = { .size = sizeof(info) };
	struct agi_lc_light_agent agent = {
		.size = sizeof(agent),
		.role = AGI_LC_LIGHT_AGENT_ROLE_PLANNER,
		.workload = AGI_LC_WORKLOAD_PLANNING,
		.correlation = 95001,
	};
	struct agi_lc_agent selected = { .size = sizeof(selected) };

	service->kernel_fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (service->kernel_fd < 0)
		return FTS_ERR_KERNEL;
	if (ioctl(service->kernel_fd, AGI_LC_GET_INFO, &info) < 0 ||
	    info.abi_version != AGI_LC_ABI_VERSION ||
	    ioctl(service->kernel_fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_LIGHT_AGENT_REGISTER, &agent) < 0 ||
	    !agent.agent_id || !agent.capability) {
		close(service->kernel_fd);
		service->kernel_fd = -1;
		return FTS_ERR_KERNEL;
	}
	selected.agent_id = agent.agent_id;
	selected.correlation = 95002;
	if (ioctl(service->kernel_fd, AGI_LC_SET_AGENT, &selected) < 0) {
		close(service->kernel_fd);
		service->kernel_fd = -1;
		return FTS_ERR_KERNEL;
	}
	service->session_id = create.session_id;
	service->agent_id = agent.agent_id;
	service->agent_capability = agent.capability;
	return FTS_OK;
}

static int append_task(struct fts_service *service, const struct fts_task *task)
{
	struct fts_disk_header header;
	struct fts_task disk_task = *task;
	uint8_t digest[FTS_DIGEST_SIZE];
	uint64_t journal_sequence = service->journal_sequence + 1;
	int result;

	disk_task.sequence = journal_sequence;
	result = digest_task(&disk_task, digest);
	if (result != FTS_OK)
		return result;
	memset(&header, 0, sizeof(header));
	header.magic = FTS_JOURNAL_MAGIC;
	header.version = FTS_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.record_size = sizeof(header) + sizeof(disk_task);
	header.journal_sequence = journal_sequence;
	header.task_id = disk_task.task_id;
	memcpy(header.task_digest, digest, sizeof(header.task_digest));
	result = write_all(service->journal_fd, &header, sizeof(header));
	if (result == FTS_OK)
		result = write_all(service->journal_fd, &disk_task, sizeof(disk_task));
	if (result == FTS_OK && fdatasync(service->journal_fd) < 0)
		result = FTS_ERR_IO;
	if (result == FTS_OK)
		service->journal_sequence = journal_sequence;
	return result;
}

static int apply_replayed_task(struct fts_service *service,
			       const struct fts_task *task)
{
	struct fts_task *existing = find_task(service, task->task_id);

	if (existing) {
		*existing = *task;
		return FTS_OK;
	}
	if (service->task_count >= FTS_MAX_TASKS)
		return FTS_ERR_FULL;
	service->tasks[service->task_count++] = *task;
	return FTS_OK;
}

static int replay_unlocked(struct fts_service *service)
{
	struct fts_disk_header header;
	uint64_t last_sequence = 0;
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FTS_ERR_IO;
	service->task_count = 0;
	service->journal_sequence = 0;
	service->next_task_id = 1;
	for (;;) {
		struct fts_task task;
		uint8_t digest[FTS_DIGEST_SIZE];

		result = read_exact_or_eof(service->journal_fd, &header,
					   sizeof(header));
		if (result == 1)
			break;
		if (result != FTS_OK || header.magic != FTS_JOURNAL_MAGIC ||
		    header.version != FTS_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    header.record_size != sizeof(header) + sizeof(task) ||
		    header.journal_sequence <= last_sequence || !header.task_id)
			return FTS_ERR_CORRUPT;
		result = read_exact_or_eof(service->journal_fd, &task, sizeof(task));
		if (result != FTS_OK || task.task_id != header.task_id ||
		    digest_task(&task, digest) != FTS_OK ||
		    memcmp(digest, header.task_digest, sizeof(digest)) != 0)
			return FTS_ERR_CORRUPT;
		if (task.dependency_count > FTS_MAX_DEPENDENCIES ||
		    task.max_retries > FTS_MAX_RETRIES ||
		    task.state < FTS_TASK_READY || task.state > FTS_TASK_DEAD_LETTER)
			return FTS_ERR_CORRUPT;
		result = apply_replayed_task(service, &task);
		if (result != FTS_OK)
			return result;
		last_sequence = header.journal_sequence;
		if (task.task_id >= service->next_task_id)
			service->next_task_id = task.task_id + 1;
	}
	service->journal_sequence = last_sequence;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FTS_ERR_IO;
	return FTS_OK;
}

int fts_replay(struct fts_service *service)
{
	int result;

	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	result = replay_unlocked(service);
	unlock_service(service);
	return result;
}

int fts_open(struct fts_service *service, const char *journal_path,
	     int require_kernel)
{
	int result;

	if (!service || !journal_path || !*journal_path ||
	    strlen(journal_path) >= sizeof(service->journal_path))
		return FTS_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->kernel_fd = -1;
	service->journal_fd = -1;
	service->require_kernel = require_kernel != 0;
	memcpy(service->journal_path, journal_path, strlen(journal_path) + 1);
	if (pthread_mutex_init(&service->lock, NULL) != 0)
		return FTS_ERR_STATE;
	service->lock_initialized = 1;
	result = kernel_session_open(service);
	if (result != FTS_OK && service->require_kernel)
		goto fail;
	if (result != FTS_OK)
		service->kernel_fd = -1;
	service->journal_fd = open(journal_path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC,
				0600);
	if (service->journal_fd < 0) {
		result = FTS_ERR_IO;
		goto fail;
	}
	result = replay_unlocked(service);
	if (result != FTS_OK)
		goto fail;
	return FTS_OK;
fail:
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	if (service->kernel_fd >= 0)
		close(service->kernel_fd);
	pthread_mutex_destroy(&service->lock);
	service->lock_initialized = 0;
	return result;
}

void fts_close(struct fts_service *service)
{
	if (!service || !service->lock_initialized)
		return;
	(void)pthread_mutex_lock(&service->lock);
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	if (service->kernel_fd >= 0)
		close(service->kernel_fd);
	service->journal_fd = -1;
	service->kernel_fd = -1;
	(void)pthread_mutex_unlock(&service->lock);
	pthread_mutex_destroy(&service->lock);
	service->lock_initialized = 0;
}

static int validate_dependencies(const struct fts_service *service,
				const uint32_t *dependency_ids,
				uint32_t dependency_count,
				uint64_t new_task_id)
{
	uint32_t index;

	if (dependency_count > FTS_MAX_DEPENDENCIES)
		return FTS_ERR_ARGUMENT;
	for (index = 0; index < dependency_count; index++) {
		uint32_t inner;

		if (!dependency_ids[index] || dependency_ids[index] == new_task_id ||
		    !find_task_const(service, dependency_ids[index]))
			return FTS_ERR_DEPENDENCY;
		for (inner = 0; inner < index; inner++)
			if (dependency_ids[inner] == dependency_ids[index])
				return FTS_ERR_CONFLICT;
	}
	return FTS_OK;
}

int fts_submit(struct fts_service *service, uint64_t goal_id,
	       const char *idempotency_key, const char *objective,
	       uint64_t deadline_ns, uint64_t cpu_budget_ns,
	       uint64_t money_budget_micro, uint32_t priority,
	       uint32_t risk_class, uint32_t max_retries,
	       const uint32_t *dependency_ids, uint32_t dependency_count,
	       struct fts_task *out)
{
	struct fts_task task;
	struct fts_task *existing;
	int result;

	if (!service || !idempotency_key || !objective || !out || !goal_id ||
	    !deadline_ns || priority > 1024U || risk_class > 1000000U ||
	    max_retries > FTS_MAX_RETRIES)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	existing = find_idempotency(service, idempotency_key);
	if (existing) {
		result = strcmp(existing->objective, objective) == 0 ? FTS_OK :
			FTS_ERR_CONFLICT;
		if (result == FTS_OK)
			*out = *existing;
		goto out_unlock;
	}
	if (service->task_count >= FTS_MAX_TASKS) {
		result = FTS_ERR_FULL;
		goto out_unlock;
	}
	memset(&task, 0, sizeof(task));
	task.task_id = service->next_task_id++;
	task.goal_id = goal_id;
	task.created_at_ns = 1;
	task.updated_at_ns = 1;
	task.deadline_ns = deadline_ns;
	task.cpu_budget_ns = cpu_budget_ns;
	task.money_budget_micro = money_budget_micro;
	task.idempotency_hash = string_hash(idempotency_key);
	task.state = FTS_TASK_READY;
	task.max_retries = max_retries;
	task.priority = priority;
	task.risk_class = risk_class;
	task.dependency_count = dependency_count;
	task.completed_dependencies = dependency_count == 0 ? 0 : 0;
	result = copy_text(task.idempotency_key, sizeof(task.idempotency_key),
			   idempotency_key);
	if (result == FTS_OK)
		result = copy_text(task.objective, sizeof(task.objective), objective);
	if (result == FTS_OK)
		result = validate_dependencies(service, dependency_ids,
					dependency_count, task.task_id);
	if (result != FTS_OK)
		goto out_unlock;
	if (dependency_count)
		memcpy(task.dependency_ids, dependency_ids,
		       dependency_count * sizeof(task.dependency_ids[0]));
	if (digest_task(&task, task.objective_digest) != FTS_OK) {
		result = FTS_ERR_IO;
		goto out_unlock;
	}
	result = append_task(service, &task);
	if (result == FTS_OK) {
		task.sequence = service->journal_sequence;
		service->tasks[service->task_count++] = task;
		*out = task;
	}
out_unlock:
	unlock_service(service);
	return result;
}

static int dependencies_ready(const struct fts_service *service,
			       const struct fts_task *task)
{
	uint32_t index;
	uint32_t completed = 0;

	for (index = 0; index < task->dependency_count; index++) {
		const struct fts_task *dependency =
			find_task_const(service, task->dependency_ids[index]);

		if (!dependency)
			return FTS_ERR_DEPENDENCY;
		if (dependency->state == FTS_TASK_CANCELLED ||
		    dependency->state == FTS_TASK_DEAD_LETTER ||
		    dependency->state == FTS_TASK_FAILED)
			return FTS_ERR_STOPPED;
		if (dependency->state != FTS_TASK_SUCCEEDED)
			continue;
		completed++;
	}
	return completed == task->dependency_count ? FTS_OK : FTS_ERR_DEPENDENCY;
}

static int check_limits(const struct fts_task *task, uint64_t now_ns)
{
	if (task->deadline_ns && now_ns >= task->deadline_ns)
		return FTS_ERR_DEADLINE;
	if (task->cpu_budget_ns && task->consumed_cpu_ns >= task->cpu_budget_ns)
		return FTS_ERR_BUDGET;
	if (task->money_budget_micro &&
	    task->consumed_money_micro >= task->money_budget_micro)
		return FTS_ERR_BUDGET;
	return FTS_OK;
}

int fts_claim(struct fts_service *service, uint64_t task_id,
	      uint64_t now_ns, uint64_t lease_ns, struct fts_task *out)
{
	struct fts_task *task;
	struct fts_task candidate;
	int result;

	if (!service || !out || !task_id || !now_ns || !lease_ns ||
	    lease_ns > FTS_MAX_LEASE_NS)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	task = find_task(service, task_id);
	if (!task) {
		result = FTS_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if ((task->state == FTS_TASK_LEASED || task->state == FTS_TASK_RUNNING) &&
	    task->lease_until_ns <= now_ns) {
		candidate = *task;
		candidate.lease_until_ns = 0;
		candidate.lease_generation++;
		if (!candidate.max_retries ||
		    candidate.retry_count >= candidate.max_retries) {
			candidate.state = FTS_TASK_DEAD_LETTER;
			candidate.stop_reason = FTS_STOP_NEGATIVE_VALUE;
		} else {
			candidate.state = FTS_TASK_READY;
		}
		result = append_task(service, &candidate);
		if (result != FTS_OK)
			goto out_unlock;
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		if (candidate.state == FTS_TASK_DEAD_LETTER) {
			result = FTS_ERR_STOPPED;
			goto out_unlock;
		}
	}
	if (task->state != FTS_TASK_READY && task->state != FTS_TASK_RETRY_WAIT) {
		result = FTS_ERR_STATE;
		goto out_unlock;
	}
	if (task->state == FTS_TASK_RETRY_WAIT && task->next_attempt_ns > now_ns) {
		result = FTS_ERR_LEASE;
		goto out_unlock;
	}
	result = check_limits(task, now_ns);
	if (result != FTS_OK) {
		candidate = *task;
		candidate.stop_reason = result == FTS_ERR_DEADLINE ?
			FTS_STOP_DEADLINE : FTS_STOP_BUDGET;
		candidate.state = FTS_TASK_DEAD_LETTER;
		if (append_task(service, &candidate) == FTS_OK) {
			candidate.sequence = service->journal_sequence;
			*task = candidate;
		}
		goto out_unlock;
	}
	result = dependencies_ready(service, task);
	if (result != FTS_OK)
		goto out_unlock;
	candidate = *task;
	candidate.state = FTS_TASK_LEASED;
	candidate.lease_until_ns = now_ns + lease_ns;
	candidate.lease_generation++;
	candidate.updated_at_ns = now_ns;
	result = append_task(service, &candidate);
	if (result == FTS_OK) {
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int fts_heartbeat(struct fts_service *service, uint64_t task_id,
		  uint64_t lease_generation, uint64_t now_ns,
		  uint64_t extend_ns, struct fts_task *out)
{
	struct fts_task *task;
	struct fts_task candidate;
	int result;

	if (!service || !out || !task_id || !lease_generation || !now_ns ||
	    !extend_ns || extend_ns > FTS_MAX_LEASE_NS)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	task = find_task(service, task_id);
	if (!task) {
		result = FTS_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if ((task->state != FTS_TASK_LEASED && task->state != FTS_TASK_RUNNING) ||
	    task->lease_generation != lease_generation ||
	    task->lease_until_ns <= now_ns) {
		result = FTS_ERR_LEASE;
		goto out_unlock;
	}
	candidate = *task;
	candidate.state = FTS_TASK_RUNNING;
	candidate.lease_until_ns = now_ns + extend_ns;
	candidate.updated_at_ns = now_ns;
	result = append_task(service, &candidate);
	if (result == FTS_OK) {
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int fts_complete(struct fts_service *service, uint64_t task_id,
		 uint64_t lease_generation, uint64_t now_ns,
		 const char *result_text, uint64_t cpu_used_ns,
		 uint64_t money_used_micro, struct fts_task *out)
{
	struct fts_task *task;
	struct fts_task candidate;
	int result;

	if (!service || !out || !task_id || !lease_generation || !now_ns ||
	    !result_text)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	task = find_task(service, task_id);
	if (!task) {
		result = FTS_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if ((task->state != FTS_TASK_LEASED && task->state != FTS_TASK_RUNNING) ||
	    task->lease_generation != lease_generation ||
	    task->lease_until_ns <= now_ns) {
		result = FTS_ERR_LEASE;
		goto out_unlock;
	}
	if (task->cpu_budget_ns &&
	    cpu_used_ns > task->cpu_budget_ns - task->consumed_cpu_ns) {
		result = FTS_ERR_BUDGET;
		goto out_unlock;
	}
	if (task->money_budget_micro &&
	    money_used_micro > task->money_budget_micro -
				       task->consumed_money_micro) {
		result = FTS_ERR_BUDGET;
		goto out_unlock;
	}
	candidate = *task;
	if (copy_text(candidate.result, sizeof(candidate.result), result_text) != FTS_OK) {
		result = FTS_ERR_ARGUMENT;
		goto out_unlock;
	}
	candidate.state = FTS_TASK_SUCCEEDED;
	candidate.stop_reason = FTS_STOP_SUCCESS;
	candidate.lease_until_ns = 0;
	candidate.consumed_cpu_ns += cpu_used_ns;
	candidate.consumed_money_micro += money_used_micro;
	candidate.updated_at_ns = now_ns;
	result = append_task(service, &candidate);
	if (result == FTS_OK) {
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int fts_fail(struct fts_service *service, uint64_t task_id,
	    uint64_t lease_generation, uint64_t now_ns,
	    uint32_t failure_class, const char *failure_text,
	    int retryable, struct fts_task *out)
{
	struct fts_task *task;
	struct fts_task candidate;
	int result;

	if (!service || !out || !task_id || !lease_generation || !now_ns ||
	    !failure_class || !failure_text || failure_class > FTS_FAILURE_ECONOMIC)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	task = find_task(service, task_id);
	if (!task) {
		result = FTS_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if ((task->state != FTS_TASK_LEASED && task->state != FTS_TASK_RUNNING) ||
	    task->lease_generation != lease_generation ||
	    task->lease_until_ns <= now_ns) {
		result = FTS_ERR_LEASE;
		goto out_unlock;
	}
	candidate = *task;
	if (copy_text(candidate.failure, sizeof(candidate.failure), failure_text) != FTS_OK) {
		result = FTS_ERR_ARGUMENT;
		goto out_unlock;
	}
	candidate.failure_class = failure_class;
	candidate.lease_until_ns = 0;
	candidate.updated_at_ns = now_ns;
	if (retryable && candidate.retry_count < candidate.max_retries) {
		candidate.retry_count++;
		candidate.state = FTS_TASK_RETRY_WAIT;
		candidate.next_attempt_ns = now_ns + backoff_ns(candidate.retry_count);
		candidate.stop_reason = FTS_STOP_NONE;
		result = FTS_OK;
	} else {
		candidate.state = retryable ? FTS_TASK_DEAD_LETTER : FTS_TASK_FAILED;
		candidate.stop_reason = retryable ? FTS_STOP_NEGATIVE_VALUE : FTS_STOP_NONE;
		result = retryable ? FTS_ERR_STOPPED : FTS_OK;
	}
	if (append_task(service, &candidate) == FTS_OK) {
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		*out = candidate;
	} else {
		result = FTS_ERR_IO;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int fts_cancel(struct fts_service *service, uint64_t task_id,
	       uint32_t stop_reason, struct fts_task *out)
{
	struct fts_task *task;
	struct fts_task candidate;
	int result;

	if (!service || !out || !task_id || stop_reason == FTS_STOP_NONE ||
	    stop_reason > FTS_STOP_CANCELLED)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	task = find_task(service, task_id);
	if (!task) {
		result = FTS_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (task->state == FTS_TASK_SUCCEEDED || task->state == FTS_TASK_FAILED ||
	    task->state == FTS_TASK_CANCELLED || task->state == FTS_TASK_DEAD_LETTER) {
		result = FTS_ERR_STATE;
		goto out_unlock;
	}
	candidate = *task;
	candidate.state = FTS_TASK_CANCELLED;
	candidate.stop_reason = stop_reason;
	candidate.lease_until_ns = 0;
	result = append_task(service, &candidate);
	if (result == FTS_OK) {
		candidate.sequence = service->journal_sequence;
		*task = candidate;
		*out = candidate;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int fts_query(const struct fts_service *service, uint64_t task_id,
	      struct fts_task *out)
{
	struct fts_service *mutable_service = (struct fts_service *)service;
	const struct fts_task *task;
	int result;

	if (!service || !out || !task_id)
		return FTS_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != FTS_OK)
		return result;
	task = find_task_const(service, task_id);
	if (!task)
		result = FTS_ERR_NOT_FOUND;
	else {
		*out = *task;
		result = FTS_OK;
	}
	unlock_service(mutable_service);
	return result;
}

int fts_recover_expired(struct fts_service *service, uint64_t now_ns,
			uint32_t *recovered, uint32_t *dead_lettered)
{
	size_t index;
	int result;

	if (!service || !now_ns || !recovered || !dead_lettered)
		return FTS_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != FTS_OK)
		return result;
	*recovered = 0;
	*dead_lettered = 0;
	for (index = 0; index < service->task_count; index++) {
		struct fts_task candidate = service->tasks[index];

		if ((candidate.state != FTS_TASK_LEASED &&
		     candidate.state != FTS_TASK_RUNNING) ||
		    candidate.lease_until_ns > now_ns)
			continue;
		candidate.lease_until_ns = 0;
		candidate.lease_generation++;
		candidate.updated_at_ns = now_ns;
		if (!candidate.max_retries ||
		    candidate.retry_count >= candidate.max_retries) {
			candidate.state = FTS_TASK_DEAD_LETTER;
			candidate.stop_reason = FTS_STOP_NEGATIVE_VALUE;
			(*dead_lettered)++;
		} else {
			candidate.state = FTS_TASK_READY;
			(*recovered)++;
		}
		result = append_task(service, &candidate);
		if (result != FTS_OK)
			break;
		candidate.sequence = service->journal_sequence;
		service->tasks[index] = candidate;
	}
	unlock_service(service);
	return result;
}

int fts_test_corrupt_tail(const struct fts_service *service)
{
	struct fts_service *mutable_service = (struct fts_service *)service;
	unsigned char corrupt = 0xff;
	int result;

	if (!service)
		return FTS_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != FTS_OK)
		return result;
	if (write_all(mutable_service->journal_fd, &corrupt, sizeof(corrupt)) ==
	    FTS_OK && fdatasync(mutable_service->journal_fd) == 0)
		result = FTS_OK;
	else
		result = FTS_ERR_IO;
	unlock_service(mutable_service);
	return result;
}
