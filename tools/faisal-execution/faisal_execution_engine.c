#define _GNU_SOURCE
#include "faisal_execution_engine.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct fex_record_header {
	uint32_t magic;
	uint16_t version;
	uint16_t kind;
	uint32_t size;
	uint64_t sequence;
};

enum fex_record_kind {
	FEX_RECORD_OBJECTIVE = 1,
	FEX_RECORD_NODE = 2,
	FEX_RECORD_CHECKPOINT = 3,
	FEX_RECORD_WORKER = 4
};

static int write_record(struct fex_service *service, uint16_t kind,
			const void *payload, uint32_t size);

static struct fex_worker *find_worker(struct fex_service *service, uint64_t task_id)
{
	size_t i;

	for (i = 0; i < service->worker_count; i++)
		if (service->workers[i].task_id == task_id)
			return &service->workers[i];
	return NULL;
}

static int persist_worker(struct fex_service *service,
				 const struct fex_worker *worker)
{
	return write_record(service, FEX_RECORD_WORKER, worker, sizeof(*worker));
}

static void digest_bytes(const void *data, size_t size,
			 uint8_t digest[FEX_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int length = 0;

	if (!ctx || !EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
	    !EVP_DigestUpdate(ctx, data, size) ||
	    !EVP_DigestFinal_ex(ctx, digest, &length) ||
	    length != FEX_DIGEST_SIZE)
		memset(digest, 0, FEX_DIGEST_SIZE);
	EVP_MD_CTX_free(ctx);
}

static int write_record(struct fex_service *service, uint16_t kind,
			const void *payload, uint32_t size)
{
	struct fex_record_header header = {
		.magic = FEX_ENGINE_MAGIC,
		.version = FEX_ENGINE_VERSION,
		.kind = kind,
		.size = size,
		.sequence = service->next_event_sequence++
	};

	if (write(service->engine_fd, &header, sizeof(header)) != sizeof(header) ||
	    write(service->engine_fd, payload, size) != (ssize_t)size ||
	    fsync(service->engine_fd) < 0)
		return FEX_ERR_IO;
	return FEX_OK;
}

static struct fex_objective *find_objective(struct fex_service *service,
					    uint64_t objective_id)
{
	size_t i;

	for (i = 0; i < service->objective_count; i++)
		if (service->objectives[i].objective_id == objective_id)
			return &service->objectives[i];
	return NULL;
}

static struct fex_node *find_node(struct fex_service *service, uint64_t task_id)
{
	size_t i;

	for (i = 0; i < service->node_count; i++)
		if (service->nodes[i].task_id == task_id)
			return &service->nodes[i];
	return NULL;
}

static void persist_objective(struct fex_service *service,
			       const struct fex_objective *objective)
{
	(void)write_record(service, FEX_RECORD_OBJECTIVE, objective,
			   sizeof(*objective));
}

static void persist_node(struct fex_service *service,
			 const struct fex_node *node)
{
	(void)write_record(service, FEX_RECORD_NODE, node, sizeof(*node));
}

static int make_path(char *dst, size_t size, const char *prefix,
		     const char *suffix)
{
	int n = snprintf(dst, size, "%s.%s", prefix, suffix);
	return n < 0 || (size_t)n >= size ? FEX_ERR_ARGUMENT : FEX_OK;
}

int fex_replay(struct fex_service *service)
{
	off_t offset = 0;
	struct fex_record_header header;
	uint8_t payload[sizeof(struct fex_objective) > sizeof(struct fex_node) ?
			 sizeof(struct fex_objective) : sizeof(struct fex_node)];

	if (!service || service->engine_fd < 0)
		return FEX_ERR_ARGUMENT;
	if (lseek(service->engine_fd, 0, SEEK_SET) < 0)
		return FEX_ERR_IO;
	service->objective_count = 0;
	service->node_count = 0;
	service->next_event_sequence = 1;
	for (;;) {
		ssize_t got = read(service->engine_fd, &header, sizeof(header));
		if (got == 0)
			break;
		if (got != sizeof(header) || header.magic != FEX_ENGINE_MAGIC ||
		    header.version != FEX_ENGINE_VERSION || header.size > sizeof(payload))
			return FEX_ERR_CORRUPT;
		if (read(service->engine_fd, payload, header.size) !=
		    (ssize_t)header.size)
			return FEX_ERR_CORRUPT;
		if (header.kind == FEX_RECORD_OBJECTIVE &&
		    header.size == sizeof(struct fex_objective)) {
			struct fex_objective *item = (struct fex_objective *)payload;
			struct fex_objective *existing = find_objective(service,
								 item->objective_id);
			if (existing)
				*existing = *item;
			else if (service->objective_count < FEX_MAX_OBJECTIVES)
				service->objectives[service->objective_count++] = *item;
			else
				return FEX_ERR_FULL;
					} else if (header.kind == FEX_RECORD_NODE &&
				   header.size == sizeof(struct fex_node)) {

			struct fex_node *item = (struct fex_node *)payload;
			struct fex_node *existing = find_node(service, item->task_id);
			if (existing)
				*existing = *item;
			else if (service->node_count < FEX_MAX_NODES)
				service->nodes[service->node_count++] = *item;
							else
					return FEX_ERR_FULL;
			} else if (header.kind == FEX_RECORD_WORKER &&
				   header.size == sizeof(struct fex_worker)) {
				struct fex_worker *item = (struct fex_worker *)payload;
				struct fex_worker *existing = find_worker(service, item->task_id);
				if (existing)
					*existing = *item;
				else if (service->worker_count < FEX_MAX_WORKERS)
					service->workers[service->worker_count++] = *item;
				else
					return FEX_ERR_FULL;
			}
			service->next_event_sequence = header.sequence + 1;

		offset += sizeof(header) + header.size;
	}
	if (lseek(service->engine_fd, 0, SEEK_END) != offset)
		return FEX_ERR_IO;
	return FEX_OK;
}

int fex_open(struct fex_service *service, const char *journal_prefix,
		     int require_kernel)
{
	char task_path[FTS_MAX_JOURNAL_PATH];
	int rc;

	if (!service || !journal_prefix)
		return FEX_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->engine_fd = -1;
	service->require_kernel = require_kernel;
	if (make_path(service->engine_path, sizeof(service->engine_path),
		      journal_prefix, "execution") != FEX_OK ||
	    make_path(task_path, sizeof(task_path), journal_prefix, "tasks") !=
		FEX_OK)
		return FEX_ERR_ARGUMENT;
	service->engine_fd = open(service->engine_path, O_RDWR | O_CREAT | O_APPEND,
				 0600);
	if (service->engine_fd < 0)
		return FEX_ERR_IO;
	rc = fts_open(&service->tasks, task_path, require_kernel);
	if (rc != FTS_OK) {
		close(service->engine_fd);
		service->engine_fd = -1;
		return rc == FTS_ERR_KERNEL ? FEX_ERR_KERNEL : FEX_ERR_IO;
	}
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		fts_close(&service->tasks);
		close(service->engine_fd);
		service->engine_fd = -1;
		return FEX_ERR_IO;
	}
	service->lock_initialized = 1;
	service->next_objective_id = 1;
	service->next_event_sequence = 1;
	rc = fex_replay(service);
	if (rc != FEX_OK) {
		fex_close(service);
		return rc;
	}
	return FEX_OK;
}

void fex_close(struct fex_service *service)
{
	if (!service)
		return;
	if (service->lock_initialized)
		pthread_mutex_destroy(&service->lock);
	service->lock_initialized = 0;
	fts_close(&service->tasks);
	if (service->engine_fd >= 0)
		close(service->engine_fd);
	service->engine_fd = -1;
}

int fex_create_objective(struct fex_service *service, const char *intent,
			 uint64_t deadline_ns, uint64_t cpu_budget_ns,
			 uint64_t money_budget_micro, uint32_t max_workers,
			 uint64_t now_ns, struct fex_objective *out)
{
	struct fex_objective objective;
	int rc;

	if (!service || !intent || !*intent || !out || !max_workers ||
	    strlen(intent) >= sizeof(objective.intent))
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (service->objective_count >= FEX_MAX_OBJECTIVES) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_FULL;
	}
	memset(&objective, 0, sizeof(objective));
	objective.objective_id = service->next_objective_id++;
	objective.generation = 1;
	objective.created_at_ns = now_ns;
	objective.updated_at_ns = now_ns;
	objective.deadline_ns = deadline_ns;
	objective.cpu_budget_ns = cpu_budget_ns;
	objective.money_budget_micro = money_budget_micro;
	objective.max_workers = max_workers > FEX_MAX_WORKERS ?
		FEX_MAX_WORKERS : max_workers;
	objective.state = FEX_OBJECTIVE_READY;
	strncpy(objective.intent, intent, sizeof(objective.intent) - 1);
	digest_bytes(objective.intent, strlen(objective.intent), objective.intent_digest);
	service->objectives[service->objective_count++] = objective;
	rc = write_record(service, FEX_RECORD_OBJECTIVE, &objective,
			  sizeof(objective));
	if (rc == FEX_OK)
		*out = objective;
	pthread_mutex_unlock(&service->lock);
	return rc;
}

int fex_add_node(struct fex_service *service, uint64_t objective_id,
			 const char *idempotency_key, const char *node_objective,
			 uint32_t priority, uint32_t risk_class, uint32_t max_retries,
			 const uint32_t *dependencies, uint32_t dependency_count,
			 uint32_t deterministic, uint32_t speculative,
			 struct fex_node *out)
{
	struct fex_objective *objective;
	struct fts_task task;
	struct fex_node node;
	int rc;

	if (!service || !idempotency_key || !node_objective || !out ||
	    dependency_count > FTS_MAX_DEPENDENCIES ||
	    strlen(node_objective) >= FTS_MAX_OBJECTIVE)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (!objective || service->node_count >= FEX_MAX_NODES) {
		pthread_mutex_unlock(&service->lock);
		return objective ? FEX_ERR_FULL : FEX_ERR_NOT_FOUND;
	}
	rc = fts_submit(&service->tasks, objective_id, idempotency_key,
			 node_objective, objective->deadline_ns,
			 objective->cpu_budget_ns, objective->money_budget_micro,
			 priority, risk_class, max_retries, dependencies,
			 dependency_count, &task);
	if (rc != FTS_OK) {
		pthread_mutex_unlock(&service->lock);
		return rc == FTS_ERR_KERNEL ? FEX_ERR_KERNEL : FEX_ERR_STATE;
	}
	memset(&node, 0, sizeof(node));
	node.objective_id = objective_id;
	node.task_id = task.task_id;
	node.state = task.state;
	node.deterministic = deterministic != 0;
	node.speculative = speculative != 0;
	strncpy(node.objective, node_objective, sizeof(node.objective) - 1);
	digest_bytes(node.objective, strlen(node.objective), node.action_digest);
	service->nodes[service->node_count++] = node;
	objective->node_count++;
	objective->updated_at_ns = task.updated_at_ns;
	objective->state = FEX_OBJECTIVE_READY;
	persist_node(service, &node);
	persist_objective(service, objective);
	*out = node;
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_dispatch(struct fex_service *service, uint64_t objective_id,
			 uint64_t now_ns, uint32_t lease_ns, uint32_t *claimed)
{
	struct fex_objective *objective;
	size_t i;
	uint32_t count = 0;

	if (!service || !claimed || !lease_ns)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (!objective) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	for (i = 0; i < service->node_count && count < objective->max_workers; i++) {
		struct fex_node *node = &service->nodes[i];
		struct fts_task task;
		int rc;

					if (node->objective_id != objective_id || node->state == FTS_TASK_SUCCEEDED ||
			    node->state == FTS_TASK_CANCELLED || node->state == FTS_TASK_DEAD_LETTER)
				continue;
			{
				struct fex_worker *existing = find_worker(service, node->task_id);
				if (existing && existing->health == FEX_WORKER_QUARANTINED)
					continue;
			}

					if (!find_worker(service, node->task_id) &&
			    service->worker_count >= FEX_MAX_WORKERS) {
				pthread_mutex_unlock(&service->lock);
				return FEX_ERR_FULL;
			}
			rc = fts_claim(&service->tasks, node->task_id, now_ns, lease_ns, &task);
			if (rc == FTS_OK) {
				struct fex_worker *worker = find_worker(service, node->task_id);
				if (!worker) {
					worker = &service->workers[service->worker_count++];
					memset(worker, 0, sizeof(*worker));
					worker->task_id = node->task_id;
					worker->objective_id = objective_id;
				}
				worker->worker_id = task.owner_agent_id ? task.owner_agent_id : task.task_id;
				worker->lease_generation = task.lease_generation;
				worker->last_heartbeat_ns = now_ns;
				worker->lease_deadline_ns = task.lease_until_ns;
				worker->last_transition_ns = now_ns;
				worker->health = FEX_WORKER_HEALTHY;
				if (persist_worker(service, worker) != FEX_OK) {
					pthread_mutex_unlock(&service->lock);
					return FEX_ERR_IO;
				}
				node->state = task.state;

			node->owner_agent_id = task.owner_agent_id;
			node->lease_generation = task.lease_generation;
			persist_node(service, node);
			count++;
		} else if (rc != FTS_ERR_DEPENDENCY && rc != FTS_ERR_LEASE &&
			   rc != FTS_ERR_DEADLINE && rc != FTS_ERR_BUDGET) {
			pthread_mutex_unlock(&service->lock);
			return FEX_ERR_STATE;
		}
	}
	if (count)
		objective->state = FEX_OBJECTIVE_RUNNING;
	objective->active_workers = count;
	objective->updated_at_ns = now_ns;
	persist_objective(service, objective);
	*claimed = count;
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_heartbeat(struct fex_service *service, uint64_t task_id,
			 uint64_t now_ns, uint64_t extend_ns)
{
	struct fex_node *node;
	struct fts_task task;
	int rc;

	if (!service)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, task_id);
	if (!node) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	rc = fts_heartbeat(&service->tasks, task_id, node->lease_generation,
			   now_ns, extend_ns, &task);
	if (rc == FTS_OK) {
		struct fex_worker *worker = find_worker(service, task_id);
		node->state = task.state;
		if (worker) {
			worker->lease_generation = task.lease_generation;
			worker->last_heartbeat_ns = now_ns;
			worker->lease_deadline_ns = task.lease_until_ns;
			worker->last_transition_ns = now_ns;
			worker->health = FEX_WORKER_HEALTHY;
			if (persist_worker(service, worker) != FEX_OK)
				rc = FTS_ERR_IO;
		}
	}
	if (rc == FTS_OK)
		persist_node(service, node);
	pthread_mutex_unlock(&service->lock);
		return rc == FTS_OK ? FEX_OK : FEX_ERR_STATE;
}

int fex_handoff(struct fex_service *service, uint64_t task_id,
			uint64_t new_worker_id, uint64_t now_ns, uint64_t lease_ns)
{
	struct fex_node *node;
	struct fex_worker *worker;
	struct fts_task task;
	int rc;

	if (!service || !task_id || !new_worker_id || !now_ns || !lease_ns)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, task_id);
	worker = find_worker(service, task_id);
	if (!node || !worker) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	if (worker->worker_id == new_worker_id) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_CONFLICT;
	}
	rc = fts_handoff(&service->tasks, task_id, node->lease_generation,
				 new_worker_id, now_ns, lease_ns, &task);
	if (rc == FTS_OK) {
		node->owner_agent_id = task.owner_agent_id;
		node->lease_generation = task.lease_generation;
		node->state = task.state;
		worker->worker_id = new_worker_id;
		worker->lease_generation = task.lease_generation;
		worker->last_heartbeat_ns = now_ns;
		worker->lease_deadline_ns = task.lease_until_ns;
		worker->last_transition_ns = now_ns;
		worker->health = FEX_WORKER_HEALTHY;
		worker->handoff_count++;
		if (persist_worker(service, worker) != FEX_OK)
			rc = FTS_ERR_IO;
		persist_node(service, node);
	}
	pthread_mutex_unlock(&service->lock);
	return rc == FTS_OK ? FEX_OK : FEX_ERR_STATE;
}

int fex_handoff_verified(struct fex_service *service, uint64_t task_id,
				 uint64_t new_worker_id, uint64_t now_ns,
				 uint64_t lease_ns,
				 const uint8_t checkpoint_digest[FEX_DIGEST_SIZE])
{
	struct fex_node *node;
	struct fex_worker *worker;
	struct fex_objective *objective;
	struct fts_task task;
	int rc;

	if (!service || !task_id || !new_worker_id || !now_ns || !lease_ns ||
	    !checkpoint_digest)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, task_id);
	worker = find_worker(service, task_id);
	objective = node ? find_objective(service, node->objective_id) : NULL;
	if (!node || !worker || !objective) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	if (memcmp(objective->state_digest, checkpoint_digest,
		   FEX_DIGEST_SIZE) != 0) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_AUTHORITY;
	}
	if (worker->worker_id == new_worker_id) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_CONFLICT;
	}
	rc = fts_handoff(&service->tasks, task_id, node->lease_generation,
			 new_worker_id, now_ns, lease_ns, &task);
	if (rc == FTS_OK) {
		node->owner_agent_id = task.owner_agent_id;
		node->lease_generation = task.lease_generation;
		node->state = task.state;
		worker->worker_id = new_worker_id;
		worker->lease_generation = task.lease_generation;
		worker->last_heartbeat_ns = now_ns;
		worker->lease_deadline_ns = task.lease_until_ns;
		worker->last_transition_ns = now_ns;
		worker->health = FEX_WORKER_HEALTHY;
		worker->handoff_count++;
		if (persist_worker(service, worker) != FEX_OK)
			rc = FTS_ERR_IO;
		persist_node(service, node);
	}
	pthread_mutex_unlock(&service->lock);
	return rc == FTS_OK ? FEX_OK :
		rc == FTS_ERR_LEASE ? FEX_ERR_STATE : FEX_ERR_STATE;
}

int fex_make_handoff_token(const struct fex_service *service, uint64_t task_id,
				   uint64_t new_worker_id, uint64_t now_ns,
				   uint8_t token[FEX_HANDOFF_TOKEN_SIZE])
{
	struct fex_service *mutable_service = (struct fex_service *)service;
	struct fex_node *node;
	struct fex_worker *worker;
	struct fex_objective *objective;
	uint8_t material[FEX_DIGEST_SIZE + 4 * sizeof(uint64_t)];

	if (!service || !task_id || !new_worker_id || !now_ns || !token)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&mutable_service->lock);
	node = find_node(mutable_service, task_id);
	worker = find_worker(mutable_service, task_id);
	objective = node ? find_objective(mutable_service, node->objective_id) : NULL;
	if (!node || !worker || !objective) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	memcpy(material, objective->state_digest, FEX_DIGEST_SIZE);
	memcpy(material + FEX_DIGEST_SIZE, &task_id, sizeof(task_id));
	memcpy(material + FEX_DIGEST_SIZE + sizeof(task_id), &new_worker_id,
	       sizeof(new_worker_id));
	memcpy(material + FEX_DIGEST_SIZE + 2 * sizeof(task_id), &now_ns,
	       sizeof(now_ns));
	memcpy(material + FEX_DIGEST_SIZE + 3 * sizeof(task_id),
	       &worker->lease_generation, sizeof(worker->lease_generation));
	memcpy(token, &now_ns, sizeof(now_ns));
	digest_bytes(material, sizeof(material), token + sizeof(now_ns));
	pthread_mutex_unlock(&mutable_service->lock);
	return FEX_OK;
}

int fex_handoff_token_verified(struct fex_service *service, uint64_t task_id,
				       uint64_t new_worker_id, uint64_t now_ns,
				       uint64_t lease_ns,
				       const uint8_t token[FEX_HANDOFF_TOKEN_SIZE])
{
	uint8_t expected[FEX_HANDOFF_TOKEN_SIZE];
	struct fex_node node;
	struct fex_objective objective;
	uint64_t issued_at_ns;
	int rc;

	if (!token || !service || !now_ns)
		return FEX_ERR_ARGUMENT;
	if (!lease_ns || lease_ns > FEX_MAX_HANDOFF_LEASE_NS)
		return FEX_ERR_POLICY;
	memcpy(&issued_at_ns, token, sizeof(issued_at_ns));
	if (now_ns < issued_at_ns ||
	    now_ns - issued_at_ns > FEX_HANDOFF_TOKEN_MAX_AGE_NS)
		return FEX_ERR_AUTHORITY;
	rc = fex_make_handoff_token(service, task_id, new_worker_id, issued_at_ns,
				    expected);
	if (rc != FEX_OK)
		return rc;
	if (memcmp(expected, token, FEX_HANDOFF_TOKEN_SIZE) != 0)
		return FEX_ERR_AUTHORITY;
	rc = fex_query_node(service, task_id, &node);
	if (rc != FEX_OK)
		return rc;
	rc = fex_query_objective(service, node.objective_id, &objective);
	if (rc != FEX_OK)
		return rc;
	return fex_handoff_verified(service, task_id, new_worker_id, now_ns,
					lease_ns, objective.state_digest);
}

int fex_supervise(struct fex_service *service, uint64_t now_ns,

			  uint64_t timeout_ns, uint32_t *reassigned,
			  uint32_t *dead_lettered)
{
	size_t i;
	int rc;
	uint32_t recovered = 0;
	uint32_t expired_dead = 0;

	if (!service || !now_ns || !timeout_ns || !reassigned || !dead_lettered)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	*reassigned = 0;
	*dead_lettered = 0;
	for (i = 0; i < service->worker_count; i++) {
		struct fex_worker *worker = &service->workers[i];
		struct fts_task task;
		int timed_out;

		if (worker->health != FEX_WORKER_HEALTHY)
			continue;
		if (fts_query(&service->tasks, worker->task_id, &task) != FTS_OK)
			continue;
		timed_out = task.state == FTS_TASK_LEASED || task.state == FTS_TASK_RUNNING;
					if (timed_out && now_ns >= worker->last_heartbeat_ns &&
			    now_ns - worker->last_heartbeat_ns >= timeout_ns) {
				struct fts_task failed;
				int quarantine = worker->restart_count + 1 >=
					FEX_MAX_WORKER_RESTARTS;
				int frc = fts_fail(&service->tasks, worker->task_id,
						   worker->lease_generation, now_ns,
						   FTS_FAILURE_SYSTEMIC,
						   quarantine ? "worker heartbeat timeout; quarantined" :
						   "worker heartbeat timeout",
						   1, &failed);

			if (frc != FTS_OK && frc != FTS_ERR_STOPPED)
				continue;
			task = failed;
		}
		worker->last_transition_ns = now_ns;
		worker->lease_deadline_ns = task.lease_until_ns;
		worker->lease_generation = task.lease_generation;
					if (task.state == FTS_TASK_READY || task.state == FTS_TASK_RETRY_WAIT) {
				worker->health = FEX_WORKER_REASSIGNED;
				worker->restart_count++;
				worker->reassignment_count++;
				(*reassigned)++;
			} else if (task.state == FTS_TASK_DEAD_LETTER) {
				worker->health = worker->restart_count + 1 >=
					FEX_MAX_WORKER_RESTARTS ? FEX_WORKER_QUARANTINED :
					FEX_WORKER_DEAD_LETTER;
				worker->restart_count++;
								worker->failure_class = task.failure_class;

			(*dead_lettered)++;
		} else if (task.state == FTS_TASK_SUCCEEDED) {
			worker->health = FEX_WORKER_COMPLETED;
			worker->lease_deadline_ns = 0;
		} else {
			continue;
		}
		if (persist_worker(service, worker) != FEX_OK) {
			pthread_mutex_unlock(&service->lock);
			return FEX_ERR_IO;
		}
	}
	rc = fts_recover_expired(&service->tasks, now_ns, &recovered, &expired_dead);
	if (rc != FTS_OK) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_STATE;
	}
	for (i = 0; i < service->node_count; i++) {
		struct fts_task task;
		if (fts_query(&service->tasks, service->nodes[i].task_id, &task) == FTS_OK) {
			service->nodes[i].state = task.state;
			if (task.state == FTS_TASK_READY || task.state == FTS_TASK_RETRY_WAIT)
				service->nodes[i].lease_generation = 0;
			persist_node(service, &service->nodes[i]);
		}
	}
	for (i = 0; i < service->objective_count; i++) {
		if (*reassigned || *dead_lettered)
			service->objectives[i].state = *dead_lettered ?
				FEX_OBJECTIVE_ADAPTING : FEX_OBJECTIVE_RECOVERING;
		service->objectives[i].updated_at_ns = now_ns;
		persist_objective(service, &service->objectives[i]);
	}
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_query_worker(const struct fex_service *service, uint64_t task_id,
			    struct fex_worker *out)
{
	struct fex_service *mutable_service = (struct fex_service *)service;
	struct fex_worker *worker;

	if (!service || !out || !task_id)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&mutable_service->lock);
	worker = find_worker(mutable_service, task_id);
	if (!worker) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	*out = *worker;
	pthread_mutex_unlock(&mutable_service->lock);
	return FEX_OK;
}

int fex_complete(struct fex_service *service, uint64_t task_id,
			 uint64_t now_ns, const char *result,
			 const uint8_t evidence_digest[FEX_DIGEST_SIZE])
{
	struct fex_node *node;
	struct fex_objective *objective;
	struct fts_task task;
	int rc;

	if (!service || !result || !evidence_digest)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, task_id);
	if (!node) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	objective = find_objective(service, node->objective_id);
	rc = fts_complete(&service->tasks, task_id, node->lease_generation,
			  now_ns, result, 0, 0, &task);
	if (rc != FTS_OK) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_STATE;
	}
	node->state = task.state;
	{
		struct fex_worker *worker = find_worker(service, task_id);
		if (worker) {
			worker->lease_generation = task.lease_generation;
			worker->last_transition_ns = now_ns;
			worker->lease_deadline_ns = 0;
			worker->health = FEX_WORKER_COMPLETED;
			if (persist_worker(service, worker) != FEX_OK) {
				pthread_mutex_unlock(&service->lock);
				return FEX_ERR_IO;
			}
		}
	}
	strncpy(node->result, result, sizeof(node->result) - 1);
	memcpy(node->evidence_digest, evidence_digest, FEX_DIGEST_SIZE);
	if (objective) {
		objective->completed_nodes++;
		objective->updated_at_ns = now_ns;
		objective->state = objective->completed_nodes == objective->node_count ?
			FEX_OBJECTIVE_VERIFYING : FEX_OBJECTIVE_RUNNING;
		if (objective->state == FEX_OBJECTIVE_VERIFYING)
			objective->state = FEX_OBJECTIVE_SUCCEEDED;
		persist_objective(service, objective);
	}
	persist_node(service, node);
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_fail(struct fex_service *service, uint64_t task_id,
		    uint64_t now_ns, uint32_t failure_class, const char *reason,
		    int retryable, uint32_t fallback_class)
{
	struct fex_node *node;
	struct fex_objective *objective;
	struct fts_task task;
	int rc;
	(void)fallback_class;

	if (!service || !reason)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, task_id);
	if (!node) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	objective = find_objective(service, node->objective_id);
	rc = fts_fail(&service->tasks, task_id, node->lease_generation, now_ns,
			  failure_class, reason, retryable, &task);
	if (rc != FTS_OK && rc != FTS_ERR_STOPPED) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_STATE;
	}
	node->state = task.state;
	{
		struct fex_worker *worker = find_worker(service, task_id);
		if (worker) {
			worker->last_transition_ns = now_ns;
			worker->lease_deadline_ns = 0;
			worker->failure_class = failure_class;
			worker->health = task.state == FTS_TASK_DEAD_LETTER ?
				FEX_WORKER_DEAD_LETTER : FEX_WORKER_REASSIGNED;
			if (worker->health == FEX_WORKER_REASSIGNED)
				worker->reassignment_count++;
			if (persist_worker(service, worker) != FEX_OK) {
				pthread_mutex_unlock(&service->lock);
				return FEX_ERR_IO;
			}
		}
	}
	if (objective && task.state == FTS_TASK_DEAD_LETTER) {
		objective->failed_nodes++;
		objective->state = FEX_OBJECTIVE_ADAPTING;
		strncpy(objective->reason, reason, sizeof(objective->reason) - 1);
		persist_objective(service, objective);
	}
	persist_node(service, node);
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_checkpoint(struct fex_service *service, uint64_t objective_id,
			 uint64_t now_ns, const uint8_t working_digest[FEX_DIGEST_SIZE],
			 const uint8_t world_digest[FEX_DIGEST_SIZE],
			 const uint8_t resource_digest[FEX_DIGEST_SIZE],
			 struct fex_checkpoint *out)
{
	struct fex_objective *objective;
	struct fex_checkpoint checkpoint;
	struct fex_node *node;
	uint8_t material[3 * FEX_DIGEST_SIZE + sizeof(uint64_t)];
	size_t i;
	int rc;

	if (!service || !working_digest || !world_digest || !resource_digest || !out)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (!objective) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	memset(&checkpoint, 0, sizeof(checkpoint));
	checkpoint.objective_id = objective_id;
	checkpoint.sequence = ++objective->checkpoint_sequence;
	checkpoint.created_at_ns = now_ns;
	checkpoint.node_count = objective->node_count;
	checkpoint.verified = objective->completed_nodes <= objective->node_count;
	memcpy(checkpoint.working_digest, working_digest, FEX_DIGEST_SIZE);
	memcpy(checkpoint.world_digest, world_digest, FEX_DIGEST_SIZE);
	memcpy(checkpoint.resource_digest, resource_digest, FEX_DIGEST_SIZE);
	memcpy(material, working_digest, FEX_DIGEST_SIZE);
	memcpy(material + FEX_DIGEST_SIZE, world_digest, FEX_DIGEST_SIZE);
	memcpy(material + 2 * FEX_DIGEST_SIZE, resource_digest, FEX_DIGEST_SIZE);
	memcpy(material + 3 * FEX_DIGEST_SIZE, &checkpoint.sequence, sizeof(uint64_t));
	digest_bytes(material, sizeof(material), checkpoint.checkpoint_digest);
	memcpy(objective->state_digest, checkpoint.checkpoint_digest, FEX_DIGEST_SIZE);
	objective->updated_at_ns = now_ns;
	rc = write_record(service, FEX_RECORD_CHECKPOINT, &checkpoint, sizeof(checkpoint));
	if (rc == FEX_OK)
		persist_objective(service, objective);
	for (i = 0; rc == FEX_OK && i < service->node_count; i++) {
		node = &service->nodes[i];
		if (node->objective_id == objective_id) {
			node->last_checkpoint = checkpoint.sequence;
			persist_node(service, node);
		}
	}
	if (rc == FEX_OK)
		*out = checkpoint;
	pthread_mutex_unlock(&service->lock);
	return rc;
}

int fex_recover(struct fex_service *service, uint64_t now_ns,
			 uint32_t *recovered, uint32_t *dead_lettered)
{
	size_t i;
	int rc;

	if (!service || !recovered || !dead_lettered)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	rc = fts_recover_expired(&service->tasks, now_ns, recovered, dead_lettered);
	if (rc != FTS_OK) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_STATE;
	}
	for (i = 0; i < service->node_count; i++) {
		struct fts_task task;
		if (fts_query(&service->tasks, service->nodes[i].task_id, &task) == FTS_OK) {
			service->nodes[i].state = task.state;
			if (task.state == FTS_TASK_READY)
				service->nodes[i].lease_generation = 0;
			persist_node(service, &service->nodes[i]);
		}
	}
	for (i = 0; i < service->objective_count; i++) {
		if (service->objectives[i].state == FEX_OBJECTIVE_RUNNING && *recovered)
			service->objectives[i].state = FEX_OBJECTIVE_RECOVERING;
		persist_objective(service, &service->objectives[i]);
	}
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_cancel(struct fex_service *service, uint64_t objective_id)
{
	struct fex_objective *objective;
	size_t i;

	if (!service)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (!objective) {
		pthread_mutex_unlock(&service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	for (i = 0; i < service->node_count; i++)
		if (service->nodes[i].objective_id == objective_id &&
		    service->nodes[i].state != FTS_TASK_SUCCEEDED)
			(void)fts_cancel(&service->tasks, service->nodes[i].task_id,
					FTS_STOP_CANCELLED, NULL);
	objective->state = FEX_OBJECTIVE_CANCELLED;
	objective->updated_at_ns++;
	persist_objective(service, objective);
	pthread_mutex_unlock(&service->lock);
	return FEX_OK;
}

int fex_query_objective(const struct fex_service *service, uint64_t objective_id,
			       struct fex_objective *out)
{
	struct fex_service *mutable_service = (struct fex_service *)service;
	struct fex_objective *objective;
	if (!service || !out)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&mutable_service->lock);
	objective = find_objective(mutable_service, objective_id);
	if (!objective) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	*out = *objective;
	pthread_mutex_unlock(&mutable_service->lock);
	return FEX_OK;
}

int fex_query_node(const struct fex_service *service, uint64_t task_id,
			   struct fex_node *out)
{
	struct fex_service *mutable_service = (struct fex_service *)service;
	struct fex_node *node;
	if (!service || !out)
		return FEX_ERR_ARGUMENT;
	pthread_mutex_lock(&mutable_service->lock);
	node = find_node(mutable_service, task_id);
	if (!node) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FEX_ERR_NOT_FOUND;
	}
	*out = *node;
	pthread_mutex_unlock(&mutable_service->lock);
	return FEX_OK;
}

int fex_test_model_output_untrusted(struct fex_service *service,
				    uint64_t task_id,
				    const uint8_t output_digest[FEX_DIGEST_SIZE])
{
	struct fex_node node;
	(void)output_digest;
	if (!service || !output_digest)
		return FEX_ERR_ARGUMENT;
	if (fex_query_node(service, task_id, &node) != FEX_OK)
		return FEX_ERR_NOT_FOUND;
	/* A model result is data; only fex_complete with external evidence commits it. */
	return FEX_ERR_AUTHORITY;
}
