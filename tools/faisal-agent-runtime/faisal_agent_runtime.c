#include "faisal_agent_runtime.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

struct far_disk_record {
	struct far_event event;
	uint8_t payload[FAR_MAX_PAYLOAD];
};

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FAR_DIGEST_SIZE])
{
	unsigned int output_length = 0U;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FAR_ERR_ARGUMENT;
	if (EVP_Digest(data, length, digest, &output_length, EVP_sha256(), NULL) != 1 ||
	    output_length != FAR_DIGEST_SIZE)
		return FAR_ERR_TAMPER;
	return FAR_OK;
}

static int is_zero_digest(const uint8_t digest[FAR_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < FAR_DIGEST_SIZE; ++i) {
		if (digest[i] != 0U)
			return 0;
	}
	return 1;
}

static int write_all(int fd, const void *data, size_t length)
{
	const uint8_t *cursor = data;

	while (length != 0U) {
		ssize_t written = write(fd, cursor, length);
		if (written <= 0)
			return FAR_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return FAR_OK;
}

static int read_all(int fd, void *data, size_t length)
{
	uint8_t *cursor = data;

	while (length != 0U) {
		ssize_t count = read(fd, cursor, length);
		if (count == 0)
			return length == sizeof(struct far_disk_record) ? FAR_ERR_NOT_FOUND : FAR_ERR_IO;
		if (count < 0)
			return FAR_ERR_IO;
		cursor += (size_t)count;
		length -= (size_t)count;
	}
	return FAR_OK;
}

static int digest_event(const struct far_event *event, const uint8_t *payload,
			 size_t payload_len, uint8_t digest[FAR_DIGEST_SIZE])
{
	struct far_event canonical;
	uint8_t buffer[sizeof(struct far_event) + FAR_MAX_PAYLOAD];

	if (event == NULL || (payload == NULL && payload_len != 0U) ||
	    payload_len > FAR_MAX_PAYLOAD || digest == NULL)
		return FAR_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, sizeof(canonical.event_digest));
	memcpy(buffer, &canonical, sizeof(canonical));
	if (payload_len != 0U)
		memcpy(buffer + sizeof(canonical), payload, payload_len);
	return digest_bytes(buffer, sizeof(canonical) + payload_len, digest);
}

int far_verify_event(const struct far_event *event,
		     const uint8_t payload[FAR_MAX_PAYLOAD],
		     const uint8_t previous_digest[FAR_DIGEST_SIZE])
{
	uint8_t payload_digest[FAR_DIGEST_SIZE];
	uint8_t event_digest[FAR_DIGEST_SIZE];

	if (event == NULL || previous_digest == NULL || event->magic != FAR_EVENT_MAGIC ||
	    event->version != FAR_EVENT_VERSION || event->sequence == 0U ||
	    event->payload_len > FAR_MAX_PAYLOAD ||
	    memcmp(event->previous_digest, previous_digest, FAR_DIGEST_SIZE) != 0)
		return FAR_ERR_TAMPER;
	if (digest_bytes(payload, event->payload_len, payload_digest) != FAR_OK ||
	    memcmp(payload_digest, event->payload_digest, FAR_DIGEST_SIZE) != 0)
		return FAR_ERR_TAMPER;
	if (digest_event(event, payload, event->payload_len, event_digest) != FAR_OK ||
	    memcmp(event_digest, event->event_digest, FAR_DIGEST_SIZE) != 0)
		return FAR_ERR_TAMPER;
	return FAR_OK;
}

static int append_event_locked(struct far_service *service, uint16_t kind,
			       uint64_t agent_id, uint64_t objective_id,
			       int status, uint64_t now_ns,
			       const void *payload, uint32_t payload_len,
			       uint64_t *out_sequence)
{
	struct far_disk_record record;
	int result;

	if (service == NULL || service->journal_fd < 0 || payload_len > FAR_MAX_PAYLOAD ||
	    (payload == NULL && payload_len != 0U))
		return FAR_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FAR_EVENT_MAGIC;
	record.event.version = FAR_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->event_sequence + 1U;
	record.event.observed_at_ns = now_ns;
	record.event.agent_id = agent_id;
	record.event.objective_id = objective_id;
	record.event.status = status;
	record.event.payload_len = payload_len;
	memcpy(record.event.previous_digest, service->chain_digest, FAR_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	result = digest_bytes(record.payload, payload_len, record.event.payload_digest);
	if (result != FAR_OK)
		return result;
	result = digest_event(&record.event, record.payload, payload_len,
			      record.event.event_digest);
	if (result != FAR_OK)
		return result;
	result = write_all(service->journal_fd, &record, sizeof(record));
	if (result != FAR_OK || fdatasync(service->journal_fd) != 0)
		return FAR_ERR_IO;
	service->event_sequence = record.event.sequence;
	service->chain_digest[0] = record.event.event_digest[0];
	memcpy(service->chain_digest, record.event.event_digest, FAR_DIGEST_SIZE);
	if (out_sequence != NULL)
		*out_sequence = record.event.sequence;
	return FAR_OK;
}

static struct far_agent *find_agent(struct far_service *service, uint64_t agent_id)
{
	size_t i;

	for (i = 0U; i < service->agent_count; ++i)
		if (service->agents[i].agent_id == agent_id)
			return &service->agents[i];
	return NULL;
}

static const struct far_agent *find_agent_const(const struct far_service *service,
						uint64_t agent_id)
{
	size_t i;

	for (i = 0U; i < service->agent_count; ++i)
		if (service->agents[i].agent_id == agent_id)
			return &service->agents[i];
	return NULL;
}

static struct far_objective *find_objective(struct far_service *service,
					    uint64_t objective_id)
{
	size_t i;

	for (i = 0U; i < service->objective_count; ++i)
		if (service->objectives[i].objective_id == objective_id)
			return &service->objectives[i];
	return NULL;
}

static const struct far_objective *find_objective_const(
		const struct far_service *service, uint64_t objective_id)
{
	size_t i;

	for (i = 0U; i < service->objective_count; ++i)
		if (service->objectives[i].objective_id == objective_id)
			return &service->objectives[i];
	return NULL;
}

static int objective_valid(const struct far_objective *request,
			   const struct far_policy *policy)
{
	if (request == NULL || policy == NULL || request->agent_id == 0U ||
	    request->tenant_id == 0U || request->trace_id == 0U ||
	    request->task_generation == 0U || request->session_generation == 0U ||
	    request->world_generation == 0U || request->model_generation == 0U ||
	    request->request_sequence == 0U || request->created_at_ns == 0U ||
	    request->deadline_ns < request->created_at_ns ||
	    request->priority == 0U || (request->flags & ~FAR_FLAGS_ALL) != 0U ||
	    is_zero_digest(request->objective_digest) ||
	    is_zero_digest(request->provenance_digest) ||
	    request->required_capability_mask == 0U)
		return FAR_ERR_ARGUMENT;
	if (policy->require_verified_input &&
	    !(request->flags & FAR_FLAG_VERIFIED_INPUT))
		return FAR_ERR_POLICY;
	if ((request->flags & FAR_FLAG_MODEL_PROPOSAL) &&
	    !(request->flags & FAR_FLAG_AUTHORITY_GRANTED))
		return FAR_ERR_AUTHORITY;
	if (policy->budget_policy.current_time_ns < request->created_at_ns ||
	    policy->budget_policy.current_time_ns > request->deadline_ns)
		return FAR_ERR_DEADLINE;
	return FAR_OK;
}

static int budget_request_from_objective(const struct far_objective *objective,
					 struct m240_request *request)
{
	if (objective == NULL || request == NULL)
		return FAR_ERR_ARGUMENT;
	memset(request, 0, sizeof(*request));
	request->objective_id = objective->objective_id;
	request->agent_id = objective->agent_id;
	request->tenant_id = objective->tenant_id;
	request->trace_id = objective->trace_id;
	request->task_generation = objective->task_generation;
	request->session_generation = objective->session_generation;
	request->world_generation = objective->world_generation;
	request->model_generation = objective->model_generation;
	request->request_sequence = objective->request_sequence;
	request->issued_at_ns = objective->created_at_ns;
	request->deadline_ns = objective->deadline_ns;
	request->priority = objective->priority;
	request->flags = M240_FLAG_VERIFIED_INPUT;
	if (objective->flags & FAR_FLAG_AUTHORITY_GRANTED)
		request->flags |= M240_FLAG_AUTHORITY_GRANTED;
	if (objective->flags & FAR_FLAG_MODEL_PROPOSAL)
		request->flags |= M240_FLAG_MODEL_PROPOSAL;
	request->requested = objective->budget;
	memcpy(request->objective_digest, objective->objective_digest, FAR_DIGEST_SIZE);
	memcpy(request->provenance_digest, objective->provenance_digest, FAR_DIGEST_SIZE);
	return FAR_OK;
}

static int objective_event_locked(struct far_service *service,
				  uint16_t kind, struct far_objective *objective,
				  int status, uint64_t now_ns)
{
	int result;

	result = append_event_locked(service, kind, objective->agent_id,
				     objective->objective_id, status, now_ns,
				     objective, sizeof(*objective),
				     &objective->event_sequence);
	return result;
}

static int checkpoint_digest(const struct far_checkpoint *checkpoint,
			     uint8_t digest[FAR_DIGEST_SIZE])
{
	struct far_checkpoint canonical;

	if (checkpoint == NULL || digest == NULL)
		return FAR_ERR_ARGUMENT;
	canonical = *checkpoint;
	memset(canonical.checkpoint_digest, 0, FAR_DIGEST_SIZE);
	return digest_bytes(&canonical, sizeof(canonical), digest);
}

static int apply_replay_record(struct far_service *service,
			       const struct far_disk_record *record)
{
	struct far_agent agent;
	struct far_objective objective;
	struct far_checkpoint checkpoint;
	struct far_tool_request tool;
	struct far_anomaly anomaly;
	struct m240_request budget_request;
	struct m240_receipt budget_receipt;
	struct far_agent *existing_agent;
	struct far_objective *existing_objective;
	uint8_t checkpoint_hash[FAR_DIGEST_SIZE];
	int result;

	if (record->event.kind == FAR_EVENT_REGISTER_AGENT) {
		if (record->event.payload_len != sizeof(agent))
			return FAR_ERR_CORRUPT;
		memcpy(&agent, record->payload, sizeof(agent));
		existing_agent = find_agent(service, agent.agent_id);
		if (existing_agent != NULL)
			*existing_agent = agent;
		else if (service->agent_count < FAR_MAX_AGENTS)
			service->agents[service->agent_count++] = agent;
		else
			return FAR_ERR_FULL;
		if (agent.agent_id >= service->next_agent_id)
			service->next_agent_id = agent.agent_id + 1U;
		return FAR_OK;
	}
	if (record->event.kind == FAR_EVENT_ADMIT_OBJECTIVE ||
	    record->event.kind == FAR_EVENT_DISPATCH ||
	    record->event.kind == FAR_EVENT_RECOVER ||
	    record->event.kind == FAR_EVENT_COMPLETE ||
	    record->event.kind == FAR_EVENT_FAIL ||
	    record->event.kind == FAR_EVENT_CANCEL) {
		if (record->event.payload_len != sizeof(objective))
			return FAR_ERR_CORRUPT;
		memcpy(&objective, record->payload, sizeof(objective));
		existing_objective = find_objective(service, objective.objective_id);
		if (existing_objective != NULL)
			*existing_objective = objective;
		else if (service->objective_count < FAR_MAX_OBJECTIVES)
			service->objectives[service->objective_count++] = objective;
		else
			return FAR_ERR_FULL;
		if (objective.objective_id >= service->next_objective_id)
			service->next_objective_id = objective.objective_id + 1U;
		if (record->event.kind == FAR_EVENT_ADMIT_OBJECTIVE) {
			if (budget_request_from_objective(&objective, &budget_request) != FAR_OK)
				return FAR_ERR_TAMPER;
			result = m240_admit(&service->budgets, &budget_request, &budget_receipt);
			if (result != M240_OK && result != M240_ERR_DUPLICATE)
				return FAR_ERR_BUDGET;
		}
		return FAR_OK;
	}
	if (record->event.kind == FAR_EVENT_CHECKPOINT) {
		if (record->event.payload_len != sizeof(checkpoint))
			return FAR_ERR_CORRUPT;
		memcpy(&checkpoint, record->payload, sizeof(checkpoint));
		if (checkpoint.sequence == 0U ||
		    checkpoint_digest(&checkpoint, checkpoint_hash) != FAR_OK ||
		    memcmp(checkpoint_hash, checkpoint.checkpoint_digest, FAR_DIGEST_SIZE) != 0)
			return FAR_ERR_TAMPER;
		if (service->checkpoint_count >= FAR_MAX_OBJECTIVES)
			return FAR_ERR_FULL;
		existing_objective = find_objective(service, checkpoint.objective_id);
		if (existing_objective == NULL)
			return FAR_ERR_CORRUPT;
		service->checkpoints[service->checkpoint_count++] = checkpoint;
		existing_objective->checkpoint_sequence = checkpoint.sequence;
		existing_objective->state = FAR_OBJECTIVE_CHECKPOINTED;
		existing_objective->event_sequence = record->event.sequence;
		return FAR_OK;
	}
	if (record->event.kind == FAR_EVENT_TOOL_REQUEST) {
		if (record->event.payload_len != sizeof(tool) ||
		    service->tool_request_count >= FAR_MAX_TOOL_REQUESTS)
			return FAR_ERR_CORRUPT;
		memcpy(&tool, record->payload, sizeof(tool));
		service->tool_requests[service->tool_request_count++] = tool;
		return FAR_OK;
	}
	if (record->event.kind == FAR_EVENT_ANOMALY) {
		struct far_agent *agent;
		struct far_objective *objective;
		if (record->event.payload_len != sizeof(anomaly))
			return FAR_ERR_CORRUPT;
		memcpy(&anomaly, record->payload, sizeof(anomaly));
		agent = find_agent(service, anomaly.agent_id);
		if (agent == NULL)
			return FAR_ERR_CORRUPT;
		agent->state = FAR_AGENT_QUARANTINED;
		agent->generation++;
		objective = find_objective(service, anomaly.objective_id);
		if (objective != NULL) {
			objective->state = FAR_OBJECTIVE_QUARANTINED;
			objective->anomaly_count++;
		}
		service->anomaly_count++;
		return FAR_OK;
	}
	if (record->event.kind == FAR_EVENT_MESSAGE)
		return FAR_OK;
	return FAR_ERR_CORRUPT;
}

static int far_replay_locked(struct far_service *service)
{
	struct far_disk_record record;
	uint8_t previous[FAR_DIGEST_SIZE] = {0};
	int result;

	service->agent_count = 0U;
	service->objective_count = 0U;
	service->checkpoint_count = 0U;
	service->tool_request_count = 0U;
	service->next_agent_id = 1U;
	service->next_objective_id = 1U;
	service->event_sequence = 0U;
	service->anomaly_count = 0U;
	memset(service->chain_digest, 0, FAR_DIGEST_SIZE);
	if (m240_init(&service->budgets, &service->policy.budget_policy) != M240_OK)
		return FAR_ERR_BUDGET;
	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FAR_ERR_IO;
	while ((result = read_all(service->journal_fd, &record, sizeof(record))) == FAR_OK) {
		if (record.event.sequence != service->event_sequence + 1U ||
		    far_verify_event(&record.event, record.payload, previous) != FAR_OK)
			return FAR_ERR_TAMPER;
		if (apply_replay_record(service, &record) != FAR_OK)
			return FAR_ERR_CORRUPT;
		service->event_sequence = record.event.sequence;
		memcpy(previous, record.event.event_digest, FAR_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FAR_DIGEST_SIZE);
	}
	if (result != FAR_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FAR_ERR_IO;
	return FAR_OK;
}

int far_open(struct far_service *service, const char *journal_path,
	     const struct far_policy *policy)
{
	if (service == NULL || journal_path == NULL || policy == NULL ||
	    policy->budget_policy.current_time_ns == 0U)
		return FAR_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = -1;
	service->policy = *policy;
	if (pthread_mutex_init(&service->lock, NULL) != 0)
		return FAR_ERR_IO;
	service->lock_initialized = 1;
	service->journal_fd = open(journal_path, O_RDWR | O_CREAT | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FAR_ERR_IO;
	strncpy(service->journal_path, journal_path, sizeof(service->journal_path) - 1U);
	service->next_agent_id = 1U;
	service->next_objective_id = 1U;
	if (m240_init(&service->budgets, &policy->budget_policy) != M240_OK)
		return FAR_ERR_BUDGET;
	return far_replay(service);
}

void far_close(struct far_service *service)
{
	if (service == NULL)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
	if (service->lock_initialized) {
		pthread_mutex_destroy(&service->lock);
		service->lock_initialized = 0;
	}
}

int far_replay(struct far_service *service)
{
	int result;

	if (service == NULL || !service->lock_initialized)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	result = far_replay_locked(service);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_query_journal(const struct far_service *service,
		      struct far_journal_attestation *out)
{
	struct far_service *mutable_service;

	if (service == NULL || out == NULL || !service->lock_initialized)
		return FAR_ERR_ARGUMENT;
	mutable_service = (struct far_service *)service;
	pthread_mutex_lock(&mutable_service->lock);
	out->last_sequence = service->event_sequence;
	out->record_count = service->event_sequence;
	out->anomaly_count = service->anomaly_count;
	memcpy(out->chain_digest, service->chain_digest, FAR_DIGEST_SIZE);
	pthread_mutex_unlock(&mutable_service->lock);
	return FAR_OK;
}

int far_register_agent(struct far_service *service, uint64_t tenant_id,
		       uint64_t capability_mask, uint32_t trust_ppm,
		       const uint8_t identity_digest[FAR_DIGEST_SIZE],
		       const char *name, struct far_agent *out)
{
	struct far_agent agent;
	int result;

	if (service == NULL || identity_digest == NULL || name == NULL || out == NULL ||
	    tenant_id == 0U || capability_mask == 0U || trust_ppm > 1000000U ||
	    name[0] == '\0')
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (service->agent_count >= FAR_MAX_AGENTS) {
		pthread_mutex_unlock(&service->lock);
		return FAR_ERR_FULL;
	}
	memset(&agent, 0, sizeof(agent));
	agent.agent_id = service->next_agent_id++;
	agent.tenant_id = tenant_id;
	agent.generation = 1U;
	agent.capability_mask = capability_mask;
	agent.state = FAR_AGENT_READY;
	agent.trust_ppm = trust_ppm;
	memcpy(agent.identity_digest, identity_digest, FAR_DIGEST_SIZE);
	strncpy(agent.name, name, sizeof(agent.name) - 1U);
	service->agents[service->agent_count++] = agent;
	result = append_event_locked(service, FAR_EVENT_REGISTER_AGENT, agent.agent_id, 0U,
				     FAR_OK, service->policy.budget_policy.current_time_ns,
				     &agent, sizeof(agent), NULL);
	if (result == FAR_OK)
		*out = agent;
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_admit_objective(struct far_service *service,
			const struct far_objective *request,
			struct far_objective *out)
{
	struct far_objective objective;
	struct far_agent *agent;
	struct m240_request budget_request;
	struct m240_receipt budget_receipt;
	size_t previous_objective_count;
	size_t previous_record_count;
	size_t previous_receipt_count;
	uint64_t previous_next_objective_id;
	uint64_t previous_next_receipt_id;
	uint64_t previous_receipt_sequence;
	uint32_t previous_active_objectives;
	int budget_admitted = 0;
	int result;

	if (service == NULL || request == NULL || out == NULL)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	result = objective_valid(request, &service->policy);
	if (result != FAR_OK)
		goto done;
	if (service->objective_count >= FAR_MAX_OBJECTIVES)
		{ result = FAR_ERR_FULL; goto done; }
	agent = find_agent(service, request->agent_id);
	if (agent == NULL || agent->state == FAR_AGENT_QUARANTINED ||
	    agent->tenant_id != request->tenant_id)
		{ result = FAR_ERR_AUTHORITY; goto done; }
	if ((agent->capability_mask & request->required_capability_mask) !=
	    request->required_capability_mask)
		{ result = FAR_ERR_CAPABILITY; goto done; }
	if (find_objective_const(service, request->objective_id) != NULL &&
	    request->objective_id != 0U)
		{ result = FAR_ERR_DUPLICATE; goto done; }
	objective = *request;
	objective.objective_id = service->next_objective_id++;
	objective.state = FAR_OBJECTIVE_QUEUED;
	objective.checkpoint_sequence = 0U;
	objective.event_sequence = 0U;
	if (budget_request_from_objective(&objective, &budget_request) != FAR_OK)
		{ result = FAR_ERR_BUDGET; goto done; }
	previous_objective_count = service->objective_count;
	previous_record_count = service->budgets.record_count;
	previous_receipt_count = service->budgets.receipt_count;
	previous_next_objective_id = service->next_objective_id;
	previous_next_receipt_id = service->budgets.next_receipt_id;
	previous_receipt_sequence = service->budgets.receipt_sequence;
	previous_active_objectives = agent->active_objectives;
	result = m240_admit(&service->budgets, &budget_request, &budget_receipt);
	if (result != M240_OK)
		{ result = FAR_ERR_BUDGET; goto done; }
	budget_admitted = 1;
	service->objectives[service->objective_count++] = objective;
	agent->active_objectives++;
	result = objective_event_locked(service, FAR_EVENT_ADMIT_OBJECTIVE, &objective,
					FAR_OK, service->policy.budget_policy.current_time_ns);
		if (result == FAR_OK)
			*out = objective;
		else if (budget_admitted) {
		service->objective_count = previous_objective_count;
		service->next_objective_id = previous_next_objective_id;
		agent->active_objectives = previous_active_objectives;
		service->budgets.record_count = previous_record_count;
		service->budgets.receipt_count = previous_receipt_count;
		service->budgets.next_receipt_id = previous_next_receipt_id;
		service->budgets.receipt_sequence = previous_receipt_sequence;
	}
done:
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_dispatch(struct far_service *service, uint64_t objective_id,
		 uint64_t now_ns, struct far_objective *out)
{
	struct far_objective *objective;
	struct far_objective before;
	int result = FAR_OK;

	if (service == NULL || out == NULL || objective_id == 0U || now_ns == 0U)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (objective == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective->deadline_ns < now_ns)
		result = FAR_ERR_DEADLINE;
	else if (objective->state != FAR_OBJECTIVE_QUEUED &&
		 objective->state != FAR_OBJECTIVE_CHECKPOINTED)
		result = FAR_ERR_STATE;
	else {
		before = *objective;
		objective->state = FAR_OBJECTIVE_RUNNING;
		objective->event_sequence = 0U;
		result = objective_event_locked(service, FAR_EVENT_DISPATCH, objective,
					FAR_OK, now_ns);
		if (result == FAR_OK)
			*out = *objective;
		else
			*objective = before;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_checkpoint(struct far_service *service, uint64_t objective_id,
		   uint64_t now_ns, const uint8_t working_digest[FAR_DIGEST_SIZE],
		   const uint8_t memory_digest[FAR_DIGEST_SIZE],
		   const uint8_t world_digest[FAR_DIGEST_SIZE],
		   struct far_checkpoint *out)
{
	struct far_objective *objective;
	struct far_checkpoint checkpoint;
	uint64_t event_sequence;
	int result = FAR_OK;

	if (service == NULL || out == NULL || working_digest == NULL ||
	    memory_digest == NULL || world_digest == NULL || objective_id == 0U ||
	    now_ns == 0U || is_zero_digest(working_digest) ||
	    is_zero_digest(memory_digest) || is_zero_digest(world_digest))
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (objective == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective->state != FAR_OBJECTIVE_RUNNING &&
		 objective->state != FAR_OBJECTIVE_CHECKPOINTED)
		result = FAR_ERR_STATE;
	else if (now_ns > objective->deadline_ns)
		result = FAR_ERR_DEADLINE;
	else {
		memset(&checkpoint, 0, sizeof(checkpoint));
		checkpoint.objective_id = objective_id;
		checkpoint.task_generation = objective->task_generation;
		checkpoint.session_generation = objective->session_generation;
		checkpoint.sequence = objective->checkpoint_sequence + 1U;
		checkpoint.observed_at_ns = now_ns;
		checkpoint.verified = 1U;
		memcpy(checkpoint.working_digest, working_digest, FAR_DIGEST_SIZE);
		memcpy(checkpoint.memory_digest, memory_digest, FAR_DIGEST_SIZE);
		memcpy(checkpoint.world_digest, world_digest, FAR_DIGEST_SIZE);
		if (digest_bytes(service->budgets.records, sizeof(service->budgets.records),
				 checkpoint.budget_digest) != FAR_OK ||
		    checkpoint_digest(&checkpoint, checkpoint.checkpoint_digest) != FAR_OK)
			result = FAR_ERR_CHECKPOINT;
		else if (service->checkpoint_count >= FAR_MAX_OBJECTIVES)
			result = FAR_ERR_FULL;
		else {
			result = append_event_locked(service, FAR_EVENT_CHECKPOINT,
						     objective->agent_id, objective_id,
						     FAR_OK, now_ns, &checkpoint,
						     sizeof(checkpoint), &event_sequence);
			if (result == FAR_OK) {
				service->checkpoints[service->checkpoint_count++] = checkpoint;
				objective->checkpoint_sequence = checkpoint.sequence;
				objective->state = FAR_OBJECTIVE_CHECKPOINTED;
				objective->event_sequence = event_sequence;
				*out = checkpoint;
			}
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_recover(struct far_service *service, uint64_t objective_id,
		uint64_t now_ns, const struct far_checkpoint *checkpoint,
		struct far_objective *out)
{
		struct far_objective *objective;
	struct far_objective before;
	uint8_t digest[FAR_DIGEST_SIZE];
	int result = FAR_OK;
	if (service == NULL || checkpoint == NULL || out == NULL || objective_id == 0U ||
	    now_ns == 0U)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (objective == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (checkpoint->objective_id != objective_id || !checkpoint->verified ||
		 checkpoint->task_generation != objective->task_generation ||
		 checkpoint->session_generation != objective->session_generation ||
		 checkpoint_digest(checkpoint, digest) != FAR_OK ||
		 memcmp(digest, checkpoint->checkpoint_digest, FAR_DIGEST_SIZE) != 0)
		result = FAR_ERR_CHECKPOINT;
	else if (now_ns > objective->deadline_ns)
		result = FAR_ERR_DEADLINE;
	else if (objective->state != FAR_OBJECTIVE_CHECKPOINTED &&
		 objective->state != FAR_OBJECTIVE_RECOVERING)
		result = FAR_ERR_STATE;
	else {
		before = *objective;
		objective->state = FAR_OBJECTIVE_QUEUED;
		objective->flags |= FAR_FLAG_RECOVERY | FAR_FLAG_CHECKPOINT_VERIFIED;
		result = objective_event_locked(service, FAR_EVENT_RECOVER, objective,
					FAR_OK, now_ns);
		if (result == FAR_OK)
			*out = *objective;
		else
			*objective = before;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_request_tool(struct far_service *service,
		     const struct far_tool_request *request)
{
	struct far_objective *objective;
	struct far_agent *agent;
	int result = FAR_OK;

	if (service == NULL || request == NULL || request->request_id == 0U ||
	    request->objective_id == 0U || request->agent_id == 0U ||
	    request->agent_generation == 0U || request->capability == 0U ||
	    request->authority_lease_id == 0U || request->sequence == 0U ||
	    request->issued_at_ns == 0U || request->deadline_ns < request->issued_at_ns ||
	    request->tool_name[0] == '\0' || is_zero_digest(request->input_digest) ||
	    is_zero_digest(request->provenance_digest) ||
	    (request->flags & ~FAR_FLAGS_ALL) != 0U)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, request->objective_id);
	agent = find_agent(service, request->agent_id);
	if (objective == NULL || agent == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective->agent_id != request->agent_id ||
		 agent->generation != request->agent_generation ||
		 objective->state != FAR_OBJECTIVE_RUNNING)
		result = FAR_ERR_GENERATION;
	else if ((agent->capability_mask & request->capability) != request->capability)
		result = FAR_ERR_CAPABILITY;
	else if (service->policy.require_tool_authority &&
		 !(request->flags & FAR_FLAG_AUTHORITY_GRANTED))
		result = FAR_ERR_AUTHORITY;
	else if ((request->flags & FAR_FLAG_MODEL_PROPOSAL) &&
		 !(request->flags & FAR_FLAG_AUTHORITY_GRANTED))
		result = FAR_ERR_AUTHORITY;
	else if (request->deadline_ns > objective->deadline_ns)
		result = FAR_ERR_DEADLINE;
	else if (service->tool_request_count >= FAR_MAX_TOOL_REQUESTS)
		result = FAR_ERR_FULL;
	else {
		result = append_event_locked(service, FAR_EVENT_TOOL_REQUEST,
					     request->agent_id, request->objective_id,
					     FAR_OK, request->issued_at_ns, request,
					     sizeof(*request), NULL);
		if (result == FAR_OK)
			service->tool_requests[service->tool_request_count++] = *request;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_send_message(struct far_service *service,
		     const struct far_message *message)
{
	const struct far_agent *from;
	const struct far_agent *to;
	int result = FAR_OK;

	if (service == NULL || message == NULL || message->message_id == 0U ||
	    message->from_agent_id == 0U || message->to_agent_id == 0U ||
	    message->from_generation == 0U || message->sequence == 0U ||
	    message->observed_at_ns == 0U || is_zero_digest(message->payload_digest))
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	from = find_agent_const(service, message->from_agent_id);
	to = find_agent_const(service, message->to_agent_id);
	if (from == NULL || to == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (from->generation != message->from_generation)
		result = FAR_ERR_GENERATION;
	else if (service->policy.require_message_authority &&
		 !(message->flags & FAR_FLAG_AUTHORITY_GRANTED))
		result = FAR_ERR_AUTHORITY;
	else
		result = append_event_locked(service, FAR_EVENT_MESSAGE,
					     message->from_agent_id, message->objective_id,
					     FAR_OK, message->observed_at_ns, message,
					     sizeof(*message), NULL);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_record_anomaly(struct far_service *service, uint64_t agent_id,
		       uint64_t objective_id, uint64_t now_ns,
		       uint32_t severity, uint32_t violation_mask,
		       const uint8_t evidence_digest[FAR_DIGEST_SIZE],
		       struct far_agent *agent_out,
		       struct far_objective *objective_out)
{
	struct far_agent *agent;
	struct far_objective *objective = NULL;
	struct far_anomaly anomaly;
	int result;

	if (service == NULL || agent_id == 0U || now_ns == 0U || severity == 0U ||
	    violation_mask == 0U || evidence_digest == NULL ||
	    is_zero_digest(evidence_digest))
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	agent = find_agent(service, agent_id);
	if (agent == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective_id != 0U && (objective = find_objective(service, objective_id)) == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective != NULL && objective->agent_id != agent_id)
		result = FAR_ERR_AUTHORITY;
	else {
		memset(&anomaly, 0, sizeof(anomaly));
		anomaly.agent_id = agent_id;
		anomaly.objective_id = objective_id;
		anomaly.observed_at_ns = now_ns;
		anomaly.severity = severity;
		anomaly.violation_mask = violation_mask;
		memcpy(anomaly.evidence_digest, evidence_digest, FAR_DIGEST_SIZE);
		agent->state = FAR_AGENT_QUARANTINED;
		agent->generation++;
		if (objective != NULL) {
			objective->state = FAR_OBJECTIVE_QUARANTINED;
			objective->anomaly_count++;
			strncpy(objective->reason, "anomaly-quarantined", sizeof(objective->reason) - 1U);
		}
		service->anomaly_count++;
		result = append_event_locked(service, FAR_EVENT_ANOMALY, agent_id,
					     objective_id, FAR_ERR_QUARANTINED,
					     now_ns, &anomaly, sizeof(anomaly), NULL);
		if (result == FAR_OK) {
			if (agent_out != NULL)
				*agent_out = *agent;
			if (objective_out != NULL && objective != NULL)
				*objective_out = *objective;
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int finish_objective(struct far_service *service, uint64_t objective_id,
			    uint64_t now_ns, uint32_t state, int status,
			    const uint8_t result_digest[FAR_DIGEST_SIZE],
			    const char *reason, struct far_objective *out,
			    uint16_t event_kind)
{
	struct far_objective *objective;
	struct far_agent *agent;
	struct m240_receipt receipt;
	int result = FAR_OK;

	if (service == NULL || out == NULL || objective_id == 0U || now_ns == 0U)
		return FAR_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	objective = find_objective(service, objective_id);
	if (objective == NULL)
		result = FAR_ERR_NOT_FOUND;
	else if (objective->state == FAR_OBJECTIVE_SUCCEEDED ||
		 objective->state == FAR_OBJECTIVE_FAILED ||
		 objective->state == FAR_OBJECTIVE_CANCELLED)
		result = FAR_ERR_STATE;
	else if (now_ns > objective->deadline_ns && state != FAR_OBJECTIVE_CANCELLED)
		result = FAR_ERR_DEADLINE;
	else {
		objective->state = state;
		if (reason != NULL)
			strncpy(objective->reason, reason, sizeof(objective->reason) - 1U);
		if (result_digest != NULL)
			memcpy(objective->result_digest, result_digest, FAR_DIGEST_SIZE);
		agent = find_agent(service, objective->agent_id);
		if (agent != NULL && agent->active_objectives != 0U)
			agent->active_objectives--;
		if (state == FAR_OBJECTIVE_SUCCEEDED)
			(void)m240_complete(&service->budgets, objective_id,
					    objective->task_generation,
					    objective->session_generation, now_ns,
					    &receipt);
		else if (state == FAR_OBJECTIVE_CANCELLED)
			(void)m240_cancel(&service->budgets, objective_id,
					  objective->task_generation,
					  objective->session_generation, now_ns, &receipt);
		result = objective_event_locked(service, event_kind, objective, status,
					 now_ns);
		if (result == FAR_OK)
			*out = *objective;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int far_complete(struct far_service *service, uint64_t objective_id,
		 uint64_t now_ns, const uint8_t result_digest[FAR_DIGEST_SIZE],
		 struct far_objective *out)
{
	if (result_digest == NULL || is_zero_digest(result_digest))
		return FAR_ERR_ARGUMENT;
	return finish_objective(service, objective_id, now_ns,
				FAR_OBJECTIVE_SUCCEEDED, FAR_OK, result_digest,
				NULL, out, FAR_EVENT_COMPLETE);
}

int far_fail(struct far_service *service, uint64_t objective_id,
	     uint64_t now_ns, const char *reason, struct far_objective *out)
{
	if (reason == NULL || reason[0] == '\0')
		return FAR_ERR_ARGUMENT;
	return finish_objective(service, objective_id, now_ns,
				FAR_OBJECTIVE_FAILED, FAR_ERR_STATE, NULL,
				reason, out, FAR_EVENT_FAIL);
}

int far_cancel(struct far_service *service, uint64_t objective_id,
	       uint64_t now_ns, struct far_objective *out)
{
	return finish_objective(service, objective_id, now_ns,
				FAR_OBJECTIVE_CANCELLED, FAR_OK, NULL,
				"cancelled", out, FAR_EVENT_CANCEL);
}

int far_query_agent(const struct far_service *service, uint64_t agent_id,
		   struct far_agent *out)
{
	const struct far_agent *agent;
	struct far_service *mutable_service;

	if (service == NULL || out == NULL || agent_id == 0U ||
	    !service->lock_initialized)
		return FAR_ERR_ARGUMENT;
	mutable_service = (struct far_service *)service;
	pthread_mutex_lock(&mutable_service->lock);
	agent = find_agent_const(service, agent_id);
	if (agent == NULL) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FAR_ERR_NOT_FOUND;
	}
	*out = *agent;
	pthread_mutex_unlock(&mutable_service->lock);
	return FAR_OK;
}

int far_query_objective(const struct far_service *service,
		       uint64_t objective_id, struct far_objective *out)
{
	const struct far_objective *objective;
	struct far_service *mutable_service;

	if (service == NULL || out == NULL || objective_id == 0U ||
	    !service->lock_initialized)
		return FAR_ERR_ARGUMENT;
	mutable_service = (struct far_service *)service;
	pthread_mutex_lock(&mutable_service->lock);
	objective = find_objective_const(service, objective_id);
	if (objective == NULL) {
		pthread_mutex_unlock(&mutable_service->lock);
		return FAR_ERR_NOT_FOUND;
	}
	*out = *objective;
	pthread_mutex_unlock(&mutable_service->lock);
	return FAR_OK;
}
