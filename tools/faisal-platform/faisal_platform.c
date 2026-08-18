#include "faisal_platform.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FPL_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FPL_ERR_TAMPER;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FPL_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FPL_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, length) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FPL_DIGEST_SIZE)
		result = FPL_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int digest_present(const uint8_t digest[FPL_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 0;
	for (i = 0U; i < FPL_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 1;
	return 0;
}

static int bounded_string(const char *value, size_t size)
{
	return value != NULL && value[0] != '\0' && memchr(value, '\0', size) != NULL;
}

static int write_full(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;
	size_t written = 0U;
	ssize_t count;

	while (written < length) {
		count = write(fd, bytes + written, length - written);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return FPL_ERR_IO;
		written += (size_t)count;
	}
	return FPL_OK;
}

static int read_full(int fd, void *data, size_t length)
{
	uint8_t *bytes = data;
	size_t read_bytes = 0U;
	ssize_t count;

	while (read_bytes < length) {
		count = read(fd, bytes + read_bytes, length - read_bytes);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return read_bytes == 0U ? FPL_ERR_NOT_FOUND : FPL_ERR_CORRUPT;
		if (count < 0)
			return FPL_ERR_IO;
		read_bytes += (size_t)count;
	}
	return FPL_OK;
}

static int digest_event(const struct fpl_event *event, const uint8_t *payload,
			 size_t payload_len, uint8_t digest[FPL_DIGEST_SIZE])
{
	struct fpl_event canonical;
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FPL_ERR_TAMPER;

	if (event == NULL || (payload == NULL && payload_len != 0U) || digest == NULL)
		return FPL_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, sizeof(canonical.event_digest));
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FPL_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, &canonical, sizeof(canonical)) == 1 &&
	    EVP_DigestUpdate(ctx, payload, payload_len) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FPL_DIGEST_SIZE)
		result = FPL_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

static void copy_text(char *destination, size_t destination_size,
		      const char *source)
{
	size_t length = 0U;

	if (destination == NULL || destination_size == 0U)
		return;
	if (source != NULL)
		while (length + 1U < destination_size && source[length] != '\0')
			++length;
	if (length != 0U)
		memcpy(destination, source, length);
	destination[length] = '\0';
}

static int node_index(const struct fpl_service *service, uint64_t node_id)
{
	size_t i;

	for (i = 0U; i < service->node_count; ++i)
		if (service->nodes[i].node_id == node_id)
			return (int)i;
	return -1;
}

static int workload_index(const struct fpl_service *service, uint64_t workload_id)
{
	size_t i;

	for (i = 0U; i < service->workload_count; ++i)
		if (service->workloads[i].intent.workload_id == workload_id)
			return (int)i;
	return -1;
}

static int valid_node(const struct fpl_node *node)
{
	if (node == NULL || node->node_id == 0U || node->generation == 0U ||
	    node->total_cpu_millis < node->free_cpu_millis ||
	    node->total_memory_bytes < node->free_memory_bytes ||
	    node->total_network_mbps < node->free_network_mbps ||
	    node->total_storage_bytes < node->free_storage_bytes ||
	    node->health_ppm > 1000000U || node->state < FPL_NODE_READY ||
	    node->state > FPL_NODE_QUARANTINED ||
	    !bounded_string(node->provider, sizeof(node->provider)) ||
	    memchr(node->zone, '\0', sizeof(node->zone)) == NULL ||
	    memchr(node->rack, '\0', sizeof(node->rack)) == NULL ||
	    memchr(node->fabric, '\0', sizeof(node->fabric)) == NULL)
		return FPL_ERR_ARGUMENT;
	return FPL_OK;
}

static int valid_policy(const struct fpl_policy *policy)
{
	if (policy == NULL || policy->current_time_ns == 0U ||
	    policy->max_intent_age_ns == 0U || policy->max_workloads == 0U ||
	    policy->max_workloads > FPL_MAX_WORKLOADS ||
	    policy->max_recovery_attempts == 0U ||
	    policy->max_recovery_attempts > FPL_MAX_RECOVERY_ATTEMPTS ||
	    (policy->flags & ~(FPL_REQUIRE_AUTHORITY | FPL_REQUIRE_LINEAGE |
			       FPL_REQUIRE_TOPOLOGY | FPL_FAIL_CLOSED)) != 0U ||
	    ((policy->flags & FPL_REQUIRE_AUTHORITY) &&
	     !digest_present(policy->authority_digest)))
		return FPL_ERR_ARGUMENT;
	return FPL_OK;
}

static int valid_intent(const struct fpl_service *service,
			const struct fpl_intent *intent)
{
	uint32_t gang;

	if (service == NULL || intent == NULL || intent->abi_version != FPL_ABI_VERSION ||
	    intent->workload_id == 0U || intent->tenant_id == 0U || intent->agent_id == 0U ||
	    intent->objective_id == 0U || intent->created_at_ns == 0U ||
	    intent->deadline_ns < intent->created_at_ns ||
	    intent->required_cpu_millis == 0U || intent->required_memory_bytes == 0U ||
	    intent->required_network_mbps == 0U || intent->required_storage_bytes == 0U ||
	    !bounded_string(intent->tenant, sizeof(intent->tenant)) ||
	    !bounded_string(intent->model_id, sizeof(intent->model_id)) ||
	    !bounded_string(intent->objective, sizeof(intent->objective)) ||
	    intent->provider_kind < FPL_PROVIDER_KUBERNETES_DRA ||
	    intent->provider_kind > FPL_PROVIDER_EDGE ||
	    intent->replicas == 0U || intent->replicas > FPL_MAX_GANG ||
	    intent->gang_size == 0U || intent->gang_size > FPL_MAX_GANG ||
	    intent->replicas != intent->gang_size ||
	    (intent->provider_kind != FPL_PROVIDER_BARE_METAL &&
	     !digest_present(intent->provider_claim_digest)) ||
	    (service->policy.flags & FPL_REQUIRE_AUTHORITY && !intent->authorized) ||
	    (service->policy.flags & FPL_REQUIRE_LINEAGE &&
	     !digest_present(intent->lineage_digest)) ||
	    (service->policy.flags & FPL_REQUIRE_TOPOLOGY &&
	     !intent->zone[0] && !intent->rack[0] && !intent->fabric[0]) ||
	    service->policy.current_time_ns < intent->created_at_ns ||
	    service->policy.current_time_ns - intent->created_at_ns >
		service->policy.max_intent_age_ns)
		return FPL_ERR_POLICY;
	gang = intent->gang_size;
	(void)gang;
	return FPL_OK;
}

static int append_record_locked(struct fpl_service *service, uint16_t kind,
				uint64_t workload_id, uint64_t node_id,
				uint64_t generation, uint64_t observed_at_ns,
				int32_t status, const void *payload, size_t payload_len)
{
	struct fpl_disk_record record;
	int result;

	if (service == NULL || (payload == NULL && payload_len != 0U) ||
	    payload_len > FPL_MAX_PAYLOAD)
		return FPL_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FPL_EVENT_MAGIC;
	record.event.version = FPL_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->next_sequence;
	record.event.workload_id = workload_id;
	record.event.node_id = node_id;
	record.event.generation = generation;
	record.event.observed_at_ns = observed_at_ns;
	record.event.status = status;
	record.event.payload_len = (uint32_t)payload_len;
	memcpy(record.event.previous_digest, service->chain_digest,
	       FPL_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	if (digest_bytes(record.payload, payload_len,
			 record.event.payload_digest) != FPL_OK ||
	    digest_event(&record.event, record.payload, payload_len,
			 record.event.event_digest) != FPL_OK)
		return FPL_ERR_TAMPER;
	result = write_full(service->journal_fd, &record, sizeof(record));
	if (result != FPL_OK || fdatasync(service->journal_fd) != 0)
		return FPL_ERR_IO;
	service->next_sequence++;
	memcpy(service->chain_digest, record.event.event_digest, FPL_DIGEST_SIZE);
	return FPL_OK;
}

static int read_record(int fd, struct fpl_disk_record *record)
{
	return read_full(fd, record, sizeof(*record));
}

static int replace_node(struct fpl_service *service, const struct fpl_node *node)
{
	int index;

	index = node_index(service, node->node_id);
	if (index < 0) {
		if (service->node_count >= FPL_MAX_NODES)
			return FPL_ERR_FULL;
		service->nodes[service->node_count++] = *node;
	} else {
		service->nodes[index] = *node;
	}
	return FPL_OK;
}

static int replace_workload(struct fpl_service *service,
				const struct fpl_workload *workload)
{
	int index;

	index = workload_index(service, workload->intent.workload_id);
	if (index < 0) {
		if (service->workload_count >= service->policy.max_workloads)
			return FPL_ERR_FULL;
		service->workloads[service->workload_count++] = *workload;
	} else {
		service->workloads[index] = *workload;
	}
	if (workload->assignment.assignment_id >= service->next_assignment_id)
		service->next_assignment_id = workload->assignment.assignment_id + 1U;
	return FPL_OK;
}

static int apply_record(struct fpl_service *service,
			const struct fpl_disk_record *record)
{
	struct fpl_cluster_snapshot snapshot;
	struct fpl_node node;
	struct fpl_workload workload;
	int result;

	if (record->event.payload_len > FPL_MAX_PAYLOAD)
		return FPL_ERR_CORRUPT;
	switch (record->event.kind) {
	case FPL_EVENT_NODE_UPSERT:
	case FPL_EVENT_NODE_FAILURE:
		if (record->event.payload_len != sizeof(node))
			return FPL_ERR_CORRUPT;
		memcpy(&node, record->payload, sizeof(node));
		if (valid_node(&node) != FPL_OK || node.node_id != record->event.node_id ||
		    node.generation != record->event.generation)
			return FPL_ERR_CORRUPT;
		result = replace_node(service, &node);
		if (record->event.kind == FPL_EVENT_NODE_FAILURE && result == FPL_OK)
			service->failed_nodes++;
		return result;
	case FPL_EVENT_WORKLOAD_SUBMIT:
	case FPL_EVENT_WORKLOAD_CHECKPOINT:
	case FPL_EVENT_WORKLOAD_RECOVERY:
		if (record->event.payload_len != sizeof(workload))
			return FPL_ERR_CORRUPT;
		memcpy(&workload, record->payload, sizeof(workload));
		if (workload.intent.workload_id != record->event.workload_id ||
		    workload.intent.abi_version != FPL_ABI_VERSION)
			return FPL_ERR_CORRUPT;
		return replace_workload(service, &workload);
	case FPL_EVENT_WORKLOAD_COMPLETE:
	case FPL_EVENT_WORKLOAD_FAILURE:
	case FPL_EVENT_WORKLOAD_SNAPSHOT:
		if (record->event.payload_len != sizeof(snapshot))
			return FPL_ERR_CORRUPT;
		memcpy(&snapshot, record->payload, sizeof(snapshot));
		if (snapshot.workload.intent.workload_id != record->event.workload_id ||
		    snapshot.node_count > FPL_MAX_NODES)
			return FPL_ERR_CORRUPT;
		service->node_count = 0U;
		memset(service->nodes, 0, sizeof(service->nodes));
		for (uint32_t i = 0U; i < snapshot.node_count; ++i) {
			if (valid_node(&snapshot.nodes[i]) != FPL_OK ||
			    replace_node(service, &snapshot.nodes[i]) != FPL_OK)
				return FPL_ERR_CORRUPT;
		}
		return replace_workload(service, &snapshot.workload);
	default:
		return FPL_ERR_CORRUPT;
	}
}

static void reset_replay_state(struct fpl_service *service)
{
	service->node_count = 0U;
	service->workload_count = 0U;
	service->next_assignment_id = 1U;
	service->next_sequence = 1U;
	service->recovery_count = 0U;
	service->failed_nodes = 0U;
	memset(service->nodes, 0, sizeof(service->nodes));
	memset(service->workloads, 0, sizeof(service->workloads));
	memset(service->chain_digest, 0, sizeof(service->chain_digest));
}

static int replay_locked(struct fpl_service *service)
{
	struct fpl_disk_record record;
	uint8_t previous[FPL_DIGEST_SIZE] = {0};
	uint8_t payload_digest[FPL_DIGEST_SIZE];
	uint8_t event_digest[FPL_DIGEST_SIZE];
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FPL_ERR_IO;
	while ((result = read_record(service->journal_fd, &record)) == FPL_OK) {
		if (record.event.payload_len > FPL_MAX_PAYLOAD ||
		    record.event.magic != FPL_EVENT_MAGIC ||
		    record.event.version != FPL_EVENT_VERSION ||
		    record.event.sequence != service->next_sequence ||
		    memcmp(record.event.previous_digest, previous, FPL_DIGEST_SIZE) != 0 ||
		    digest_bytes(record.payload, record.event.payload_len,
				 payload_digest) != FPL_OK ||
		    memcmp(payload_digest, record.event.payload_digest,
			   FPL_DIGEST_SIZE) != 0 ||
		    digest_event(&record.event, record.payload, record.event.payload_len,
				 event_digest) != FPL_OK ||
		    memcmp(event_digest, record.event.event_digest,
			   FPL_DIGEST_SIZE) != 0)
			return FPL_ERR_REPLAY;
		if (apply_record(service, &record) != FPL_OK)
			return FPL_ERR_CORRUPT;
		service->next_sequence++;
		memcpy(previous, record.event.event_digest, FPL_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FPL_DIGEST_SIZE);
	}
	if (result != FPL_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FPL_ERR_IO;
	return FPL_OK;
}

int fpl_open(struct fpl_service *service, const char *journal_path,
	     const struct fpl_policy *policy)
{
	int result;

	if (service == NULL || journal_path == NULL || valid_policy(policy) != FPL_OK)
		return FPL_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->policy = *policy;
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FPL_ERR_IO;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FPL_ERR_IO;
	}
	service->next_assignment_id = 1U;
	service->next_sequence = 1U;
	result = replay_locked(service);
	if (result != FPL_OK) {
		pthread_mutex_destroy(&service->lock);
		close(service->journal_fd);
	}
	return result;
}

void fpl_close(struct fpl_service *service)
{
	if (service == NULL)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	if (service->journal_fd >= 0)
		pthread_mutex_destroy(&service->lock);
	service->journal_fd = -1;
}

int fpl_replay(struct fpl_service *service)
{
	int result;

	if (service == NULL || service->journal_fd < 0)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	reset_replay_state(service);
	result = replay_locked(service);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_query_attestation(const struct fpl_service *service,
			  struct fpl_attestation *out)
{
	size_t i;
	uint64_t recovery_count = 0U;

	if (service == NULL || out == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FPL_ERR_IO;
	for (i = 0U; i < service->workload_count; ++i)
		recovery_count += service->workloads[i].recovery_attempts;
	memset(out, 0, sizeof(*out));
	out->last_sequence = service->next_sequence - 1U;
	out->next_workload_id = service->workload_count + 1U;
	out->next_assignment_id = service->next_assignment_id;
	out->recovery_count = recovery_count;
	out->failed_nodes = service->failed_nodes;
	memcpy(out->chain_digest, service->chain_digest, FPL_DIGEST_SIZE);
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FPL_OK;
}

int fpl_add_node(struct fpl_service *service, const struct fpl_node *node)
{
	int result;

	if (service == NULL || valid_node(node) != FPL_OK)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	if (node_index(service, node->node_id) >= 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_STATE;
	}
	if (service->node_count >= FPL_MAX_NODES) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_FULL;
	}
	result = append_record_locked(service, FPL_EVENT_NODE_UPSERT, 0U,
				      node->node_id, node->generation,
				      service->policy.current_time_ns, FPL_OK,
				      node, sizeof(*node));
	if (result == FPL_OK)
		service->nodes[service->node_count++] = *node;
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_heartbeat(struct fpl_service *service, const struct fpl_node *node)
{
	int index;
	int result;

	if (service == NULL || valid_node(node) != FPL_OK)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = node_index(service, node->node_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	if (node->generation < service->nodes[index].generation) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_GENERATION;
	}
	result = append_record_locked(service, FPL_EVENT_NODE_UPSERT, 0U,
				      node->node_id, node->generation,
				      service->policy.current_time_ns, FPL_OK,
				      node, sizeof(*node));
	if (result == FPL_OK)
		service->nodes[index] = *node;
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_fail_node(struct fpl_service *service, uint64_t node_id,
		  uint64_t generation)
{
	struct fpl_node failed;
	int index;
	int result;

	if (service == NULL || node_id == 0U || generation == 0U)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = node_index(service, node_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	if (service->nodes[index].generation != generation) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_GENERATION;
	}
	failed = service->nodes[index];
	failed.state = FPL_NODE_FAILED;
	failed.generation++;
	result = append_record_locked(service, FPL_EVENT_NODE_FAILURE, 0U,
				      failed.node_id, failed.generation,
				      service->policy.current_time_ns, FPL_OK,
				      &failed, sizeof(failed));
	if (result == FPL_OK) {
		service->nodes[index] = failed;
		service->failed_nodes++;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_submit(struct fpl_service *service, const struct fpl_intent *intent,
	      struct fpl_workload *out)
{
	struct fpl_workload workload;
	int result;

	if (service == NULL || out == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	result = valid_intent(service, intent);
	if (result != FPL_OK) {
		pthread_mutex_unlock(&service->lock);
		return result == FPL_ERR_POLICY &&
			(intent != NULL && !intent->authorized) ? FPL_ERR_AUTHORITY : result;
	}
	if (workload_index(service, intent->workload_id) >= 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_STATE;
	}
	if (service->workload_count >= service->policy.max_workloads) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_FULL;
	}
	memset(&workload, 0, sizeof(workload));
	workload.intent = *intent;
	workload.state = FPL_WORKLOAD_SUBMITTED;
	workload.last_transition_ns = service->policy.current_time_ns;
	result = append_record_locked(service, FPL_EVENT_WORKLOAD_SUBMIT,
				      intent->workload_id, 0U, 0U,
				      intent->created_at_ns, FPL_OK,
				      &workload, sizeof(workload));
	if (result == FPL_OK) {
		service->workloads[service->workload_count++] = workload;
		*out = workload;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int node_meets_intent(const struct fpl_node *node,
			     const struct fpl_intent *intent)
{
	return node->state == FPL_NODE_READY && node->health_ppm >= 800000U &&
	       node->free_network_mbps >= intent->required_network_mbps &&
	       node->free_storage_bytes >= intent->required_storage_bytes;
}

static int make_snapshot(const struct fpl_service *service,
			 const struct fpl_workload *workload,
			 const struct fpl_node nodes[FPL_MAX_NODES],
			 uint32_t node_count, struct fpl_cluster_snapshot *out)
{
	if (service == NULL || workload == NULL || nodes == NULL || out == NULL ||
		node_count > FPL_MAX_NODES)
		return FPL_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->workload = *workload;
	out->node_count = node_count;
	memcpy(out->nodes, nodes, (size_t)node_count * sizeof(nodes[0]));
	return FPL_OK;
}

static int place_locked(struct fpl_service *service, size_t workload_idx,
			uint64_t now_ns, uint32_t recovery,
			struct fpl_workload *out)
{
	struct fpl_workload candidate;
	struct fpl_cluster_snapshot snapshot;
	struct fle_service fleet;
	struct fle_intent fleet_intent;
	struct fle_assignment fleet_assignment;
	struct fpl_node updated_nodes[FPL_MAX_NODES];
	uint32_t fleet_policy = FLE_POLICY_FAIL_CLOSED;
	uint32_t eligible_nodes = 0U;
	int result;
	uint32_t i;

	candidate = service->workloads[workload_idx];
	if (candidate.state != FPL_WORKLOAD_SUBMITTED &&
	    candidate.state != FPL_WORKLOAD_RECOVERING)
		return FPL_ERR_STATE;
	if (now_ns > candidate.intent.deadline_ns)
		return FPL_ERR_DEADLINE;
	if (service->policy.flags & FPL_REQUIRE_AUTHORITY)
		fleet_policy |= FLE_POLICY_REQUIRE_AUTHORITY;
	if (service->policy.flags & FPL_REQUIRE_LINEAGE)
		fleet_policy |= FLE_POLICY_REQUIRE_LINEAGE;
	if (service->policy.flags & FPL_REQUIRE_TOPOLOGY)
		fleet_policy |= FLE_POLICY_REQUIRE_TOPOLOGY;
	result = fle_init(&fleet, fleet_policy, now_ns);
	if (result != FLE_OK)
		return FPL_ERR_STATE;
	memcpy(updated_nodes, service->nodes, sizeof(updated_nodes));
	for (i = 0U; i < service->node_count; ++i) {
		struct fle_node fleet_node;
		if (!node_meets_intent(&service->nodes[i], &candidate.intent))
			continue;
		memset(&fleet_node, 0, sizeof(fleet_node));
		fleet_node.node_id = service->nodes[i].node_id;
		fleet_node.generation = service->nodes[i].generation;
		fleet_node.total_cpu_millis = service->nodes[i].total_cpu_millis;
		fleet_node.free_cpu_millis = service->nodes[i].free_cpu_millis;
		fleet_node.total_memory_bytes = service->nodes[i].total_memory_bytes;
		fleet_node.free_memory_bytes = service->nodes[i].free_memory_bytes;
		fleet_node.accelerator_mask = service->nodes[i].accelerator_mask;
		fleet_node.accelerator_count = service->nodes[i].accelerator_count;
		fleet_node.capability_mask = service->nodes[i].capability_mask;
		fleet_node.health_ppm = service->nodes[i].health_ppm;
		fleet_node.state = FLE_STATE_READY;
		snprintf(fleet_node.zone, sizeof(fleet_node.zone), "%s", service->nodes[i].zone);
		snprintf(fleet_node.rack, sizeof(fleet_node.rack), "%s", service->nodes[i].rack);
		snprintf(fleet_node.fabric, sizeof(fleet_node.fabric), "%s", service->nodes[i].fabric);
		if (fle_add_node(&fleet, &fleet_node) == FLE_OK)
			eligible_nodes++;
	}
	if (eligible_nodes < candidate.intent.gang_size)
		return FPL_ERR_NO_PLACEMENT;
	memset(&fleet_intent, 0, sizeof(fleet_intent));
	fleet_intent.abi_version = FLE_ABI_VERSION;
	fleet_intent.policy_flags = fleet_policy;
	fleet_intent.objective_id = candidate.intent.objective_id;
	fleet_intent.tenant_id = candidate.intent.tenant_id;
	fleet_intent.agent_id = candidate.intent.agent_id;
	fleet_intent.expected_node_generation = 1U;
	fleet_intent.deadline_ns = candidate.intent.deadline_ns;
	fleet_intent.required_cpu_millis = candidate.intent.required_cpu_millis;
	fleet_intent.required_memory_bytes = candidate.intent.required_memory_bytes;
	fleet_intent.required_accelerator_mask = candidate.intent.required_accelerator_mask;
	fleet_intent.required_accelerator_count = candidate.intent.required_accelerator_count;
	fleet_intent.required_capability_mask = candidate.intent.required_capability_mask;
	fleet_intent.gang_size = candidate.intent.gang_size;
	fleet_intent.authorized = candidate.intent.authorized;
		copy_text(fleet_intent.tenant, sizeof(fleet_intent.tenant), candidate.intent.tenant);
		copy_text(fleet_intent.objective, sizeof(fleet_intent.objective), candidate.intent.objective);
		copy_text(fleet_intent.zone, sizeof(fleet_intent.zone), candidate.intent.zone);
		copy_text(fleet_intent.rack, sizeof(fleet_intent.rack), candidate.intent.rack);
		copy_text(fleet_intent.fabric, sizeof(fleet_intent.fabric), candidate.intent.fabric);
	memcpy(fleet_intent.lineage_digest, candidate.intent.lineage_digest, FPL_DIGEST_SIZE);
	result = fle_place(&fleet, &fleet_intent, &fleet_assignment);
	if (result != FLE_OK)
		return result == FLE_ERR_NO_PLACEMENT ? FPL_ERR_NO_PLACEMENT : FPL_ERR_POLICY;
	for (i = 0U; i < fleet_assignment.selected_count; ++i) {
		int node_idx = node_index(service, fleet_assignment.selected_nodes[i]);
		if (node_idx < 0 || updated_nodes[node_idx].generation != service->nodes[node_idx].generation ||
		    updated_nodes[node_idx].free_cpu_millis < candidate.intent.required_cpu_millis ||
		    updated_nodes[node_idx].free_memory_bytes < candidate.intent.required_memory_bytes ||
		    updated_nodes[node_idx].free_network_mbps < candidate.intent.required_network_mbps ||
		    updated_nodes[node_idx].free_storage_bytes < candidate.intent.required_storage_bytes)
			return FPL_ERR_STALE;
		updated_nodes[node_idx].free_cpu_millis -= candidate.intent.required_cpu_millis;
		updated_nodes[node_idx].free_memory_bytes -= candidate.intent.required_memory_bytes;
		updated_nodes[node_idx].free_network_mbps -= candidate.intent.required_network_mbps;
		updated_nodes[node_idx].free_storage_bytes -= candidate.intent.required_storage_bytes;
	}
	candidate.assignment.assignment_id = service->next_assignment_id;
	candidate.assignment.workload_id = candidate.intent.workload_id;
	candidate.assignment.placement_generation = service->next_sequence;
	candidate.assignment.recovery_sequence = recovery;
	candidate.assignment.state = FPL_WORKLOAD_PLACED;
	candidate.assignment.selected_count = fleet_assignment.selected_count;
	candidate.assignment.score = fleet_assignment.score;
	candidate.assignment.violation_mask = 0U;
	candidate.assignment.reason[0] = '\0';
	snprintf(candidate.assignment.reason, sizeof(candidate.assignment.reason),
		 "provider=%u gang=%u zone=%.31s rack=%.31s fabric=%.31s claim=verified",
		 candidate.intent.provider_kind, candidate.intent.gang_size,
		 candidate.intent.zone, candidate.intent.rack, candidate.intent.fabric);
	for (i = 0U; i < fleet_assignment.selected_count; ++i)
		candidate.assignment.selected_nodes[i] = fleet_assignment.selected_nodes[i];
	candidate.assignment.selected_count = fleet_assignment.selected_count;
	if (digest_bytes(&candidate.assignment, sizeof(candidate.assignment),
			candidate.assignment.evidence_digest) != FPL_OK)
		return FPL_ERR_TAMPER;
	candidate.state = FPL_WORKLOAD_PLACED;
	candidate.last_transition_ns = now_ns;
	candidate.recovery_attempts = recovery;
	result = make_snapshot(service, &candidate, updated_nodes,
				 service->node_count, &snapshot);
	if (result != FPL_OK)
		return result;
	result = append_record_locked(service, FPL_EVENT_WORKLOAD_SNAPSHOT,
				      candidate.intent.workload_id, 0U,
				      candidate.assignment.placement_generation,
				      now_ns, FPL_OK, &snapshot, sizeof(snapshot));
	if (result != FPL_OK)
		return result;
	memcpy(service->nodes, updated_nodes, sizeof(updated_nodes));
	service->workloads[workload_idx] = candidate;
	service->next_assignment_id++;
	if (recovery != 0U)
		service->recovery_count++;
	if (out != NULL)
		*out = candidate;
	return FPL_OK;
}

int fpl_place(struct fpl_service *service, uint64_t workload_id,
	     struct fpl_workload *out)
{
	int index;
	int result;

	if (service == NULL || workload_id == 0U || out == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	result = index < 0 ? FPL_ERR_NOT_FOUND :
		place_locked(service, (size_t)index, service->policy.current_time_ns,
			     service->workloads[index].recovery_attempts, out);
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int release_nodes(const struct fpl_service *service,
			 const struct fpl_workload *workload,
			 struct fpl_node nodes[FPL_MAX_NODES])
{
	uint32_t i;

	memcpy(nodes, service->nodes, sizeof(service->nodes));
	for (i = 0U; i < workload->assignment.selected_count; ++i) {
		int index = node_index(service, workload->assignment.selected_nodes[i]);
		if (index < 0)
			continue;
		if (nodes[index].free_cpu_millis > nodes[index].total_cpu_millis -
			workload->intent.required_cpu_millis ||
		    nodes[index].free_memory_bytes > nodes[index].total_memory_bytes -
			workload->intent.required_memory_bytes ||
		    nodes[index].free_network_mbps > nodes[index].total_network_mbps -
			workload->intent.required_network_mbps ||
		    nodes[index].free_storage_bytes > nodes[index].total_storage_bytes -
			workload->intent.required_storage_bytes)
			return FPL_ERR_OVERFLOW;
		nodes[index].free_cpu_millis += workload->intent.required_cpu_millis;
		nodes[index].free_memory_bytes += workload->intent.required_memory_bytes;
		nodes[index].free_network_mbps += workload->intent.required_network_mbps;
		nodes[index].free_storage_bytes += workload->intent.required_storage_bytes;
	}
	return FPL_OK;
}

int fpl_checkpoint(struct fpl_service *service, uint64_t workload_id,
		   uint64_t now_ns,
		   const uint8_t checkpoint_digest[FPL_DIGEST_SIZE])
{
	struct fpl_workload workload;
	int index;
	int result;

	if (service == NULL || workload_id == 0U || now_ns == 0U ||
	    !digest_present(checkpoint_digest))
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	workload = service->workloads[index];
	if (workload.state != FPL_WORKLOAD_PLACED &&
	    workload.state != FPL_WORKLOAD_CHECKPOINTED) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_STATE;
	}
	memcpy(workload.checkpoint_digest, checkpoint_digest, FPL_DIGEST_SIZE);
	workload.checkpoint_sequence = service->next_sequence;
	workload.state = FPL_WORKLOAD_CHECKPOINTED;
	workload.last_transition_ns = now_ns;
	result = append_record_locked(service, FPL_EVENT_WORKLOAD_CHECKPOINT,
				      workload_id, 0U, workload.checkpoint_sequence,
				      now_ns, FPL_OK, &workload, sizeof(workload));
	if (result == FPL_OK)
		service->workloads[index] = workload;
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_complete(struct fpl_service *service, uint64_t workload_id,
		 const uint8_t result_digest[FPL_DIGEST_SIZE])
{
	struct fpl_workload workload;
	struct fpl_node updated_nodes[FPL_MAX_NODES];
	struct fpl_cluster_snapshot snapshot;
	int index;
	int result;

	if (service == NULL || workload_id == 0U || !digest_present(result_digest))
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	workload = service->workloads[index];
	if (workload.state != FPL_WORKLOAD_PLACED &&
	    workload.state != FPL_WORKLOAD_CHECKPOINTED) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_STATE;
	}
	result = release_nodes(service, &workload, updated_nodes);
	if (result != FPL_OK) {
		pthread_mutex_unlock(&service->lock);
		return result;
	}
	memcpy(workload.checkpoint_digest, result_digest, FPL_DIGEST_SIZE);
	workload.state = FPL_WORKLOAD_COMPLETED;
	workload.last_transition_ns = service->policy.current_time_ns;
	result = make_snapshot(service, &workload, updated_nodes,
				 service->node_count, &snapshot);
	if (result == FPL_OK)
		result = append_record_locked(service, FPL_EVENT_WORKLOAD_COMPLETE,
				       workload_id, 0U, 0U,
				       service->policy.current_time_ns, FPL_OK,
				       &snapshot, sizeof(snapshot));
	if (result == FPL_OK) {
			memcpy(service->nodes, updated_nodes, sizeof(updated_nodes));
			service->workloads[index] = workload;
		}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_fail(struct fpl_service *service, uint64_t workload_id,
	    uint64_t now_ns, uint32_t failure_class, const char *reason,
	    int retryable)
{
	struct fpl_workload workload;
	struct fpl_node updated_nodes[FPL_MAX_NODES];
	struct fpl_cluster_snapshot snapshot;
	int index;
	int result;

	if (service == NULL || workload_id == 0U || now_ns == 0U ||
	    reason == NULL || memchr(reason, '\0', FPL_MAX_REASON) == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	workload = service->workloads[index];
	if (workload.state != FPL_WORKLOAD_PLACED &&
	    workload.state != FPL_WORKLOAD_CHECKPOINTED &&
	    workload.state != FPL_WORKLOAD_RECOVERING) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_STATE;
	}
	result = release_nodes(service, &workload, updated_nodes);
	if (result != FPL_OK) {
		pthread_mutex_unlock(&service->lock);
		return result;
	}
	workload.failure_class = failure_class;
	snprintf(workload.failure_reason, sizeof(workload.failure_reason), "%s", reason);
	workload.state = retryable && workload.intent.allow_recovery &&
		workload.recovery_attempts < service->policy.max_recovery_attempts ?
		FPL_WORKLOAD_RECOVERING : FPL_WORKLOAD_FAILED;
	workload.last_transition_ns = now_ns;
	result = make_snapshot(service, &workload, updated_nodes,
				 service->node_count, &snapshot);
	if (result == FPL_OK)
		result = append_record_locked(service, FPL_EVENT_WORKLOAD_FAILURE,
				       workload_id, 0U, 0U, now_ns, failure_class,
				       &snapshot, sizeof(snapshot));
	if (result == FPL_OK) {
		memcpy(service->nodes, updated_nodes, sizeof(updated_nodes));
		service->workloads[index] = workload;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_recover(struct fpl_service *service, uint64_t workload_id,
	       uint64_t now_ns, struct fpl_workload *out)
{
	int index;
	uint32_t attempt;
	int result;

	if (service == NULL || workload_id == 0U || now_ns == 0U || out == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock(&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	if (index < 0) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	if (service->workloads[index].state != FPL_WORKLOAD_RECOVERING ||
	    !service->workloads[index].intent.allow_recovery) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_RECOVERY;
	}
	attempt = service->workloads[index].recovery_attempts + 1U;
	if (attempt > service->policy.max_recovery_attempts) {
		pthread_mutex_unlock(&service->lock);
		return FPL_ERR_RECOVERY;
	}
	result = place_locked(service, (size_t)index, now_ns, attempt, out);
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fpl_query(const struct fpl_service *service, uint64_t workload_id,
	      struct fpl_workload *out)
{
	int index;

	if (service == NULL || workload_id == 0U || out == NULL)
		return FPL_ERR_ARGUMENT;
	if (pthread_mutex_lock((pthread_mutex_t *)&service->lock) != 0)
		return FPL_ERR_IO;
	index = workload_index(service, workload_id);
	if (index < 0) {
		pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
		return FPL_ERR_NOT_FOUND;
	}
	*out = service->workloads[index];
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FPL_OK;
}

int fpl_test_model_output_untrusted(struct fpl_service *service,
				    const struct fpl_intent *intent)
{
	struct fpl_intent proposal;
	struct fpl_workload ignored;
	int result;

	if (service == NULL || intent == NULL)
		return FPL_ERR_ARGUMENT;
	proposal = *intent;
	proposal.authorized = 0U;
	result = fpl_submit(service, &proposal, &ignored);
	return result == FPL_ERR_AUTHORITY || result == FPL_ERR_POLICY ? FPL_OK : FPL_ERR_AUTHORITY;
}

int fpl_test_corrupt_tail(const struct fpl_service *service)
{
	uint8_t byte = 0xA5U;
	if (service == NULL || service->journal_fd < 0)
		return FPL_ERR_ARGUMENT;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0 ||
	    write_full(service->journal_fd, &byte, sizeof(byte)) != FPL_OK ||
	    fdatasync(service->journal_fd) != 0)
		return FPL_ERR_IO;
	return FPL_OK;
}
