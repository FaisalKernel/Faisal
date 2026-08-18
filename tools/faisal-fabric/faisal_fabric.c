#define _GNU_SOURCE
#include "faisal_fabric.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const uint8_t *data, size_t length,
			uint8_t digest[FF_DIGEST_SIZE])
{
	unsigned int digest_length = 0U;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FF_ERR_ARGUMENT;
	if (EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 ||
	    digest_length != FF_DIGEST_SIZE)
		return FF_ERR_TAMPER;
	return FF_OK;
}

static int zero_digest(const uint8_t digest[FF_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < FF_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 0;
	return 1;
}

static int add_overflow(uint64_t left, uint64_t right)
{
	return UINT64_MAX - left < right;
}

static int vector_zero(const struct ff_resource_vector *v)
{
	return v != NULL && v->cpu_ns == 0U && v->memory_bytes == 0U &&
	       v->gpu_ns == 0U && v->npu_ns == 0U && v->network_bytes == 0U &&
	       v->storage_bytes == 0U && v->cost_micro == 0U && v->energy_uj == 0U;
}

static int vector_fits(const struct ff_resource_vector *need,
			       const struct ff_resource_vector *available)
{
	return need != NULL && available != NULL && need->cpu_ns <= available->cpu_ns &&
	       need->memory_bytes <= available->memory_bytes &&
	       need->gpu_ns <= available->gpu_ns && need->npu_ns <= available->npu_ns &&
	       need->network_bytes <= available->network_bytes &&
	       need->storage_bytes <= available->storage_bytes &&
	       need->cost_micro <= available->cost_micro &&
	       need->energy_uj <= available->energy_uj;
}

static int vector_add(struct ff_resource_vector *dst,
		      const struct ff_resource_vector *src)
{
	if (dst == NULL || src == NULL || add_overflow(dst->cpu_ns, src->cpu_ns) ||
	    add_overflow(dst->memory_bytes, src->memory_bytes) ||
	    add_overflow(dst->gpu_ns, src->gpu_ns) ||
	    add_overflow(dst->npu_ns, src->npu_ns) ||
	    add_overflow(dst->network_bytes, src->network_bytes) ||
	    add_overflow(dst->storage_bytes, src->storage_bytes) ||
	    add_overflow(dst->cost_micro, src->cost_micro) ||
	    add_overflow(dst->energy_uj, src->energy_uj))
		return FF_ERR_OVERFLOW;
	dst->cpu_ns += src->cpu_ns;
	dst->memory_bytes += src->memory_bytes;
	dst->gpu_ns += src->gpu_ns;
	dst->npu_ns += src->npu_ns;
	dst->network_bytes += src->network_bytes;
	dst->storage_bytes += src->storage_bytes;
	dst->cost_micro += src->cost_micro;
	dst->energy_uj += src->energy_uj;
	return FF_OK;
}

static void vector_sub(struct ff_resource_vector *dst,
			       const struct ff_resource_vector *src)
{
	dst->cpu_ns -= src->cpu_ns;
	dst->memory_bytes -= src->memory_bytes;
	dst->gpu_ns -= src->gpu_ns;
	dst->npu_ns -= src->npu_ns;
	dst->network_bytes -= src->network_bytes;
	dst->storage_bytes -= src->storage_bytes;
	dst->cost_micro -= src->cost_micro;
	dst->energy_uj -= src->energy_uj;
}

static int valid_observation(const struct ff_policy *policy,
			     const struct ff_node *node)
{
	uint64_t age;

	if (policy == NULL || node == NULL || node->observed_at_ns == 0U ||
	    policy->current_time_ns < node->observed_at_ns ||
	    node->generation == 0U || node->health_permille > 1000U ||
	    node->pressure_permille > 1000U || node->thermal_permille > 1000U ||
	    node->forecast_permille > 1000U || vector_zero(&node->capacity) ||
	    !vector_fits(&node->available, &node->capacity) ||
	    zero_digest(node->identity_digest) || zero_digest(node->topology_digest))
		return 0;
	age = policy->current_time_ns - node->observed_at_ns;
	return policy->observation_max_age_ns == 0U || age <= policy->observation_max_age_ns;
}

static int valid_shard(const struct ff_policy *policy,
			   const struct ff_shard *shard)
{
	if (policy == NULL || shard == NULL || shard->objective_id == 0U ||
	    shard->agent_id == 0U || shard->tenant_id == 0U || shard->trace_id == 0U ||
	    shard->task_generation == 0U || shard->session_generation == 0U ||
	    shard->issued_at_ns == 0U || shard->deadline_ns < shard->issued_at_ns ||
	    shard->priority < policy->minimum_priority ||
	    (shard->flags & ~FF_FLAGS_ALL) != 0U || vector_zero(&shard->demand) ||
	    zero_digest(shard->budget_receipt_digest) ||
	    zero_digest(shard->provenance_digest) ||
	    ((shard->flags & FF_FLAG_REQUIRES_LOCALITY) != 0U &&
	     zero_digest(shard->locality_digest)))
		return FF_ERR_ARGUMENT;
	if (policy->require_authority &&
	    !(shard->flags & FF_FLAG_AUTHORITY_GRANTED))
		return FF_ERR_AUTHORITY;
	if (policy->require_verified_input &&
	    !(shard->flags & FF_FLAG_VERIFIED_INPUT))
		return FF_ERR_AUTHORITY;
	if (policy->current_time_ns < shard->issued_at_ns ||
	    policy->current_time_ns > shard->deadline_ns)
		return FF_ERR_DEADLINE;
	return FF_OK;
}

static int digest_node(const struct ff_node *node, uint8_t digest[FF_DIGEST_SIZE])
{
	struct ff_node canonical;

	if (node == NULL || digest == NULL)
		return FF_ERR_ARGUMENT;
	canonical = *node;
	memset(canonical.identity_digest, 0, FF_DIGEST_SIZE);
	memset(canonical.topology_digest, 0, FF_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_shard(const struct ff_shard *shard,
			uint8_t digest[FF_DIGEST_SIZE])
{
	struct ff_shard canonical;

	if (shard == NULL || digest == NULL)
		return FF_ERR_ARGUMENT;
	canonical = *shard;
	canonical.shard_id = 0U;
	canonical.node_id = 0U;
	canonical.node_generation = 0U;
	canonical.lease_id = 0U;
	canonical.placement_generation = 0U;
	memset(canonical.request_digest, 0, FF_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_lease(const struct ff_lease *lease,
			uint8_t digest[FF_DIGEST_SIZE])
{
	struct ff_lease canonical;

	if (lease == NULL || digest == NULL)
		return FF_ERR_ARGUMENT;
	canonical = *lease;
	memset(canonical.lease_digest, 0, FF_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int sign_event(const struct ff_event *event, uint8_t digest[FF_DIGEST_SIZE])
{
	struct ff_event canonical;

	if (event == NULL || digest == NULL)
		return FF_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, FF_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

int ff_verify_event(const struct ff_event *event, const uint8_t *payload,
		   const uint8_t previous_digest[FF_DIGEST_SIZE])
{
	uint8_t payload_digest[FF_DIGEST_SIZE];
	uint8_t event_digest[FF_DIGEST_SIZE];

	if (event == NULL || previous_digest == NULL ||
	    (payload == NULL && event->payload_len != 0U) ||
	    event->magic != FF_EVENT_MAGIC || event->version != FF_EVENT_VERSION ||
	    event->payload_len > FF_MAX_PAYLOAD)
		return FF_ERR_TAMPER;
	if (memcmp(event->previous_digest, previous_digest, FF_DIGEST_SIZE) != 0 ||
	    digest_bytes(payload, event->payload_len, payload_digest) != FF_OK ||
	    memcmp(payload_digest, event->payload_digest, FF_DIGEST_SIZE) != 0 ||
	    sign_event(event, event_digest) != FF_OK ||
	    memcmp(event_digest, event->event_digest, FF_DIGEST_SIZE) != 0)
		return FF_ERR_TAMPER;
	return FF_OK;
}

static int write_all(int fd, const void *buffer, size_t length)
{
	const uint8_t *bytes = buffer;
	size_t offset = 0U;
	ssize_t written;

	while (offset < length) {
		written = write(fd, bytes + offset, length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return FF_ERR_IO;
		offset += (size_t)written;
	}
	return FF_OK;
}

static int read_record(int fd, struct ff_disk_record *record)
{
	uint8_t *bytes = (uint8_t *)record;
	size_t offset = 0U;
	ssize_t count;

	while (offset < sizeof(*record)) {
		count = read(fd, bytes + offset, sizeof(*record) - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return offset == 0U ? FF_ERR_NOT_FOUND : FF_ERR_IO;
		if (count < 0)
			return FF_ERR_IO;
		offset += (size_t)count;
	}
	return FF_OK;
}

static struct ff_node *find_node(struct ff_service *service, uint64_t node_id)
{
	size_t i;

	for (i = 0U; i < service->node_count; ++i)
		if (service->nodes[i].node_id == node_id)
			return &service->nodes[i];
	return NULL;
}

static const struct ff_node *find_node_const(const struct ff_service *service,
						 uint64_t node_id)
{
	size_t i;

	for (i = 0U; i < service->node_count; ++i)
		if (service->nodes[i].node_id == node_id)
			return &service->nodes[i];
	return NULL;
}

static struct ff_shard *find_shard(struct ff_service *service, uint64_t shard_id)
{
	size_t i;

	for (i = 0U; i < service->shard_count; ++i)
		if (service->shards[i].shard_id == shard_id)
			return &service->shards[i];
	return NULL;
}

static const struct ff_shard *find_shard_const(const struct ff_service *service,
						   uint64_t shard_id)
{
	size_t i;

	for (i = 0U; i < service->shard_count; ++i)
		if (service->shards[i].shard_id == shard_id)
			return &service->shards[i];
	return NULL;
}

static struct ff_lease *find_lease(struct ff_service *service, uint64_t lease_id)
{
	size_t i;

	for (i = 0U; i < service->lease_count; ++i)
		if (service->leases[i].lease_id == lease_id)
			return &service->leases[i];
	return NULL;
}

static int append_event_locked(struct ff_service *service, uint16_t kind,
				       uint64_t node_id, uint64_t shard_id,
				       uint64_t lease_id, int status, uint64_t now_ns,
				       const void *payload, size_t payload_len,
				       uint64_t *sequence_out)
{
	struct ff_disk_record record;

	if (service == NULL || payload_len > FF_MAX_PAYLOAD ||
	    (payload == NULL && payload_len != 0U))
		return FF_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FF_EVENT_MAGIC;
	record.event.version = FF_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->event_sequence + 1U;
	record.event.node_id = node_id;
	record.event.shard_id = shard_id;
	record.event.lease_id = lease_id;
	record.event.observed_at_ns = now_ns;
	record.event.status = status;
	record.event.payload_len = (uint32_t)payload_len;
	memcpy(record.event.previous_digest, service->chain_digest, FF_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	if (digest_bytes(record.payload, payload_len, record.event.payload_digest) != FF_OK ||
	    sign_event(&record.event, record.event.event_digest) != FF_OK)
		return FF_ERR_TAMPER;
	if (write_all(service->journal_fd, &record, sizeof(record)) != FF_OK ||
	    fdatasync(service->journal_fd) != 0)
		return FF_ERR_IO;
	service->event_sequence = record.event.sequence;
	memcpy(service->chain_digest, record.event.event_digest, FF_DIGEST_SIZE);
	if (sequence_out != NULL)
		*sequence_out = record.event.sequence;
	return FF_OK;
}

static int apply_lease_resources(struct ff_service *service,
				 const struct ff_lease *lease, int replay)
{
	struct ff_node *node;
	struct ff_node *previous;

	if (lease->state == FF_LEASE_ACTIVE) {
		node = find_node(service, lease->node_id);
		if (node == NULL || node->state == FF_NODE_QUARANTINED ||
		    !vector_fits(&lease->demand, &node->available))
			return replay ? FF_ERR_CORRUPT : FF_ERR_NO_CAPACITY;
		if (lease->previous_node_id != 0U &&
		    lease->previous_node_id != lease->node_id) {
			previous = find_node(service, lease->previous_node_id);
			if (previous == NULL || vector_add(&previous->available, &lease->demand) != FF_OK)
				return replay ? FF_ERR_CORRUPT : FF_ERR_OVERFLOW;
		}
		vector_sub(&node->available, &lease->demand);
	} else if (lease->state == FF_LEASE_RELEASED ||
		   lease->state == FF_LEASE_EXPIRED) {
		node = find_node(service, lease->node_id);
		if (node != NULL && vector_add(&node->available, &lease->demand) != FF_OK)
			return replay ? FF_ERR_CORRUPT : FF_ERR_OVERFLOW;
	}
	return FF_OK;
}

static int apply_replay_record(struct ff_service *service,
			       const struct ff_disk_record *record)
{
	struct ff_node node;
	struct ff_shard shard;
	struct ff_lease lease;
	uint8_t stored_lease_digest[FF_DIGEST_SIZE];
	uint8_t computed_lease_digest[FF_DIGEST_SIZE];
	struct ff_node *existing_node;
	struct ff_shard *existing_shard;
	struct ff_lease *existing_lease;
	int result;

	if (record->event.kind == FF_EVENT_REGISTER_NODE) {
		if (record->event.payload_len != sizeof(node))
			return FF_ERR_CORRUPT;
		memcpy(&node, record->payload, sizeof(node));
		{
			uint8_t topology_digest[FF_DIGEST_SIZE];
			if (!valid_observation(&service->policy, &node) ||
			    digest_node(&node, topology_digest) != FF_OK ||
			    memcmp(topology_digest, node.topology_digest, FF_DIGEST_SIZE) != 0)
				return FF_ERR_CORRUPT;
		}
		if (service->node_count >= FF_MAX_NODES)
			return FF_ERR_FULL;
		existing_node = find_node(service, node.node_id);
		if (existing_node != NULL)
			*existing_node = node;
		else
			service->nodes[service->node_count++] = node;
		if (node.node_id >= service->next_node_id)
			service->next_node_id = node.node_id + 1U;
		return FF_OK;
	}
	if (record->event.kind == FF_EVENT_SUBMIT_SHARD) {
		if (record->event.payload_len != sizeof(shard))
			return FF_ERR_CORRUPT;
		memcpy(&shard, record->payload, sizeof(shard));
		{
			uint8_t request_digest[FF_DIGEST_SIZE];
			if (valid_shard(&service->policy, &shard) != FF_OK ||
			    digest_shard(&shard, request_digest) != FF_OK ||
			    memcmp(request_digest, shard.request_digest, FF_DIGEST_SIZE) != 0)
				return FF_ERR_CORRUPT;
		}
		if (service->shard_count >= FF_MAX_SHARDS ||
		    find_shard(service, shard.shard_id) != NULL)
			return FF_ERR_CORRUPT;
		service->shards[service->shard_count++] = shard;
		if (shard.shard_id >= service->next_shard_id)
			service->next_shard_id = shard.shard_id + 1U;
		return FF_OK;
	}
	if (record->event.kind == FF_EVENT_LEASE) {
		if (record->event.payload_len != sizeof(lease))
			return FF_ERR_CORRUPT;
		memcpy(&lease, record->payload, sizeof(lease));
		memcpy(stored_lease_digest, lease.lease_digest, FF_DIGEST_SIZE);
		if (digest_lease(&lease, computed_lease_digest) != FF_OK ||
		    zero_digest(stored_lease_digest) ||
		    memcmp(stored_lease_digest, computed_lease_digest, FF_DIGEST_SIZE) != 0)
			return FF_ERR_TAMPER;
		memcpy(lease.lease_digest, stored_lease_digest, FF_DIGEST_SIZE);
		existing_shard = find_shard(service, lease.shard_id);
		if (existing_shard == NULL)
			return FF_ERR_CORRUPT;
		existing_lease = find_lease(service, lease.lease_id);
		if (existing_lease == NULL) {
			if (service->lease_count >= FF_MAX_LEASES)
				return FF_ERR_FULL;
			result = apply_lease_resources(service, &lease, 1);
			if (result != FF_OK)
				return result;
			service->leases[service->lease_count++] = lease;
		} else {
			if (lease.state == FF_LEASE_ACTIVE &&
			    lease.previous_node_id == lease.node_id)
				;
			else {
				result = apply_lease_resources(service, &lease, 1);
				if (result != FF_OK)
					return result;
			}
			*existing_lease = lease;
		}
		existing_shard->node_id = lease.node_id;
		existing_shard->lease_id = lease.lease_id;
		existing_shard->node_generation = lease.node_generation;
		existing_shard->placement_generation = lease.lease_generation;
		existing_shard->state = lease.shard_state;
		if (lease.lease_id >= service->next_lease_id)
			service->next_lease_id = lease.lease_id + 1U;
		return FF_OK;
	}
	if (record->event.kind == FF_EVENT_NODE_QUARANTINE) {
		if (record->event.payload_len != sizeof(node))
			return FF_ERR_CORRUPT;
		memcpy(&node, record->payload, sizeof(node));
		existing_node = find_node(service, node.node_id);
		if (existing_node == NULL)
			return FF_ERR_CORRUPT;
		*existing_node = node;
		for (size_t i = 0U; i < service->shard_count; ++i)
			if (service->shards[i].node_id == node.node_id)
				service->shards[i].state = FF_SHARD_RECOVERY;
		for (size_t i = 0U; i < service->lease_count; ++i)
			if (service->leases[i].node_id == node.node_id)
				service->leases[i].state = FF_LEASE_QUARANTINED;
		return FF_OK;
	}
	if (record->event.kind == FF_EVENT_BACKPRESSURE) {
		if (record->event.payload_len != sizeof(shard))
			return FF_ERR_CORRUPT;
		memcpy(&shard, record->payload, sizeof(shard));
		existing_shard = find_shard(service, shard.shard_id);
		if (existing_shard == NULL)
			return FF_ERR_CORRUPT;
		*existing_shard = shard;
		service->backpressure_count++;
		return FF_OK;
	}
	return FF_ERR_CORRUPT;
}

static int replay_locked(struct ff_service *service)
{
	struct ff_disk_record record;
	uint8_t previous[FF_DIGEST_SIZE] = {0};
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FF_ERR_IO;
	while ((result = read_record(service->journal_fd, &record)) == FF_OK) {
		if (record.event.sequence != service->event_sequence + 1U ||
		    ff_verify_event(&record.event, record.payload, previous) != FF_OK)
			return FF_ERR_REPLAY;
		result = apply_replay_record(service, &record);
		if (result != FF_OK)
			return result;
		service->event_sequence = record.event.sequence;
		memcpy(previous, record.event.event_digest, FF_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FF_DIGEST_SIZE);
	}
	if (result != FF_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FF_ERR_IO;
	return FF_OK;
}

int ff_open(struct ff_service *service, const char *journal_path,
	    const struct ff_policy *policy)
{
	int result;

	if (service == NULL || journal_path == NULL || policy == NULL ||
	    policy->current_time_ns == 0U || policy->default_lease_ns == 0U ||
	    policy->max_lease_ns < policy->default_lease_ns ||
	    policy->max_queue_depth == 0U)
		return FF_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FF_ERR_IO;
	service->policy = *policy;
	service->next_node_id = 1U;
	service->next_shard_id = 1U;
	service->next_lease_id = 1U;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FF_ERR_IO;
	}
	result = replay_locked(service);
	if (result != FF_OK) {
		pthread_mutex_destroy(&service->lock);
		close(service->journal_fd);
	}
	return result;
}

void ff_close(struct ff_service *service)
{
	if (service == NULL)
		return;
	pthread_mutex_destroy(&service->lock);
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

int ff_register_node(struct ff_service *service, const struct ff_node *observation,
		     struct ff_node *out)
{
	struct ff_node node;
	size_t previous_node_count;
	uint64_t previous_next_node_id;
	int result;

	if (service == NULL || observation == NULL || out == NULL ||
	    valid_observation(&service->policy, observation) == 0)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (service->node_count >= FF_MAX_NODES)
		result = FF_ERR_FULL;
	else {
		node = *observation;
		node.node_id = observation->node_id != 0U ? observation->node_id : service->next_node_id++;
		if (node.node_id >= service->next_node_id)
			service->next_node_id = node.node_id + 1U;
		if (find_node(service, node.node_id) != NULL)
			result = FF_ERR_DUPLICATE;
		else {
			if (digest_node(&node, node.topology_digest) != FF_OK)
				result = FF_ERR_TAMPER;
			else {
				previous_node_count = service->node_count;
				previous_next_node_id = service->next_node_id;
				service->nodes[service->node_count++] = node;
				result = append_event_locked(service, FF_EVENT_REGISTER_NODE,
							     node.node_id, 0U, 0U, FF_OK,
							     node.observed_at_ns, &node, sizeof(node), NULL);
				if (result == FF_OK)
					*out = node;
				else {
					service->node_count = previous_node_count;
					service->next_node_id = previous_next_node_id;
				}
			}
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int ff_submit_shard(struct ff_service *service, const struct ff_shard *request,
		   struct ff_shard *out)
{
	struct ff_shard shard;
	size_t previous_shard_count;
	uint64_t previous_next_shard_id;
	int result;

	if (service == NULL || request == NULL || out == NULL)
		return FF_ERR_ARGUMENT;
	result = valid_shard(&service->policy, request);
	if (result != FF_OK)
		return result;
	pthread_mutex_lock(&service->lock);
	if (service->shard_count >= FF_MAX_SHARDS)
		result = FF_ERR_FULL;
	else if (service->shard_count >= service->policy.max_queue_depth)
		result = FF_ERR_BACKPRESSURE;
	else {
		shard = *request;
		shard.shard_id = service->next_shard_id++;
		shard.node_id = 0U;
		shard.node_generation = 0U;
		shard.lease_id = 0U;
		shard.placement_generation = 0U;
		shard.state = FF_SHARD_PENDING;
		if (digest_shard(&shard, shard.request_digest) != FF_OK)
			result = FF_ERR_TAMPER;
		else {
			previous_shard_count = service->shard_count;
			previous_next_shard_id = service->next_shard_id;
			service->shards[service->shard_count++] = shard;
			result = append_event_locked(service, FF_EVENT_SUBMIT_SHARD, 0U,
						     shard.shard_id, 0U, FF_OK,
						     shard.issued_at_ns, &shard, sizeof(shard), NULL);
			if (result == FF_OK)
				*out = shard;
			else {
				service->shard_count = previous_shard_count;
				service->next_shard_id = previous_next_shard_id;
			}
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static uint64_t node_score(const struct ff_node *node)
{
	return (uint64_t)node->health_permille * 4U +
	       (uint64_t)(1000U - node->pressure_permille) * 2U +
	       (uint64_t)(1000U - node->thermal_permille) +
	       (uint64_t)(1000U - node->forecast_permille);
}

int ff_place_shard(struct ff_service *service, uint64_t shard_id,
		  uint64_t now_ns, struct ff_shard *out, struct ff_lease *lease_out)
{
	struct ff_shard *shard;
	struct ff_shard before_shard;
	struct ff_lease lease;
	struct ff_node *best = NULL;
	struct ff_node before_node;
	size_t previous_lease_count;
	uint64_t previous_next_lease_id;
	uint64_t best_score = 0U;
	int result = FF_OK;

	if (service == NULL || out == NULL || lease_out == NULL || shard_id == 0U ||
	    now_ns == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	shard = find_shard(service, shard_id);
	if (shard == NULL)
		result = FF_ERR_NOT_FOUND;
	else if (shard->state != FF_SHARD_PENDING &&
		 shard->state != FF_SHARD_BACKPRESSURED &&
		 shard->state != FF_SHARD_RECOVERY)
		result = FF_ERR_STATE;
	else if (now_ns > shard->deadline_ns)
		result = FF_ERR_DEADLINE;
	else {
		for (size_t i = 0U; i < service->node_count; ++i) {
			struct ff_node *candidate = &service->nodes[i];
			uint64_t score;
			if (candidate->state != FF_NODE_HEALTHY ||
			    candidate->health_permille < 500U ||
			    candidate->pressure_permille > 950U ||
			    candidate->thermal_permille > 950U ||
			    candidate->forecast_permille > 950U ||
			    now_ns < candidate->observed_at_ns ||
			    !vector_fits(&shard->demand, &candidate->available) ||
			    ((shard->flags & FF_FLAG_REQUIRES_LOCALITY) != 0U &&
			     memcmp(candidate->topology_digest, shard->locality_digest, FF_DIGEST_SIZE) != 0))
				continue;
			score = node_score(candidate);
			if (best == NULL || score > best_score ||
			    (score == best_score && candidate->node_id < best->node_id)) {
				best = candidate;
				best_score = score;
			}
		}
		if (best == NULL)
			result = FF_ERR_NO_CAPACITY;
		else {
			before_shard = *shard;
			before_node = *best;
			previous_lease_count = service->lease_count;
			previous_next_lease_id = service->next_lease_id;
			memset(&lease, 0, sizeof(lease));
			lease.lease_id = service->next_lease_id++;
			lease.shard_id = shard->shard_id;
			lease.node_id = best->node_id;
			lease.previous_node_id = 0U;
			lease.node_generation = best->generation;
			lease.lease_generation = shard->placement_generation + 1U;
			lease.issued_at_ns = now_ns;
			lease.expiry_ns = now_ns + service->policy.default_lease_ns;
			lease.state = FF_LEASE_ACTIVE;
			lease.shard_state = FF_SHARD_PLACED;
			lease.demand = shard->demand;
			memcpy(lease.shard_request_digest, shard->request_digest, FF_DIGEST_SIZE);
			memcpy(lease.node_identity_digest, best->identity_digest, FF_DIGEST_SIZE);
			if (digest_lease(&lease, lease.lease_digest) != FF_OK)
				result = FF_ERR_TAMPER;
			else {
				vector_sub(&best->available, &lease.demand);
				shard->node_id = best->node_id;
				shard->node_generation = best->generation;
				shard->lease_id = lease.lease_id;
				shard->placement_generation = lease.lease_generation;
				shard->state = FF_SHARD_PLACED;
				if (service->lease_count >= FF_MAX_LEASES)
					result = FF_ERR_FULL;
				else {
					service->leases[service->lease_count++] = lease;
					result = append_event_locked(service, FF_EVENT_LEASE,
								     best->node_id, shard_id,
								     lease.lease_id, FF_OK, now_ns,
								     &lease, sizeof(lease), NULL);
				}
				if (result == FF_OK) {
					*out = *shard;
					*lease_out = lease;
				} else {
					*shard = before_shard;
					*best = before_node;
					service->lease_count = previous_lease_count;
					service->next_lease_id = previous_next_lease_id;
				}
			}
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int ff_renew_lease(struct ff_service *service, uint64_t lease_id,
		  uint64_t now_ns, uint64_t extension_ns, struct ff_lease *out)
{
	struct ff_lease *lease;
	struct ff_lease before;
	int result = FF_OK;

	if (service == NULL || out == NULL || lease_id == 0U || now_ns == 0U ||
	    extension_ns == 0U || extension_ns > service->policy.max_lease_ns)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	lease = find_lease(service, lease_id);
	if (lease == NULL)
		result = FF_ERR_NOT_FOUND;
	else if (lease->state != FF_LEASE_ACTIVE)
		result = FF_ERR_STATE;
	else if (now_ns > lease->expiry_ns)
		result = FF_ERR_EXPIRED;
	else if (add_overflow(now_ns, extension_ns))
		result = FF_ERR_OVERFLOW;
	else {
		before = *lease;
		lease->previous_node_id = lease->node_id;
		lease->lease_generation++;
		lease->issued_at_ns = now_ns;
		lease->expiry_ns = now_ns + extension_ns;
		if (digest_lease(lease, lease->lease_digest) != FF_OK)
			result = FF_ERR_TAMPER;
		else
			result = append_event_locked(service, FF_EVENT_LEASE, lease->node_id,
						    lease->shard_id, lease->lease_id,
						    FF_OK, now_ns, lease, sizeof(*lease), NULL);
		if (result == FF_OK)
			*out = *lease;
		else
			*lease = before;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static struct ff_node *choose_migration_node(struct ff_service *service,
					     const struct ff_shard *shard,
					     uint64_t current_node_id,
					     uint64_t now_ns)
{
	struct ff_node *best = NULL;
	uint64_t best_score = 0U;

	for (size_t i = 0U; i < service->node_count; ++i) {
		struct ff_node *candidate = &service->nodes[i];
		uint64_t score;
		if (candidate->node_id == current_node_id ||
		    candidate->state != FF_NODE_HEALTHY || candidate->health_permille < 500U ||
		    candidate->pressure_permille > 950U || candidate->thermal_permille > 950U ||
		    candidate->forecast_permille > 950U || now_ns < candidate->observed_at_ns ||
		    !vector_fits(&shard->demand, &candidate->available) ||
		    ((shard->flags & FF_FLAG_REQUIRES_LOCALITY) != 0U &&
		     memcmp(candidate->topology_digest, shard->locality_digest, FF_DIGEST_SIZE) != 0))
			continue;
		score = node_score(candidate);
		if (best == NULL || score > best_score ||
		    (score == best_score && candidate->node_id < best->node_id)) {
			best = candidate;
			best_score = score;
		}
	}
	return best;
}

int ff_migrate_shard(struct ff_service *service, uint64_t shard_id,
		     uint64_t now_ns, struct ff_shard *shard_out,
		     struct ff_lease *lease_out)
{
	struct ff_shard *shard;
	struct ff_lease *lease;
	struct ff_node *old_node;
	struct ff_node *new_node;
	struct ff_shard shard_before;
	struct ff_lease lease_before;
	struct ff_node old_before;
	struct ff_node new_before;
	int result = FF_OK;

	if (service == NULL || shard_out == NULL || lease_out == NULL || shard_id == 0U ||
	    now_ns == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	shard = find_shard(service, shard_id);
	lease = shard == NULL ? NULL : find_lease(service, shard->lease_id);
	if (shard == NULL || lease == NULL)
		result = FF_ERR_NOT_FOUND;
	else if ((shard->flags & FF_FLAG_MIGRATION_ALLOWED) == 0U)
		result = FF_ERR_AUTHORITY;
	else if (shard->state != FF_SHARD_PLACED && shard->state != FF_SHARD_RUNNING)
		result = FF_ERR_STATE;
	else if (lease->state != FF_LEASE_ACTIVE)
		result = FF_ERR_EXPIRED;
	else if (now_ns > shard->deadline_ns || now_ns > lease->expiry_ns)
		result = FF_ERR_DEADLINE;
	else {
		old_node = find_node(service, lease->node_id);
		new_node = choose_migration_node(service, shard, lease->node_id, now_ns);
		if (old_node == NULL || new_node == NULL)
			result = FF_ERR_NO_CAPACITY;
		else {
			shard_before = *shard;
			lease_before = *lease;
			old_before = *old_node;
			new_before = *new_node;
			vector_sub(&new_node->available, &shard->demand);
			vector_add(&old_node->available, &shard->demand);
			lease->previous_node_id = old_node->node_id;
			lease->node_id = new_node->node_id;
			lease->node_generation = new_node->generation;
			lease->lease_generation++;
			lease->issued_at_ns = now_ns;
			lease->expiry_ns = now_ns + service->policy.default_lease_ns;
			shard->node_id = new_node->node_id;
			shard->node_generation = new_node->generation;
			shard->placement_generation = lease->lease_generation;
			shard->state = FF_SHARD_PLACED;
			if (digest_lease(lease, lease->lease_digest) != FF_OK)
				result = FF_ERR_TAMPER;
			else
				result = append_event_locked(service, FF_EVENT_LEASE,
							    new_node->node_id, shard_id,
							    lease->lease_id, FF_OK, now_ns,
							    lease, sizeof(*lease), NULL);
			if (result == FF_OK) {
				*shard_out = *shard;
				*lease_out = *lease;
			} else {
				*shard = shard_before;
				*lease = lease_before;
				*old_node = old_before;
				*new_node = new_before;
			}
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int ff_release_lease(struct ff_service *service, uint64_t lease_id,
		     uint64_t now_ns, struct ff_shard *shard_out)
{
	struct ff_lease *lease;
	struct ff_shard *shard;
	struct ff_lease before_lease;
	struct ff_shard before_shard;
	struct ff_node *node;
	struct ff_node before_node;
	struct ff_resource_vector restored;
	int result = FF_OK;

	if (service == NULL || lease_id == 0U || now_ns == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	lease = find_lease(service, lease_id);
	shard = lease == NULL ? NULL : find_shard(service, lease->shard_id);
	node = lease == NULL ? NULL : find_node(service, lease->node_id);
	if (lease == NULL || shard == NULL || node == NULL)
		result = FF_ERR_NOT_FOUND;
	else if (lease->state != FF_LEASE_ACTIVE)
		result = FF_ERR_STATE;
	else {
		before_lease = *lease;
		before_shard = *shard;
		before_node = *node;
		restored = node->available;
		if (vector_add(&restored, &lease->demand) != FF_OK)
			result = FF_ERR_OVERFLOW;
		else {
			lease->state = FF_LEASE_RELEASED;
			lease->shard_state = FF_SHARD_COMPLETED;
			lease->previous_node_id = 0U;
			shard->state = FF_SHARD_COMPLETED;
			node->available = restored;
		}
		if (result == FF_OK) {
			if (digest_lease(lease, lease->lease_digest) != FF_OK)
				result = FF_ERR_TAMPER;
			else
				result = append_event_locked(service, FF_EVENT_LEASE, node->node_id,
							    shard->shard_id, lease->lease_id,
							    FF_OK, now_ns, lease, sizeof(*lease), NULL);
		}
		if (result == FF_OK) {
			if (shard_out != NULL)
				*shard_out = *shard;
		} else {
			*lease = before_lease;
			*shard = before_shard;
			*node = before_node;
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int ff_quarantine_node(struct ff_service *service, uint64_t node_id,
		       uint64_t now_ns, struct ff_node *out)
{
	struct ff_node *node;
	struct ff_node quarantined;
	int result;

	if (service == NULL || out == NULL || node_id == 0U || now_ns == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	node = find_node(service, node_id);
	if (node == NULL)
		result = FF_ERR_NOT_FOUND;
	else if (node->state == FF_NODE_QUARANTINED)
		result = FF_ERR_QUARANTINED;
	else {
		quarantined = *node;
		quarantined.state = FF_NODE_QUARANTINED;
		quarantined.health_permille = 0U;
		quarantined.generation++;
		quarantined.observed_at_ns = now_ns;
		result = append_event_locked(service, FF_EVENT_NODE_QUARANTINE,
					     node_id, 0U, 0U, FF_ERR_QUARANTINED,
					     now_ns, &quarantined, sizeof(quarantined), NULL);
		if (result == FF_OK) {
			*node = quarantined;
			for (size_t i = 0U; i < service->shard_count; ++i)
				if (service->shards[i].node_id == node_id)
					service->shards[i].state = FF_SHARD_RECOVERY;
			for (size_t i = 0U; i < service->lease_count; ++i)
				if (service->leases[i].node_id == node_id)
					service->leases[i].state = FF_LEASE_QUARANTINED;
			*out = *node;
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int ff_recover_expired(struct ff_service *service, uint64_t now_ns,
		       uint32_t *recovered, uint32_t *unrecoverable)
{
	uint32_t recovered_count = 0U;
	uint32_t unrecoverable_count = 0U;

	if (service == NULL || recovered == NULL || unrecoverable == NULL || now_ns == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	for (size_t i = 0U; i < service->lease_count; ++i) {
		struct ff_lease candidate;
		struct ff_lease *lease = &service->leases[i];
		struct ff_shard *shard;
		struct ff_node *node;
		int result;
		if (lease->state != FF_LEASE_ACTIVE || lease->expiry_ns > now_ns)
			continue;
		shard = find_shard(service, lease->shard_id);
		node = find_node(service, lease->node_id);
		if (shard == NULL || node == NULL)
			continue;
		candidate = *lease;
		candidate.state = FF_LEASE_EXPIRED;
		candidate.shard_state = now_ns <= shard->deadline_ns ? FF_SHARD_RECOVERY : FF_SHARD_QUARANTINED;
		candidate.previous_node_id = 0U;
		candidate.issued_at_ns = now_ns;
		candidate.lease_generation++;
		if (digest_lease(&candidate, candidate.lease_digest) != FF_OK)
			continue;
		result = append_event_locked(service, FF_EVENT_LEASE, node->node_id,
						    shard->shard_id, lease->lease_id,
						    FF_OK, now_ns, &candidate,
						    sizeof(candidate), NULL);
		if (result != FF_OK)
			continue;
		vector_add(&node->available, &lease->demand);
		*lease = candidate;
		shard->state = candidate.shard_state;
		if (candidate.shard_state == FF_SHARD_RECOVERY)
			recovered_count++;
		else
			unrecoverable_count++;
	}
	pthread_mutex_unlock(&service->lock);
	*recovered = recovered_count;
	*unrecoverable = unrecoverable_count;
	return FF_OK;
}

int ff_query_node(const struct ff_service *service, uint64_t node_id,
		  struct ff_node *out)
{
	const struct ff_node *node;

	if (service == NULL || out == NULL || node_id == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock((pthread_mutex_t *)&service->lock);
	node = find_node_const(service, node_id);
	if (node != NULL)
		*out = *node;
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return node == NULL ? FF_ERR_NOT_FOUND : FF_OK;
}

int ff_query_shard(const struct ff_service *service, uint64_t shard_id,
		   struct ff_shard *out)
{
	const struct ff_shard *shard;

	if (service == NULL || out == NULL || shard_id == 0U)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock((pthread_mutex_t *)&service->lock);
	shard = find_shard_const(service, shard_id);
	if (shard != NULL)
		*out = *shard;
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return shard == NULL ? FF_ERR_NOT_FOUND : FF_OK;
}

int ff_query_journal(const struct ff_service *service,
		    struct ff_journal_attestation *out)
{
	if (service == NULL || out == NULL)
		return FF_ERR_ARGUMENT;
	pthread_mutex_lock((pthread_mutex_t *)&service->lock);
	memset(out, 0, sizeof(*out));
	out->last_sequence = service->event_sequence;
	out->record_count = service->event_sequence;
	out->node_count = service->node_count;
	out->shard_count = service->shard_count;
	out->lease_count = service->lease_count;
	out->backpressure_count = service->backpressure_count;
	memcpy(out->chain_digest, service->chain_digest, FF_DIGEST_SIZE);
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FF_OK;
}
