#define _GNU_SOURCE
#include "faisal_world_state_service.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

static uint64_t hash_text(const char *text)
{
	uint64_t hash = 1469598103934665603ULL;
	while (*text) {
		hash ^= (unsigned char)*text++;
		hash *= 1099511628211ULL;
	}
	return hash ? hash : 1;
}

static int digest_text(const char *text, unsigned char digest[FMS_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 0;
	int ret = -1;
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, text, strlen(text)) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
	    out_len == FMS_DIGEST_SIZE)
		ret = 0;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static struct fws_fact *find_fact(struct fws_service *service, uint64_t key)
{
	uint32_t i;
	for (i = 0; i < service->fact_count; i++)
		if (service->facts[i].key_hash == key)
			return &service->facts[i];
	return NULL;
}

int fws_open(struct fws_service *service, const char *journal_path)
{
	struct agi_lc_subscribe subscribe;
	struct agi_lc_world_subscription world;
	int ret;
	if (!service)
		return -1;
	memset(service, 0, sizeof(*service));
	ret = fms_open(&service->memory, journal_path);
	if (ret != FMS_OK)
		return ret;
	memset(&subscribe, 0, sizeof(subscribe));
	subscribe.size = sizeof(subscribe);
	subscribe.event_mask = (1ULL << (AGI_LC_EVENT_WORLD_SYNC - 1)) |
		(1ULL << (AGI_LC_EVENT_TEMPORAL - 1)) |
		(1ULL << (AGI_LC_EVENT_MEMORY_RECORD - 1)) |
		(1ULL << (AGI_LC_EVENT_KNOWLEDGE - 1)) |
		(1ULL << (AGI_LC_EVENT_REFLECTION - 1));
	subscribe.correlation = 73000;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SUBSCRIBE, &subscribe) < 0)
		goto fail;
	memset(&world, 0, sizeof(world));
	world.size = sizeof(world);
	world.class_mask = (1ULL << (AGI_LC_WORLD_EVENT_RESOURCE - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_DEVICE - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_MEMORY_PRESSURE - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_CPU_PRESSURE - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_ACCELERATOR - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_SECURITY - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_TASK_STATE - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_CHECKPOINT - 1));
	world.min_priority = AGI_LC_WORLD_PRIORITY_LOW;
	world.queue_policy = AGI_LC_WORLD_QUEUE_DROP_NEW;
	world.correlation = 73000;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SET_WORLD_SUBSCRIPTION,
		  &world) < 0)
		goto fail;
	return FMS_OK;
fail:
	fms_close(&service->memory);
	return -1;
}

void fws_close(struct fws_service *service)
{
	if (service)
		fms_close(&service->memory);
}

int fws_world_query(struct fws_service *service, struct agi_lc_world_sync *out)
{
	struct agi_lc_world_sync sync;
	if (!service || !out)
		return -1;
	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_QUERY;
	sync.correlation = 73001;
	if (ioctl(service->memory.kernel_fd, AGI_LC_WORLD_SYNC, &sync) < 0)
		return -1;
	service->world_generation = sync.generation;
	service->resync_required = sync.resync_required ? 1U : 0U;
	if (sync.last_loss_sequence &&
	    sync.last_loss_sequence > service->last_ack_sequence)
		service->resync_required = 1U;
	if (service->last_observed_sequence && sync.oldest_sequence &&
	    sync.oldest_sequence > service->last_observed_sequence + 1)
		service->resync_required = 1U;
	if (sync.newest_sequence > service->last_observed_sequence)
		service->last_observed_sequence = sync.newest_sequence;
	*out = sync;
	return 0;
}

int fws_world_ack(struct fws_service *service, uint64_t sequence,
		  struct agi_lc_world_sync *out)
{
	struct agi_lc_world_sync sync;
	if (!service || !out || !sequence || sequence < service->last_ack_sequence ||
	    !service->memory.session_id)
		return -1;
	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_ACK;
	sync.consumer_id = service->memory.session_id;
	sync.ack_sequence = sequence;
	sync.correlation = 73002;
	if (ioctl(service->memory.kernel_fd, AGI_LC_WORLD_SYNC, &sync) < 0)
		return -1;
	service->last_ack_sequence = sequence;
	*out = sync;
	return 0;
}

int fws_add_fact(struct fws_service *service, const char *entity,
		const char *property, const char *value, uint64_t provenance_sequence,
		uint64_t freshness_ttl_ns, uint32_t confidence_ppm,
		struct fws_fact *out)
{
	char content[FWS_MAX_ENTITY + FWS_MAX_PROPERTY + FWS_MAX_VALUE + 4];
	struct fws_fact *existing;
	struct fms_entry memory;
	struct fws_fact fact;
	uint64_t key;
	int ret;

	if (!service || !entity || !property || !value || !out || !*entity ||
	    !*property || !*value || strlen(entity) >= FWS_MAX_ENTITY ||
	    strlen(property) >= FWS_MAX_PROPERTY || strlen(value) >= FWS_MAX_VALUE ||
	    confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    service->fact_count >= FWS_MAX_FACTS)
		return -1;
	snprintf(content, sizeof(content), "%s=%s:%s", entity, property, value);
	if (digest_text(content, fact.digest) < 0)
		return -1;
	key = hash_text(entity) ^ (hash_text(property) << 1);
	existing = find_fact(service, key);
	if (existing && !memcmp(existing->digest, fact.digest, FMS_DIGEST_SIZE)) {
		*out = *existing;
		return 0;
	}
	ret = fms_put(&service->memory, content, AGI_LC_MEMORY_TIER_WORLD_MODEL,
		      confidence_ppm, confidence_ppm, provenance_sequence, &memory);
	if (ret != FMS_OK)
		return -2;
	{
		unsigned char digest[FMS_DIGEST_SIZE];
		if (digest_text(content, digest) < 0)
			return -1;
		memset(&fact, 0, sizeof(fact));
		memcpy(fact.digest, digest, FMS_DIGEST_SIZE);
	}
	fact.key_hash = key;
	fact.memory_record_id = memory.record_id;
	fact.memory_capability = memory.authority_capability;
	fact.provenance_sequence = provenance_sequence;
	fact.event_sequence = service->last_observed_sequence;
	fact.generation = existing ? existing->generation + 1 : 1;
	fact.freshness_deadline_ns = freshness_ttl_ns ? monotonic_ns() + freshness_ttl_ns : 0;
	fact.confidence_ppm = confidence_ppm;
	fact.freshness_state = freshness_ttl_ns ? AGI_LC_MEMORY_FRESH : AGI_LC_MEMORY_FRESHNESS_UNKNOWN;
	fact.conflict_state = existing ? FWS_CONFLICT_DETECTED : FWS_CONFLICT_NONE;
	strncpy(fact.entity, entity, sizeof(fact.entity) - 1);
	strncpy(fact.property, property, sizeof(fact.property) - 1);
	strncpy(fact.value, value, sizeof(fact.value) - 1);
	if (existing) {
		existing->conflict_state = FWS_CONFLICT_DETECTED;
		fact.key_hash = key ^ fact.generation;
	}
	if (service->fact_count >= FWS_MAX_FACTS)
		return -3;
	service->facts[service->fact_count++] = fact;
	*out = fact;
	return 0;
}

int fws_resolve_conflict(struct fws_service *service, const char *entity,
			const char *property, const char *value, uint64_t provenance_sequence,
			uint64_t freshness_ttl_ns, uint32_t confidence_ppm,
			struct fws_fact *out)
{
	char content[FWS_MAX_ENTITY + FWS_MAX_PROPERTY + FWS_MAX_VALUE + 4];
	struct fms_entry memory;
	struct fws_fact fact;
	uint64_t key;
	uint64_t generation = 0;
	uint32_t i;
	int had_conflict = 0;
	if (!service || !entity || !property || !value || !out || !*entity ||
	    !*property || !*value || strlen(entity) >= FWS_MAX_ENTITY ||
	    strlen(property) >= FWS_MAX_PROPERTY || strlen(value) >= FWS_MAX_VALUE ||
	    confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    service->fact_count >= FWS_MAX_FACTS)
		return -1;
	key = hash_text(entity) ^ (hash_text(property) << 1);
	for (i = 0; i < service->fact_count; i++) {
		if (!strcmp(service->facts[i].entity, entity) &&
		    !strcmp(service->facts[i].property, property)) {
			if (service->facts[i].generation > generation)
				generation = service->facts[i].generation;
			if (service->facts[i].conflict_state == FWS_CONFLICT_DETECTED)
				had_conflict = 1;
		}
	}
	if (!had_conflict)
		return -2;
	snprintf(content, sizeof(content), "%s=%s:%s", entity, property, value);
	if (fms_put(&service->memory, content, AGI_LC_MEMORY_TIER_WORLD_MODEL,
			confidence_ppm, confidence_ppm, provenance_sequence, &memory) != FMS_OK)
		return -2;
	memset(&fact, 0, sizeof(fact));
	fact.key_hash = key;
	fact.memory_record_id = memory.record_id;
	fact.memory_capability = memory.authority_capability;
	fact.provenance_sequence = provenance_sequence;
	fact.event_sequence = service->last_observed_sequence;
	fact.generation = generation + 1;
	fact.freshness_deadline_ns = freshness_ttl_ns ? monotonic_ns() + freshness_ttl_ns : 0;
	fact.confidence_ppm = confidence_ppm;
	fact.freshness_state = freshness_ttl_ns ? AGI_LC_MEMORY_FRESH : AGI_LC_MEMORY_FRESHNESS_UNKNOWN;
	fact.conflict_state = FWS_CONFLICT_NONE;
	if (digest_text(content, fact.digest) < 0)
		return -1;
	strncpy(fact.entity, entity, sizeof(fact.entity) - 1);
	strncpy(fact.property, property, sizeof(fact.property) - 1);
	strncpy(fact.value, value, sizeof(fact.value) - 1);
	for (i = 0; i < service->fact_count; i++)
		if (!strcmp(service->facts[i].entity, entity) &&
		    !strcmp(service->facts[i].property, property))
			service->facts[i].conflict_state = FWS_CONFLICT_RESOLVED;
	service->facts[service->fact_count++] = fact;
	*out = fact;
	return 0;
}

int fws_get_fresh(struct fws_service *service, const char *entity,
			const char *property, struct fws_fact *out)
{
	uint64_t key;
	uint32_t i;
	uint64_t now;
	if (!service || !entity || !property || !out)
		return -1;
	key = hash_text(entity) ^ (hash_text(property) << 1);
	now = monotonic_ns();
	for (i = 0; i < service->fact_count; i++) {
		const struct fws_fact *fact = &service->facts[i];
		if (fact->key_hash != key || fact->conflict_state != FWS_CONFLICT_NONE)
			continue;
		if (fact->freshness_deadline_ns && now >= fact->freshness_deadline_ns) {
			service->facts[i].freshness_state = AGI_LC_MEMORY_STALE;
			*out = service->facts[i];
			return 0;
		}
		*out = *fact;
		return 0;
	}
	return -2;
}

int fws_temporal_probe(struct fws_service *service,
			struct fws_temporal_handle *out)
{
	struct agi_lc_temporal temporal;
	struct agi_lc_world_sync sync;
	if (!service || !out)
		return -1;
	memset(&temporal, 0, sizeof(temporal));
	temporal.size = sizeof(temporal);
	temporal.operation = AGI_LC_TEMPORAL_RECORD;
	temporal.correlation = 73003;
	if (ioctl(service->memory.kernel_fd, AGI_LC_TEMPORAL, &temporal) < 0)
		return -1;
	out->record_id = temporal.record_id;
	out->authority_capability = temporal.authority_capability;
	if (fws_world_query(service, &sync) < 0 || !sync.newest_sequence)
		return -1;
	memset(&temporal, 0, sizeof(temporal));
	temporal.size = sizeof(temporal);
	temporal.operation = AGI_LC_TEMPORAL_CHECK;
	temporal.flags = AGI_LC_TEMPORAL_FLAG_REFERENCE;
	temporal.record_id = out->record_id;
	temporal.authority_capability = out->authority_capability;
	temporal.reference_sequence = sync.newest_sequence;
	temporal.correlation = 73004;
	if (ioctl(service->memory.kernel_fd, AGI_LC_TEMPORAL, &temporal) < 0)
		return -1;
	if (temporal.state != AGI_LC_TEMPORAL_STATE_SATISFIED ||
	    temporal.constraint_result != AGI_LC_TEMPORAL_RESULT_OK)
		return -1;
	out->event_sequence = temporal.event_sequence;
	out->generation = temporal.generation;
	return 0;
}

int fws_resource_snapshot(struct fws_service *service,
			struct agi_lc_resource_snapshot *out)
{
	struct agi_lc_resource_snapshot snapshot;
	if (!service || !out)
		return -1;
	memset(&snapshot, 0, sizeof(snapshot));
	snapshot.size = sizeof(snapshot);
	snapshot.correlation = 73005;
	if (ioctl(service->memory.kernel_fd, AGI_LC_GET_RESOURCE_SNAPSHOT,
		  &snapshot) < 0)
		return -1;
	*out = snapshot;
	return 0;
}

int fws_test_sequence_guard(struct fws_service *service)
{
	uint64_t saved;
	if (!service)
		return -1;
	saved = service->last_observed_sequence;
	if (!saved)
		return -1;
	if (saved < service->last_ack_sequence)
		return -1;
	service->last_observed_sequence = saved - 1;
	if (service->last_observed_sequence >= saved)
		return -1;
	service->last_observed_sequence = saved;
	return 0;
}

int fws_test_stale_temporal(struct fws_service *service,
			    const struct fws_temporal_handle *handle)
{
	struct agi_lc_temporal temporal;
	if (!service || !handle || !handle->record_id || !handle->authority_capability)
		return -1;
	memset(&temporal, 0, sizeof(temporal));
	temporal.size = sizeof(temporal);
	temporal.operation = AGI_LC_TEMPORAL_QUERY;
	temporal.record_id = handle->record_id;
	temporal.authority_capability = handle->authority_capability ^ 1ULL;
	temporal.correlation = 73006;
	if (ioctl(service->memory.kernel_fd, AGI_LC_TEMPORAL, &temporal) == 0)
		return -2;
	return errno == EACCES ? 0 : -3;
}
