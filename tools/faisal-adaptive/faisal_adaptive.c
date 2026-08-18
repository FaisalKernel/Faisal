#define _GNU_SOURCE
#include "faisal_adaptive.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const uint8_t *data, size_t length,
			uint8_t digest[FAP_DIGEST_SIZE])
{
	unsigned int digest_length = 0U;

	if ((data == NULL && length != 0U) || digest == NULL ||
	    EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 ||
	    digest_length != FAP_DIGEST_SIZE)
		return FAP_ERR_TAMPER;
	return FAP_OK;
}

static int zero_digest(const uint8_t digest[FAP_DIGEST_SIZE])
{
	size_t i;

	if (digest == NULL)
		return 1;
	for (i = 0U; i < FAP_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 0;
	return 1;
}

static uint32_t abs_delta_u32(uint32_t left, uint32_t right)
{
	return left >= right ? left - right : right - left;
}

static uint32_t abs_delta_i32(int32_t left, int32_t right)
{
	int64_t delta = (int64_t)left - (int64_t)right;

	if (delta < 0)
		delta = -delta;
	return delta > UINT32_MAX ? UINT32_MAX : (uint32_t)delta;
}

static int valid_action_bounds(const struct fap_policy *policy,
			       const struct fap_action *action, int enforce_delta,
			       const struct fap_action *current)
{
	if (policy == NULL || action == NULL || action->policy_generation == 0U ||
	    action->mode < FAP_MODE_BASELINE || action->mode > FAP_MODE_QUARANTINED ||
	    action->admission_permille < policy->minimum_admission_permille ||
	    action->admission_permille > policy->maximum_admission_permille ||
	    action->migration_permille < policy->minimum_migration_permille ||
	    action->migration_permille > policy->maximum_migration_permille ||
	    action->lease_permille < policy->minimum_lease_permille ||
	    action->lease_permille > policy->maximum_lease_permille ||
	    action->priority_delta < policy->minimum_priority_delta ||
	    action->priority_delta > policy->maximum_priority_delta)
		return FAP_ERR_BOUNDS;
	if (enforce_delta && current != NULL && action->mode != FAP_MODE_FALLBACK &&
	    (abs_delta_u32(action->admission_permille, current->admission_permille) > policy->maximum_action_delta ||
	     abs_delta_u32(action->migration_permille, current->migration_permille) > policy->maximum_action_delta ||
	     abs_delta_u32(action->lease_permille, current->lease_permille) > policy->maximum_action_delta ||
	     abs_delta_i32(action->priority_delta, current->priority_delta) > policy->maximum_action_delta))
		return FAP_ERR_BOUNDS;
	return FAP_OK;
}

static int digest_action(const struct fap_action *action,
			uint8_t digest[FAP_DIGEST_SIZE])
{
	struct fap_action canonical;

	if (action == NULL || digest == NULL)
		return FAP_ERR_ARGUMENT;
	canonical = *action;
	memset(canonical.action_digest, 0, FAP_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_policy(const struct fap_policy *policy,
			uint8_t digest[FAP_DIGEST_SIZE])
{
	struct fap_policy canonical;

	if (policy == NULL || digest == NULL)
		return FAP_ERR_ARGUMENT;
	canonical = *policy;
	memset(canonical.policy_digest, 0, FAP_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_observation(const struct fap_observation *observation,
			      uint8_t digest[FAP_DIGEST_SIZE])
{
	struct fap_observation canonical;

	if (observation == NULL || digest == NULL)
		return FAP_ERR_ARGUMENT;
	canonical = *observation;
	memset(canonical.observation_digest, 0, FAP_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_recommendation(const struct fap_recommendation *recommendation,
				 uint8_t digest[FAP_DIGEST_SIZE])
{
	struct fap_recommendation canonical;

	if (recommendation == NULL || digest == NULL)
		return FAP_ERR_ARGUMENT;
	canonical = *recommendation;
	memset(canonical.recommendation_digest, 0, FAP_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_event(const struct fap_event *event,
			uint8_t digest[FAP_DIGEST_SIZE])
{
	struct fap_event canonical;

	if (event == NULL || digest == NULL)
		return FAP_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, FAP_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

int fap_verify_event(const struct fap_event *event, const uint8_t *payload,
		     const uint8_t previous_digest[FAP_DIGEST_SIZE])
{
	uint8_t payload_digest[FAP_DIGEST_SIZE];
	uint8_t event_digest_value[FAP_DIGEST_SIZE];

	if (event == NULL || previous_digest == NULL ||
	    (payload == NULL && event->payload_len != 0U) ||
	    event->magic != FAP_EVENT_MAGIC || event->version != FAP_EVENT_VERSION ||
	    event->payload_len > FAP_MAX_PAYLOAD ||
	    memcmp(event->previous_digest, previous_digest, FAP_DIGEST_SIZE) != 0 ||
	    digest_bytes(payload, event->payload_len, payload_digest) != FAP_OK ||
	    memcmp(payload_digest, event->payload_digest, FAP_DIGEST_SIZE) != 0 ||
	    digest_event(event, event_digest_value) != FAP_OK ||
	    memcmp(event_digest_value, event->event_digest, FAP_DIGEST_SIZE) != 0)
		return FAP_ERR_TAMPER;
	return FAP_OK;
}

static int write_all(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;
	size_t offset = 0U;
	ssize_t written;

	while (offset < length) {
		written = write(fd, bytes + offset, length - offset);
		if (written < 0 && errno == EINTR)
			continue;
		if (written <= 0)
			return FAP_ERR_IO;
		offset += (size_t)written;
	}
	return FAP_OK;
}

static int read_record(int fd, struct fap_disk_record *record)
{
	uint8_t *bytes = (uint8_t *)record;
	size_t offset = 0U;
	ssize_t count;

	while (offset < sizeof(*record)) {
		count = read(fd, bytes + offset, sizeof(*record) - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return offset == 0U ? FAP_ERR_NOT_FOUND : FAP_ERR_IO;
		if (count < 0)
			return FAP_ERR_IO;
		offset += (size_t)count;
	}
	return FAP_OK;
}

static int append_event_locked(struct fap_service *service, uint16_t kind,
				       uint64_t observation_seq,
				       uint64_t recommendation_id,
				       int status, uint64_t now_ns,
				       const void *payload, size_t payload_len)
{
	struct fap_disk_record record;

	if (service == NULL || payload_len > FAP_MAX_PAYLOAD ||
	    (payload == NULL && payload_len != 0U))
		return FAP_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FAP_EVENT_MAGIC;
	record.event.version = FAP_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->event_sequence + 1U;
	record.event.observation_seq = observation_seq;
	record.event.recommendation_id = recommendation_id;
	record.event.policy_generation = service->policy_generation;
	record.event.observed_at_ns = now_ns;
	record.event.status = status;
	record.event.payload_len = (uint32_t)payload_len;
	memcpy(record.event.previous_digest, service->chain_digest, FAP_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	if (digest_bytes(record.payload, payload_len, record.event.payload_digest) != FAP_OK ||
	    digest_event(&record.event, record.event.event_digest) != FAP_OK ||
	    write_all(service->journal_fd, &record, sizeof(record)) != FAP_OK ||
	    fdatasync(service->journal_fd) != 0)
		return FAP_ERR_IO;
	service->event_sequence = record.event.sequence;
	memcpy(service->chain_digest, record.event.event_digest, FAP_DIGEST_SIZE);
	return FAP_OK;
}

static int valid_policy(const struct fap_policy *policy)
{
	if (policy == NULL || policy->current_time_ns == 0U ||
	    policy->observation_max_age_ns == 0U || policy->maximum_action_delta == 0U ||
	    policy->maximum_queue_depth == 0U ||
	    policy->minimum_admission_permille > policy->maximum_admission_permille ||
	    policy->minimum_migration_permille > policy->maximum_migration_permille ||
	    policy->minimum_lease_permille > policy->maximum_lease_permille ||
	    policy->minimum_priority_delta > policy->maximum_priority_delta ||
	    policy->maximum_pressure_permille > 1000U ||
	    policy->maximum_thermal_permille > 1000U ||
	    policy->minimum_health_permille > 1000U || zero_digest(policy->authority_digest))
		return FAP_ERR_ARGUMENT;
	return FAP_OK;
}

static int valid_observation(const struct fap_service *service,
			     const struct fap_observation *observation)
{
	uint8_t digest[FAP_DIGEST_SIZE];
	uint64_t age;

	if (service == NULL || observation == NULL || observation->observation_seq == 0U ||
	    observation->policy_generation == 0U || observation->source_generation == 0U ||
	    observation->observed_at_ns == 0U || zero_digest(observation->source_digest) ||
	    zero_digest(observation->provenance_digest) ||
	    observation->pressure_permille > 1000U || observation->thermal_permille > 1000U ||
	    observation->health_permille > 1000U || observation->cache_hit_permille > 1000U ||
	    observation->queue_depth > service->policy.maximum_queue_depth ||
	    service->policy.current_time_ns < observation->observed_at_ns)
		return FAP_ERR_ARGUMENT;
	age = service->policy.current_time_ns - observation->observed_at_ns;
	if (age > service->policy.observation_max_age_ns)
		return FAP_ERR_DEADLINE;
	if (digest_observation(observation, digest) != FAP_OK ||
	    (!zero_digest(observation->observation_digest) &&
	     memcmp(digest, observation->observation_digest, FAP_DIGEST_SIZE) != 0))
		return FAP_ERR_TAMPER;
	return FAP_OK;
}

static int valid_recommendation(const struct fap_service *service,
				const struct fap_recommendation *recommendation,
				int enforce_delta)
{
	uint8_t action_digest[FAP_DIGEST_SIZE];
	uint8_t recommendation_digest[FAP_DIGEST_SIZE];
	int result;

	if (service == NULL || recommendation == NULL || recommendation->recommendation_id == 0U ||
	    recommendation->observation_seq == 0U ||
	    recommendation->policy_generation != service->policy_generation ||
	    recommendation->created_at_ns == 0U ||
	    (recommendation->flags & ~FAP_FLAGS_ALL) != 0U ||
	    zero_digest(recommendation->source_digest) ||
	    digest_action(&recommendation->action, action_digest) != FAP_OK ||
	    memcmp(action_digest, recommendation->action.action_digest, FAP_DIGEST_SIZE) != 0 ||
	    digest_recommendation(recommendation, recommendation_digest) != FAP_OK ||
	    (!zero_digest(recommendation->recommendation_digest) &&
	     memcmp(recommendation_digest, recommendation->recommendation_digest, FAP_DIGEST_SIZE) != 0))
		return FAP_ERR_ARGUMENT;
	result = valid_action_bounds(&service->policy, &recommendation->action,
				     enforce_delta && !(recommendation->flags & FAP_FLAG_FALLBACK),
				     &service->current_action);
	return result;
}

static int replay_observation(struct fap_service *service,
			      const struct fap_observation_record *record)
{
	struct fap_observation observation = record->observation;
	struct fap_recommendation recommendation = record->recommendation;
	uint8_t observation_digest[FAP_DIGEST_SIZE];

	if (observation.observation_seq <= service->last_observation.observation_seq ||
	    valid_observation(service, &observation) != FAP_OK ||
	    digest_observation(&observation, observation_digest) != FAP_OK ||
	    memcmp(observation_digest, observation.observation_digest, FAP_DIGEST_SIZE) != 0 ||
	    valid_recommendation(service, &recommendation, 1) != FAP_OK ||
	    recommendation.observation_seq != observation.observation_seq)
		return FAP_ERR_CORRUPT;
	service->last_observation = observation;
	service->current_recommendation = recommendation;
	service->has_observation = 1U;
	if (recommendation.recommendation_id >= service->next_recommendation_id)
		service->next_recommendation_id = recommendation.recommendation_id + 1U;
	return FAP_OK;
}

static int apply_event(struct fap_service *service,
		       const struct fap_disk_record *record)
{
	struct fap_observation_record observation_record;
	struct fap_recommendation recommendation;
	struct fap_action action;
	uint8_t action_digest[FAP_DIGEST_SIZE];

	switch (record->event.kind) {
	case FAP_EVENT_OBSERVATION:
		if (record->event.payload_len != sizeof(observation_record))
			return FAP_ERR_CORRUPT;
		memcpy(&observation_record, record->payload, sizeof(observation_record));
		return replay_observation(service, &observation_record);
	case FAP_EVENT_PROPOSAL:
		if (record->event.payload_len != sizeof(recommendation))
			return FAP_ERR_CORRUPT;
		memcpy(&recommendation, record->payload, sizeof(recommendation));
		if (!service->has_observation || valid_recommendation(service, &recommendation, 1) != FAP_OK ||
		    recommendation.observation_seq != service->last_observation.observation_seq)
			return FAP_ERR_CORRUPT;
		service->current_recommendation = recommendation;
		if (recommendation.recommendation_id >= service->next_recommendation_id)
			service->next_recommendation_id = recommendation.recommendation_id + 1U;
		return FAP_OK;
	case FAP_EVENT_COMMIT:
	case FAP_EVENT_ROLLBACK:
		if (record->event.payload_len != sizeof(action))
			return FAP_ERR_CORRUPT;
		memcpy(&action, record->payload, sizeof(action));
		if (digest_action(&action, action_digest) != FAP_OK ||
		    memcmp(action_digest, action.action_digest, FAP_DIGEST_SIZE) != 0 ||
		    action.policy_generation != record->event.policy_generation ||
		    valid_action_bounds(&service->policy, &action, 0, NULL) != FAP_OK)
			return FAP_ERR_CORRUPT;
		if (record->event.kind == FAP_EVENT_ROLLBACK) {
			if (action.policy_generation <= service->policy_generation)
				return FAP_ERR_REPLAY;
			service->policy_generation = action.policy_generation;
			service->rollback_count++;
		}
		service->current_action = action;
		if (action.mode == FAP_MODE_FALLBACK)
			service->fallback_count++;
		return FAP_OK;
	default:
		return FAP_ERR_CORRUPT;
	}
}

static int replay_locked(struct fap_service *service)
{
	struct fap_disk_record record;
	uint8_t previous[FAP_DIGEST_SIZE] = {0};
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FAP_ERR_IO;
	while ((result = read_record(service->journal_fd, &record)) == FAP_OK) {
		if (record.event.sequence != service->event_sequence + 1U ||
		    fap_verify_event(&record.event, record.payload, previous) != FAP_OK)
			return FAP_ERR_REPLAY;
		result = apply_event(service, &record);
		if (result != FAP_OK)
			return result;
		service->event_sequence = record.event.sequence;
		memcpy(previous, record.event.event_digest, FAP_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FAP_DIGEST_SIZE);
	}
	if (result != FAP_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FAP_ERR_IO;
	return FAP_OK;
}

int fap_open(struct fap_service *service, const char *journal_path,
	     const struct fap_policy *policy)
{
	struct fap_policy configured;
	int result;

	if (service == NULL || journal_path == NULL || valid_policy(policy) != FAP_OK)
		return FAP_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	configured = *policy;
	configured.baseline.policy_generation = 1U;
	configured.baseline.action_generation = 0U;
	configured.baseline.mode = FAP_MODE_BASELINE;
	configured.fallback.policy_generation = 1U;
	configured.fallback.action_generation = 0U;
	configured.fallback.mode = FAP_MODE_FALLBACK;
	if (valid_action_bounds(&configured, &configured.baseline, 0, NULL) != FAP_OK ||
	    valid_action_bounds(&configured, &configured.fallback, 0, NULL) != FAP_OK ||
	    digest_action(&configured.baseline, configured.baseline.action_digest) != FAP_OK ||
	    digest_action(&configured.fallback, configured.fallback.action_digest) != FAP_OK ||
	    digest_policy(&configured, configured.policy_digest) != FAP_OK)
		return FAP_ERR_ARGUMENT;
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FAP_ERR_IO;
	service->policy = configured;
	service->current_action = configured.baseline;
	service->policy_generation = 1U;
	service->next_recommendation_id = 1U;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FAP_ERR_IO;
	}
	result = replay_locked(service);
	if (result != FAP_OK) {
		pthread_mutex_destroy(&service->lock);
		close(service->journal_fd);
	}
	return result;
}

void fap_close(struct fap_service *service)
{
	if (service == NULL)
		return;
	pthread_mutex_destroy(&service->lock);
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

static uint32_t step_up(uint32_t value, uint32_t delta, uint32_t maximum)
{
	if (value >= maximum || maximum - value < delta)
		return maximum;
	return value + delta;
}

static uint32_t step_down(uint32_t value, uint32_t delta, uint32_t minimum)
{
	if (value <= minimum || value - minimum < delta)
		return minimum;
	return value - delta;
}

static int deterministic_recommendation(struct fap_service *service,
					const struct fap_observation *observation,
					struct fap_recommendation *recommendation)
{
	struct fap_action action = service->current_action;
	int unsafe;
	int stable_improving;
	
	unsafe = observation->deadline_misses != 0U ||
		 observation->health_permille < service->policy.minimum_health_permille ||
		 observation->pressure_permille > service->policy.maximum_pressure_permille ||
		 observation->thermal_permille > service->policy.maximum_thermal_permille ||
		 observation->queue_depth >= service->policy.maximum_queue_depth;
	stable_improving = service->has_observation && !unsafe &&
		observation->queue_depth <= service->last_observation.queue_depth &&
		observation->latency_ns <= service->last_observation.latency_ns &&
		observation->throughput_units >= service->last_observation.throughput_units &&
		observation->cache_hit_permille >= service->last_observation.cache_hit_permille &&
		observation->pressure_permille < 700U && observation->thermal_permille < 700U;
	if (unsafe) {
		action = service->policy.fallback;
		action.policy_generation = service->policy_generation;
		action.action_generation = service->current_action.action_generation + 1U;
		action.mode = FAP_MODE_FALLBACK;
		memset(recommendation->reason, 0, sizeof(recommendation->reason));
		(void)snprintf(recommendation->reason, sizeof(recommendation->reason),
			       "deterministic safety fallback");
		recommendation->flags |= FAP_FLAG_FALLBACK;
	} else {
		action.mode = FAP_MODE_ADAPTIVE;
		action.policy_generation = service->policy_generation;
		action.action_generation = service->current_action.action_generation + 1U;
		if (stable_improving) {
			action.admission_permille = step_up(action.admission_permille,
							service->policy.maximum_action_delta,
							service->policy.maximum_admission_permille);
			action.migration_permille = step_down(action.migration_permille,
							  service->policy.maximum_action_delta,
							  service->policy.minimum_migration_permille);
			(void)snprintf(recommendation->reason, sizeof(recommendation->reason),
			       "safe improvement envelope");
		} else {
			action.admission_permille = step_down(action.admission_permille,
							  service->policy.maximum_action_delta,
							  service->policy.minimum_admission_permille);
			action.migration_permille = step_up(action.migration_permille,
							 service->policy.maximum_action_delta,
							 service->policy.maximum_migration_permille);
			(void)snprintf(recommendation->reason, sizeof(recommendation->reason),
			       "bounded pressure-aware adjustment");
		}
	}
	if (digest_action(&action, action.action_digest) != FAP_OK)
		return FAP_ERR_TAMPER;
	recommendation->action = action;
	return FAP_OK;
}

int fap_observe(struct fap_service *service, const struct fap_observation *observation,
		struct fap_recommendation *out)
{
	struct fap_observation normalized;
	struct fap_recommendation recommendation;
	struct fap_observation_record record;
	int result;

	if (service == NULL || observation == NULL || out == NULL)
		return FAP_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	result = valid_observation(service, observation);
	if (result == FAP_OK && observation->policy_generation != service->policy_generation)
		result = FAP_ERR_GENERATION;
	if (result == FAP_OK && service->has_observation &&
	    observation->observation_seq <= service->last_observation.observation_seq)
		result = FAP_ERR_REPLAY;
	if (result != FAP_OK)
		goto done;
	normalized = *observation;
	if (digest_observation(&normalized, normalized.observation_digest) != FAP_OK) {
		result = FAP_ERR_TAMPER;
		goto done;
	}
	memset(&recommendation, 0, sizeof(recommendation));
	recommendation.recommendation_id = service->next_recommendation_id;
	recommendation.observation_seq = normalized.observation_seq;
	recommendation.policy_generation = service->policy_generation;
	recommendation.created_at_ns = normalized.observed_at_ns;
	recommendation.source_kind = 1U;
	recommendation.flags = FAP_FLAG_VERIFIED_INPUT;
	memcpy(recommendation.source_digest, normalized.source_digest, FAP_DIGEST_SIZE);
	result = deterministic_recommendation(service, &normalized, &recommendation);
	if (result != FAP_OK)
		goto done;
	if (digest_recommendation(&recommendation, recommendation.recommendation_digest) != FAP_OK) {
		result = FAP_ERR_TAMPER;
		goto done;
	}
	record.observation = normalized;
	record.recommendation = recommendation;
	result = append_event_locked(service, FAP_EVENT_OBSERVATION,
				     normalized.observation_seq, recommendation.recommendation_id,
				     FAP_OK, normalized.observed_at_ns, &record, sizeof(record));
	if (result == FAP_OK) {
		service->last_observation = normalized;
		service->current_recommendation = recommendation;
		service->has_observation = 1U;
		service->next_recommendation_id++;
		*out = recommendation;
	}
done:
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fap_propose(struct fap_service *service, const struct fap_recommendation *proposal,
		struct fap_recommendation *out)
{
	struct fap_recommendation normalized;
	uint64_t previous_next_recommendation_id;
	int result;

	if (service == NULL || proposal == NULL || out == NULL)
		return FAP_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	previous_next_recommendation_id = service->next_recommendation_id;
	if (!service->has_observation || proposal->observation_seq != service->last_observation.observation_seq ||
	    proposal->policy_generation != service->policy_generation ||
	    (proposal->flags & FAP_FLAG_VERIFIED_INPUT) == 0U)
		result = FAP_ERR_AUTHORITY;
	else {
		normalized = *proposal;
		normalized.recommendation_id = service->next_recommendation_id++;
		normalized.policy_generation = service->policy_generation;
		memset(normalized.recommendation_digest, 0, FAP_DIGEST_SIZE);
		if (zero_digest(normalized.source_digest))
			result = FAP_ERR_ARGUMENT;
		else if (normalized.action.policy_generation != service->policy_generation)
			result = FAP_ERR_GENERATION;
		else {
				if (digest_action(&normalized.action, normalized.action.action_digest) != FAP_OK) {
					result = FAP_ERR_TAMPER;
				} else {
					result = valid_recommendation(service, &normalized, 1);
					if (result == FAP_OK && digest_recommendation(&normalized,
										 normalized.recommendation_digest) != FAP_OK) {
						result = FAP_ERR_TAMPER;
					}
					if (result == FAP_OK) {
						result = append_event_locked(service, FAP_EVENT_PROPOSAL,
									     normalized.observation_seq,
									     normalized.recommendation_id, FAP_OK,
									     normalized.created_at_ns, &normalized,
									     sizeof(normalized));
						if (result == FAP_OK) {
							service->current_recommendation = normalized;
							*out = normalized;
						}
					}
				}
			}
		}
		if (result != FAP_OK)
			service->next_recommendation_id = previous_next_recommendation_id;
		pthread_mutex_unlock(&service->lock);
		return result;
}

int fap_commit(struct fap_service *service, uint64_t recommendation_id,
	       uint64_t now_ns, uint32_t flags, struct fap_action *out)
{
	struct fap_recommendation recommendation;
	struct fap_action action;
	int result;

	if (service == NULL || out == NULL || recommendation_id == 0U || now_ns == 0U ||
	    (flags & (FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT | FAP_FLAG_EXPERIMENTAL)) !=
	    (FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT | FAP_FLAG_EXPERIMENTAL) ||
	    (flags & ~FAP_FLAGS_ALL) != 0U)
		return FAP_ERR_AUTHORITY;
	pthread_mutex_lock(&service->lock);
	recommendation = service->current_recommendation;
	if (!service->has_observation || recommendation.recommendation_id != recommendation_id)
		result = FAP_ERR_NOT_FOUND;
	else if (recommendation.flags & FAP_FLAG_MODEL_PROPOSAL)
		result = FAP_ERR_AUTHORITY;
	else if (recommendation.policy_generation != service->policy_generation)
		result = FAP_ERR_GENERATION;
	else if (now_ns < recommendation.created_at_ns)
		result = FAP_ERR_DEADLINE;
	else {
		action = recommendation.action;
		result = valid_action_bounds(&service->policy, &action,
					     action.mode != FAP_MODE_FALLBACK,
					     &service->current_action);
		if (result == FAP_OK)
			result = append_event_locked(service, FAP_EVENT_COMMIT,
						     recommendation.observation_seq, recommendation_id,
						     FAP_OK, now_ns, &action, sizeof(action));
		if (result == FAP_OK) {
			service->current_action = action;
			if (action.mode == FAP_MODE_FALLBACK)
				service->fallback_count++;
			*out = action;
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fap_rollback(struct fap_service *service, uint64_t now_ns, uint32_t flags,
		const char *reason, struct fap_action *out)
{
	struct fap_action action;
	int result;

	if (service == NULL || out == NULL || reason == NULL || reason[0] == '\0' ||
	    now_ns == 0U || (flags & (FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT)) !=
	    (FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT))
		return FAP_ERR_AUTHORITY;
	pthread_mutex_lock(&service->lock);
	if (service->policy_generation == UINT64_MAX)
		result = FAP_ERR_OVERFLOW;
	else {
		memset(&action, 0, sizeof(action));
		service->policy_generation++;
		action = service->policy.fallback;
		action.policy_generation = service->policy_generation;
		action.action_generation = service->current_action.action_generation + 1U;
		action.mode = FAP_MODE_FALLBACK;
		if (digest_action(&action, action.action_digest) != FAP_OK)
			result = FAP_ERR_TAMPER;
		else
			result = append_event_locked(service, FAP_EVENT_ROLLBACK, 0U, 0U,
						    FAP_ERR_UNSAFE, now_ns, &action, sizeof(action));
		if (result == FAP_OK) {
			service->current_action = action;
			service->current_recommendation = (struct fap_recommendation){0};
			service->rollback_count++;
			service->fallback_count++;
			*out = action;
		} else
			service->policy_generation--;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fap_query(const struct fap_service *service, struct fap_attestation *out)
{
	if (service == NULL || out == NULL)
		return FAP_ERR_ARGUMENT;
	pthread_mutex_lock((pthread_mutex_t *)&service->lock);
	memset(out, 0, sizeof(*out));
	out->last_sequence = service->event_sequence;
	out->last_observation_seq = service->last_observation.observation_seq;
	out->last_recommendation_id = service->current_recommendation.recommendation_id;
	out->policy_generation = service->policy_generation;
	out->fallback_count = service->fallback_count;
	out->rollback_count = service->rollback_count;
	memcpy(out->chain_digest, service->chain_digest, FAP_DIGEST_SIZE);
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FAP_OK;
}
