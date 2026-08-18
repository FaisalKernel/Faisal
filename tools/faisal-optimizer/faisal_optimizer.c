#define _GNU_SOURCE
#include "faisal_optimizer.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const uint8_t *data, size_t length,
			uint8_t digest[FAO_DIGEST_SIZE])
{
	unsigned int digest_length = 0U;

	if ((data == NULL && length != 0U) || digest == NULL ||
	    EVP_Digest(data, length, digest, &digest_length, EVP_sha256(), NULL) != 1 ||
	    digest_length != FAO_DIGEST_SIZE)
		return FAO_ERR_TAMPER;
	return FAO_OK;
}

static int zero_digest(const uint8_t digest[FAO_DIGEST_SIZE])
{
	for (size_t i = 0U; i < FAO_DIGEST_SIZE; ++i)
		if (digest[i] != 0U)
			return 0;
	return 1;
}

static uint64_t safe_add_u64(uint64_t left, uint64_t right, int *ok)
{
	if (UINT64_MAX - left < right) {
		*ok = 0;
		return 0U;
	}
	return left + right;
}

static uint64_t ratio_increase_u64(uint64_t current, uint64_t previous)
{
	uint64_t delta;

	if (previous == 0U || current <= previous)
		return 0U;
	delta = current - previous;
	if (delta > UINT64_MAX / 1000U)
		return 1000U;
	delta = (delta * 1000U) / previous;
	return delta > 1000U ? 1000U : delta;
}

static uint32_t ratio_decrease_u64(uint64_t current, uint64_t previous)
{
	uint64_t delta;

	if (previous == 0U || current >= previous)
		return 0U;
	delta = previous - current;
	if (delta > UINT64_MAX / 1000U)
		return 1000U;
	delta = (delta * 1000U) / previous;
	return delta > 1000U ? 1000U : (uint32_t)delta;
}

static int digest_sample(const struct fao_sample *sample,
			uint8_t digest[FAO_DIGEST_SIZE])
{
	struct fao_sample canonical;

	if (sample == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	canonical = *sample;
	memset(canonical.sample_digest, 0, FAO_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_forecast(const struct fao_forecast *forecast,
			   uint8_t digest[FAO_DIGEST_SIZE])
{
	struct fao_forecast canonical;

	if (forecast == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	canonical = *forecast;
	memset(canonical.forecast_digest, 0, FAO_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_candidate(const struct fao_candidate *candidate,
			    uint8_t digest[FAO_DIGEST_SIZE])
{
	struct fao_candidate canonical;

	if (candidate == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	canonical = *candidate;
	memset(canonical.candidate_digest, 0, FAO_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_compare(const struct fao_compare *compare,
			  uint8_t digest[FAO_DIGEST_SIZE])
{
	struct fao_compare canonical;

	if (compare == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	canonical = *compare;
	memset(canonical.compare_digest, 0, FAO_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

static int digest_transition(const struct fao_transition *transition,
			     uint8_t digest[FAO_DIGEST_SIZE])
{
	if (transition == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	return digest_bytes((const uint8_t *)transition, sizeof(*transition), digest);
}

static int digest_event(const struct fao_event *event,
			uint8_t digest[FAO_DIGEST_SIZE])
{
	struct fao_event canonical;

	if (event == NULL || digest == NULL)
		return FAO_ERR_ARGUMENT;
	canonical = *event;
	memset(canonical.event_digest, 0, FAO_DIGEST_SIZE);
	return digest_bytes((const uint8_t *)&canonical, sizeof(canonical), digest);
}

int fao_verify_event(const struct fao_event *event, const uint8_t *payload,
		     const uint8_t previous_digest[FAO_DIGEST_SIZE])
{
	uint8_t payload_digest[FAO_DIGEST_SIZE];
	uint8_t event_digest_value[FAO_DIGEST_SIZE];

	if (event == NULL || previous_digest == NULL ||
	    (payload == NULL && event->payload_len != 0U) ||
	    event->magic != FAO_EVENT_MAGIC || event->version != FAO_EVENT_VERSION ||
	    event->payload_len > FAO_MAX_PAYLOAD ||
	    memcmp(event->previous_digest, previous_digest, FAO_DIGEST_SIZE) != 0 ||
	    digest_bytes(payload, event->payload_len, payload_digest) != FAO_OK ||
	    memcmp(payload_digest, event->payload_digest, FAO_DIGEST_SIZE) != 0 ||
	    digest_event(event, event_digest_value) != FAO_OK ||
	    memcmp(event_digest_value, event->event_digest, FAO_DIGEST_SIZE) != 0)
		return FAO_ERR_TAMPER;
	return FAO_OK;
}

static int write_all(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;
	size_t offset = 0U;
	ssize_t count;

	while (offset < length) {
		count = write(fd, bytes + offset, length - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return FAO_ERR_IO;
		offset += (size_t)count;
	}
	return FAO_OK;
}

static int read_record(int fd, struct fao_disk_record *record)
{
	uint8_t *bytes = (uint8_t *)record;
	size_t offset = 0U;
	ssize_t count;

	while (offset < sizeof(*record)) {
		count = read(fd, bytes + offset, sizeof(*record) - offset);
		if (count < 0 && errno == EINTR)
			continue;
		if (count == 0)
			return offset == 0U ? FAO_ERR_NOT_FOUND : FAO_ERR_IO;
		if (count < 0)
			return FAO_ERR_IO;
		offset += (size_t)count;
	}
	return FAO_OK;
}

static int append_event_locked(struct fao_service *service, uint16_t kind,
				       uint64_t object_id, int status,
				       uint64_t observed_at_ns, const void *payload,
				       size_t payload_len)
{
	struct fao_disk_record record;

	if (service == NULL || payload_len > FAO_MAX_PAYLOAD ||
	    (payload == NULL && payload_len != 0U))
		return FAO_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.event.magic = FAO_EVENT_MAGIC;
	record.event.version = FAO_EVENT_VERSION;
	record.event.kind = kind;
	record.event.sequence = service->event_sequence + 1U;
	record.event.policy_generation = service->adaptive->policy_generation;
	record.event.object_id = object_id;
	record.event.observed_at_ns = observed_at_ns;
	record.event.status = status;
	record.event.payload_len = (uint32_t)payload_len;
	memcpy(record.event.previous_digest, service->chain_digest, FAO_DIGEST_SIZE);
	if (payload_len != 0U)
		memcpy(record.payload, payload, payload_len);
	if (digest_bytes(record.payload, payload_len, record.event.payload_digest) != FAO_OK ||
	    digest_event(&record.event, record.event.event_digest) != FAO_OK ||
	    write_all(service->journal_fd, &record, sizeof(record)) != FAO_OK ||
	    fdatasync(service->journal_fd) != 0)
		return FAO_ERR_IO;
	service->event_sequence = record.event.sequence;
	memcpy(service->chain_digest, record.event.event_digest, FAO_DIGEST_SIZE);
	return FAO_OK;
}

static int valid_policy(const struct fao_policy *policy)
{
	if (policy == NULL || policy->now_ns == 0U || policy->max_age_ns == 0U ||
	    policy->minimum_canary_samples == 0U || policy->minimum_canary_samples > FAO_MAX_SAMPLES ||
	    policy->maximum_latency_increase_permille > 1000U ||
	    policy->maximum_throughput_decrease_permille > 1000U ||
	    policy->maximum_pressure_permille > 1000U || policy->maximum_thermal_permille > 1000U ||
	    policy->minimum_health_permille > 1000U || policy->maximum_queue_depth == 0U ||
	    policy->maximum_forecast_risk_permille > 1000U ||
	    policy->minimum_confidence_permille > 1000U || zero_digest(policy->authority_digest))
		return FAO_ERR_ARGUMENT;
	return FAO_OK;
}

static int valid_sample(const struct fao_service *service,
			const struct fao_sample *sample)
{
	uint8_t digest[FAO_DIGEST_SIZE];
	uint64_t age;

	if (service == NULL || sample == NULL || sample->sequence == 0U ||
	    sample->policy_generation == 0U || sample->observed_at_ns == 0U || sample->source_generation == 0U ||
	    (sample->lane != FAO_LANE_CONTROL && sample->lane != FAO_LANE_CANARY) ||
	    sample->queue_depth > service->policy.maximum_queue_depth ||
	    sample->pressure_permille > 1000U || sample->thermal_permille > 1000U ||
	    sample->health_permille > 1000U || sample->cache_hit_permille > 1000U ||
	    zero_digest(sample->source_digest) || zero_digest(sample->provenance_digest) ||
	    service->policy.now_ns < sample->observed_at_ns)
		return FAO_ERR_ARGUMENT;
	age = service->policy.now_ns - sample->observed_at_ns;
	if (age > service->policy.max_age_ns)
		return FAO_ERR_DEADLINE;
	if (digest_sample(sample, digest) != FAO_OK ||
	    (!zero_digest(sample->sample_digest) && memcmp(digest, sample->sample_digest, FAO_DIGEST_SIZE) != 0))
		return FAO_ERR_TAMPER;
	return FAO_OK;
}

static void window_push(struct fao_service *service, const struct fao_sample *sample)
{
	service->samples[service->sample_cursor] = *sample;
	service->sample_cursor = (service->sample_cursor + 1U) % FAO_MAX_SAMPLES;
	if (service->sample_count < FAO_MAX_SAMPLES)
		service->sample_count++;
	service->last_sample_sequence = sample->sequence;
}

static int get_previous_sample(const struct fao_service *service,
			       struct fao_sample *out)
{
	uint32_t index;

	if (service->sample_count < 1U || out == NULL)
		return FAO_ERR_NOT_FOUND;
	index = service->sample_cursor == 0U ? FAO_MAX_SAMPLES - 1U : service->sample_cursor - 1U;
	*out = service->samples[index];
	return FAO_OK;
}

static int get_previous_previous_sample(const struct fao_service *service,
					struct fao_sample *out)
{
	uint32_t index;

	if (service->sample_count < 2U || out == NULL)
		return FAO_ERR_NOT_FOUND;
	index = service->sample_cursor < 2U ? FAO_MAX_SAMPLES + service->sample_cursor - 2U : service->sample_cursor - 2U;
	*out = service->samples[index];
	return FAO_OK;
}

static uint32_t mean_lane_count(const struct fao_service *service, uint32_t lane,
				struct fao_window_stats *stats)
{
	uint64_t latency = 0U;
	uint64_t throughput = 0U;
	uint64_t energy = 0U;
	uint32_t pressure = 0U;
	uint32_t thermal = 0U;
	uint32_t health = 1000U;
	uint32_t count = 0U;
	uint32_t start;
	int ok = 1;

	if (service == NULL || stats == NULL)
		return 0U;
	start = service->sample_count == FAO_MAX_SAMPLES ? service->sample_cursor : 0U;
	for (uint32_t i = 0U; i < service->sample_count; ++i) {
		const struct fao_sample *sample = &service->samples[(start + i) % FAO_MAX_SAMPLES];
		if (sample->lane != lane)
			continue;
		latency = safe_add_u64(latency, sample->latency_ns, &ok);
		throughput = safe_add_u64(throughput, sample->throughput_units, &ok);
		energy = safe_add_u64(energy, sample->energy_uj, &ok);
		if (!ok)
			return 0U;
		if (UINT32_MAX - pressure < sample->pressure_permille ||
		    UINT32_MAX - thermal < sample->thermal_permille)
			return 0U;
		pressure += sample->pressure_permille;
		thermal += sample->thermal_permille;
		if (sample->health_permille < health)
			health = sample->health_permille;
		count++;
	}
	memset(stats, 0, sizeof(*stats));
	stats->count = count;
	if (count == 0U)
		return 0U;
	stats->mean_latency_ns = latency / count;
	stats->mean_throughput_units = throughput / count;
	stats->mean_pressure_permille = pressure / count;
	stats->mean_thermal_permille = thermal / count;
	stats->mean_health_permille = health;
	stats->mean_energy_uj = energy / count;
	return count;
}

static int make_forecast(const struct fao_service *service,
			 const struct fao_sample *sample, struct fao_forecast *forecast)
{
	struct fao_sample previous;
	struct fao_sample previous_previous;
	uint32_t risk = 0U;
	uint32_t flags = 0U;
	uint32_t confidence;
	uint64_t latency_prediction = sample->latency_ns;
	uint64_t throughput_prediction = sample->throughput_units;

	if (service == NULL || sample == NULL || forecast == NULL)
		return FAO_ERR_ARGUMENT;
	memset(forecast, 0, sizeof(*forecast));
	forecast->forecast_id = service->next_forecast_id;
	forecast->sample_sequence = sample->sequence;
	forecast->policy_generation = sample->policy_generation;
	forecast->created_at_ns = sample->observed_at_ns;
	forecast->source_digest[0] = sample->source_digest[0];
	confidence = service->sample_count >= 16U ? 1000U : service->sample_count * 1000U / 16U;
	forecast->confidence_permille = confidence;
	if (sample->deadline_misses != 0U || sample->health_permille < service->policy.minimum_health_permille ||
	    sample->pressure_permille > service->policy.maximum_pressure_permille ||
	    sample->thermal_permille > service->policy.maximum_thermal_permille ||
	    sample->queue_depth > service->policy.maximum_queue_depth)
		risk = 1000U;
	else {
		risk = sample->pressure_permille > risk ? sample->pressure_permille : risk;
		risk = sample->thermal_permille > risk ? sample->thermal_permille : risk;
		if (sample->queue_depth > service->policy.maximum_queue_depth / 2U)
			flags |= FAO_REGRESSION_QUEUE;
	}
	if (get_previous_sample(service, &previous) == FAO_OK) {
		uint64_t latency_increase = ratio_increase_u64(sample->latency_ns, previous.latency_ns);
		uint32_t throughput_decrease = ratio_decrease_u64(sample->throughput_units, previous.throughput_units);
		if (latency_increase > service->policy.maximum_latency_increase_permille)
			flags |= FAO_REGRESSION_LATENCY;
		if (throughput_decrease > service->policy.maximum_throughput_decrease_permille)
			flags |= FAO_REGRESSION_THROUGHPUT;
		if (latency_increase > risk)
			risk = latency_increase > 1000U ? 1000U : (uint32_t)latency_increase;
		if (throughput_decrease > risk)
			risk = throughput_decrease;
		if (sample->pressure_permille > previous.pressure_permille)
			flags |= FAO_REGRESSION_PRESSURE;
		if (sample->thermal_permille > previous.thermal_permille)
			flags |= FAO_REGRESSION_THERMAL;
		if (sample->health_permille < previous.health_permille)
			flags |= FAO_REGRESSION_HEALTH;
		if (sample->latency_ns > previous.latency_ns) {
			uint64_t delta = sample->latency_ns - previous.latency_ns;
			latency_prediction = delta > UINT64_MAX - sample->latency_ns ? UINT64_MAX : sample->latency_ns + delta;
		}
		if (sample->throughput_units < previous.throughput_units) {
			uint64_t delta = previous.throughput_units - sample->throughput_units;
			throughput_prediction = sample->throughput_units > delta ? sample->throughput_units - delta : 0U;
		}
	}
	if (get_previous_previous_sample(service, &previous_previous) == FAO_OK &&
	    sample->latency_ns > previous.latency_ns && previous.latency_ns > previous_previous.latency_ns)
		flags |= FAO_REGRESSION_LATENCY;
	forecast->risk_permille = risk > 1000U ? 1000U : risk;
	forecast->regression_flags = flags;
	forecast->predicted_latency_ns = latency_prediction;
	forecast->predicted_throughput_units = throughput_prediction;
	forecast->predicted_queue_depth = sample->queue_depth;
	forecast->predicted_pressure_permille = sample->pressure_permille;
	forecast->predicted_thermal_permille = sample->thermal_permille;
	forecast->predicted_health_permille = sample->health_permille;
	return digest_forecast(forecast, forecast->forecast_digest);
}

static int apply_event(struct fao_service *service,
		       const struct fao_disk_record *record)
{
	struct fao_sample_record sample_record;
	struct fao_candidate candidate;
	struct fao_transition transition;
	struct fao_compare compare;
	uint8_t digest[FAO_DIGEST_SIZE];

	if (service == NULL || record == NULL)
		return FAO_ERR_ARGUMENT;
	switch (record->event.kind) {
	case FAO_EVENT_SAMPLE:
		if (record->event.payload_len != sizeof(sample_record))
			return FAO_ERR_REPLAY;
		memcpy(&sample_record, record->payload, sizeof(sample_record));
		if (record->event.policy_generation != sample_record.sample.policy_generation ||
		    valid_sample(service, &sample_record.sample) != FAO_OK ||
		    digest_forecast(&sample_record.forecast, digest) != FAO_OK ||
		    memcmp(digest, sample_record.forecast.forecast_digest, FAO_DIGEST_SIZE) != 0 ||
		    sample_record.forecast.sample_sequence != sample_record.sample.sequence ||
		    sample_record.sample.sequence <= service->last_sample_sequence)
			return FAO_ERR_REPLAY;
		window_push(service, &sample_record.sample);
		service->forecast = sample_record.forecast;
		service->next_forecast_id = sample_record.forecast.forecast_id + 1U;
		return FAO_OK;
	case FAO_EVENT_CANDIDATE:
		if (record->event.payload_len != sizeof(candidate))
			return FAO_ERR_REPLAY;
		memcpy(&candidate, record->payload, sizeof(candidate));
		if (record->event.policy_generation != candidate.policy_generation ||
		    digest_candidate(&candidate, digest) != FAO_OK ||
		    memcmp(digest, candidate.candidate_digest, FAO_DIGEST_SIZE) != 0 ||
		    candidate.policy_generation == 0U)
			return FAO_ERR_REPLAY;
		service->candidate = candidate;
		service->stage = candidate.stage;
		service->next_candidate_id = candidate.candidate_id + 1U;
		return FAO_OK;
	case FAO_EVENT_TRANSITION:
		if (record->event.payload_len != sizeof(transition))
			return FAO_ERR_REPLAY;
		memcpy(&transition, record->payload, sizeof(transition));
		if (transition.candidate_id != service->candidate.candidate_id ||
		    transition.policy_generation == 0U ||
		    (transition.to_stage == FAO_STAGE_ROLLED_BACK &&
		     transition.policy_generation != service->adaptive->policy_generation) ||
		    (transition.to_stage != FAO_STAGE_ROLLED_BACK &&
		     transition.policy_generation != service->candidate.policy_generation) ||
		    digest_transition(&transition, digest) != FAO_OK || zero_digest(transition.reason_digest))
			return FAO_ERR_REPLAY;
		service->stage = transition.to_stage;
		if (transition.to_stage == FAO_STAGE_ROLLED_BACK)
			service->rollback_count++;
		return FAO_OK;
	case FAO_EVENT_COMPARE:
		if (record->event.payload_len != sizeof(compare))
			return FAO_ERR_REPLAY;
		memcpy(&compare, record->payload, sizeof(compare));
		if (digest_compare(&compare, digest) != FAO_OK ||
		    memcmp(digest, compare.compare_digest, FAO_DIGEST_SIZE) != 0)
			return FAO_ERR_REPLAY;
		service->compare = compare;
		return FAO_OK;
	default:
		return FAO_ERR_REPLAY;
	}
}

static int replay_locked(struct fao_service *service)
{
	struct fao_disk_record record;
	uint8_t previous[FAO_DIGEST_SIZE] = {0};
	int result;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FAO_ERR_IO;
	while ((result = read_record(service->journal_fd, &record)) == FAO_OK) {
		if (record.event.sequence != service->event_sequence + 1U ||
		    fao_verify_event(&record.event, record.payload, previous) != FAO_OK ||
		    apply_event(service, &record) != FAO_OK)
			return FAO_ERR_REPLAY;
		service->event_sequence = record.event.sequence;
		memcpy(previous, record.event.event_digest, FAO_DIGEST_SIZE);
		memcpy(service->chain_digest, previous, FAO_DIGEST_SIZE);
	}
	if (result != FAO_ERR_NOT_FOUND)
		return result;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FAO_ERR_IO;
	return FAO_OK;
}

int fao_open(struct fao_service *service, const char *journal_path,
	     const struct fao_policy *policy, struct fap_service *adaptive)
{
	if (service == NULL || journal_path == NULL || adaptive == NULL ||
	    valid_policy(policy) != FAO_OK)
		return FAO_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FAO_ERR_IO;
	service->adaptive = adaptive;
	service->policy = *policy;
	service->stage = FAO_STAGE_IDLE;
	service->next_forecast_id = 1U;
	service->next_candidate_id = 1U;
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->journal_fd);
		return FAO_ERR_IO;
	}
	if (replay_locked(service) != FAO_OK) {
		pthread_mutex_destroy(&service->lock);
		close(service->journal_fd);
		return FAO_ERR_REPLAY;
	}
	return FAO_OK;
}

void fao_close(struct fao_service *service)
{
	if (service == NULL)
		return;
	pthread_mutex_destroy(&service->lock);
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

int fao_ingest(struct fao_service *service, const struct fao_sample *sample,
	       struct fao_forecast *out)
{
	struct fao_sample normalized;
	struct fao_forecast forecast;
	struct fao_sample_record record;
	int result;

	if (service == NULL || sample == NULL || out == NULL)
		return FAO_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	result = valid_sample(service, sample);
	if (result == FAO_OK && sample->policy_generation != service->adaptive->policy_generation)
		result = FAO_ERR_GENERATION;
	if (result == FAO_OK && sample->sequence <= service->last_sample_sequence)
		result = FAO_ERR_REPLAY;
	if (result == FAO_OK) {
		normalized = *sample;
		result = digest_sample(&normalized, normalized.sample_digest);
	}
	if (result == FAO_OK) {
		result = make_forecast(service, &normalized, &forecast);
		if (result == FAO_OK) {
			record.sample = normalized;
			record.forecast = forecast;
			result = append_event_locked(service, FAO_EVENT_SAMPLE,
						     normalized.sequence, FAP_OK,
						     normalized.observed_at_ns, &record,
						     sizeof(record));
		}
	}
	if (result == FAO_OK) {
		window_push(service, &normalized);
		service->forecast = forecast;
		service->next_forecast_id++;
		*out = forecast;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fao_attach_recommendation(struct fao_service *service,
			      const struct fap_recommendation *recommendation,
			      struct fao_candidate *out)
{
	struct fao_candidate candidate;
	int result;

	if (service == NULL || recommendation == NULL || out == NULL)
		return FAO_ERR_ARGUMENT;
	pthread_mutex_lock(&service->lock);
	if (service->stage != FAO_STAGE_IDLE || recommendation->policy_generation != service->adaptive->policy_generation ||
	    recommendation->recommendation_id == 0U || recommendation->action.policy_generation != service->adaptive->policy_generation)
		result = FAO_ERR_STATE;
	else {
		memset(&candidate, 0, sizeof(candidate));
		candidate.candidate_id = service->next_candidate_id;
		candidate.forecast_id = service->forecast.forecast_id;
		candidate.recommendation_id = recommendation->recommendation_id;
		candidate.policy_generation = recommendation->policy_generation;
		candidate.created_at_ns = recommendation->created_at_ns;
		candidate.flags = (recommendation->flags & FAP_FLAG_MODEL_PROPOSAL) != 0U ? FAO_FLAG_MODEL_ADVISORY : 0U;
		candidate.stage = FAO_STAGE_PROPOSED;
		candidate.action = recommendation->action;
		result = digest_candidate(&candidate, candidate.candidate_digest);
		if (result == FAO_OK)
			result = append_event_locked(service, FAO_EVENT_CANDIDATE, candidate.candidate_id,
						     FAP_OK, candidate.created_at_ns, &candidate,
						     sizeof(candidate));
		if (result == FAO_OK) {
			service->candidate = candidate;
			service->stage = FAO_STAGE_PROPOSED;
			service->next_candidate_id++;
			*out = candidate;
		}
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int transition_locked(struct fao_service *service, uint32_t to_stage,
			     int status, uint64_t now_ns, const char *reason)
{
	struct fao_transition transition;
	uint8_t reason_digest[FAO_DIGEST_SIZE];
	int result;

	if (reason == NULL || reason[0] == '\0')
		return FAO_ERR_ARGUMENT;
	memset(&transition, 0, sizeof(transition));
	transition.candidate_id = service->candidate.candidate_id;
	transition.policy_generation = service->adaptive->policy_generation;
	transition.from_stage = service->stage;
	transition.to_stage = to_stage;
	transition.status = status;
	if (digest_bytes((const uint8_t *)reason, strlen(reason), reason_digest) != FAO_OK)
		return FAO_ERR_TAMPER;
	memcpy(transition.reason_digest, reason_digest, FAO_DIGEST_SIZE);
	result = append_event_locked(service, FAO_EVENT_TRANSITION,
				     transition.candidate_id, status, now_ns,
				     &transition, sizeof(transition));
	if (result == FAO_OK) {
		service->stage = to_stage;
		if (to_stage == FAO_STAGE_ROLLED_BACK)
			service->rollback_count++;
	}
	return result;
}

int fao_approve(struct fao_service *service, uint64_t candidate_id,
		uint64_t now_ns, uint32_t flags)
{
	int result;

	if (service == NULL || now_ns == 0U ||
	    (flags & (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL)) !=
	    (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL) ||
	    (flags & ~FAO_FLAGS_ALL) != 0U)
		return FAO_ERR_AUTHORITY;
	pthread_mutex_lock(&service->lock);
	if (service->stage != FAO_STAGE_PROPOSED || service->candidate.candidate_id != candidate_id)
		result = FAO_ERR_STATE;
	else if ((service->candidate.flags & FAO_FLAG_MODEL_ADVISORY) != 0U)
		result = FAO_ERR_AUTHORITY;
	else if (service->forecast.risk_permille > service->policy.maximum_forecast_risk_permille ||
		 service->forecast.confidence_permille < service->policy.minimum_confidence_permille)
		result = FAO_ERR_UNSAFE;
	else
		result = transition_locked(service, FAO_STAGE_APPROVED, FAO_OK, now_ns,
					   "approved by bounded policy authority");
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fao_begin_canary(struct fao_service *service, uint64_t candidate_id,
		     uint64_t now_ns, uint32_t flags)
{
	int result;

	if (service == NULL || now_ns == 0U ||
	    (flags & (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL)) !=
	    (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL))
		return FAO_ERR_AUTHORITY;
	pthread_mutex_lock(&service->lock);
	if (service->stage != FAO_STAGE_APPROVED || service->candidate.candidate_id != candidate_id)
		result = FAO_ERR_STATE;
	else
		result = transition_locked(service, FAO_STAGE_CANARY, FAO_OK, now_ns,
					   "bounded canary started");
	pthread_mutex_unlock(&service->lock);
	return result;
}

static int compute_compare(const struct fao_service *service,
			   struct fao_compare *compare)
{
	struct fao_window_stats control;
	struct fao_window_stats canary;

	if (mean_lane_count(service, FAO_LANE_CONTROL, &control) == 0U ||
	    mean_lane_count(service, FAO_LANE_CANARY, &canary) == 0U)
		return FAO_ERR_STATE;
	memset(compare, 0, sizeof(*compare));
	compare->control_count = control.count;
	compare->canary_count = canary.count;
	compare->control_mean_latency_ns = control.mean_latency_ns;
	compare->canary_mean_latency_ns = canary.mean_latency_ns;
	compare->control_mean_throughput_units = control.mean_throughput_units;
	compare->canary_mean_throughput_units = canary.mean_throughput_units;
	compare->control_mean_pressure_permille = control.mean_pressure_permille;
	compare->canary_mean_pressure_permille = canary.mean_pressure_permille;
	compare->control_mean_thermal_permille = control.mean_thermal_permille;
	compare->canary_mean_thermal_permille = canary.mean_thermal_permille;
	compare->control_min_health_permille = control.mean_health_permille;
	compare->canary_min_health_permille = canary.mean_health_permille;
	if (compare->canary_mean_latency_ns > compare->control_mean_latency_ns &&
	    ratio_increase_u64(compare->canary_mean_latency_ns, compare->control_mean_latency_ns) >
	    service->policy.maximum_latency_increase_permille)
		compare->regression_flags |= FAO_REGRESSION_LATENCY;
	if (compare->canary_mean_throughput_units < compare->control_mean_throughput_units &&
	    ratio_decrease_u64(compare->canary_mean_throughput_units, compare->control_mean_throughput_units) >
	    service->policy.maximum_throughput_decrease_permille)
		compare->regression_flags |= FAO_REGRESSION_THROUGHPUT;
	if (compare->canary_mean_pressure_permille > service->policy.maximum_pressure_permille)
		compare->regression_flags |= FAO_REGRESSION_PRESSURE;
	if (compare->canary_mean_thermal_permille > service->policy.maximum_thermal_permille)
		compare->regression_flags |= FAO_REGRESSION_THERMAL;
	if (compare->canary_min_health_permille < service->policy.minimum_health_permille)
		compare->regression_flags |= FAO_REGRESSION_HEALTH;
	return digest_compare(compare, compare->compare_digest);
}

int fao_monitor(struct fao_service *service, uint64_t now_ns,
		uint32_t flags, struct fao_compare *out)
{
	struct fao_compare compare;
	int result;

	if (service == NULL || out == NULL || now_ns == 0U ||
	    (flags & (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL)) !=
	    (FAO_FLAG_AUTHORITY_GRANTED | FAO_FLAG_VERIFIED_INPUT | FAO_FLAG_EXPERIMENTAL))
		return FAO_ERR_AUTHORITY;
	pthread_mutex_lock(&service->lock);
	if (service->stage != FAO_STAGE_CANARY)
		result = FAO_ERR_STATE;
	else if (compute_compare(service, &compare) != FAO_OK)
		result = FAO_ERR_STATE;
	else if (compare.canary_count < service->policy.minimum_canary_samples)
		result = FAO_ERR_STATE;
	else {
		result = append_event_locked(service, FAO_EVENT_COMPARE,
					     service->candidate.candidate_id, FAO_OK,
					     now_ns, &compare, sizeof(compare));
		if (result == FAO_OK)
			service->compare = compare;
		if (result == FAO_OK && compare.regression_flags != 0U) {
			struct fap_action fallback;
			result = fap_rollback(service->adaptive, now_ns,
					      FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT,
					      "M244 canary regression automatic rollback", &fallback);
			if (result == FAP_OK)
				result = transition_locked(service, FAO_STAGE_ROLLED_BACK,
							    FAO_ERR_UNSAFE, now_ns,
							    "canary regression automatic rollback");
		} else if (result == FAO_OK) {
			struct fap_action applied;
			result = fap_commit(service->adaptive, service->candidate.recommendation_id,
					    now_ns, FAP_FLAG_AUTHORITY_GRANTED | FAP_FLAG_VERIFIED_INPUT |
					    FAP_FLAG_EXPERIMENTAL, &applied);
			if (result == FAP_OK)
				result = transition_locked(service, FAO_STAGE_ACTIVE, FAO_OK,
							    now_ns, "canary accepted and applied");
		}
		if (result == FAO_OK)
			*out = compare;
	}
	pthread_mutex_unlock(&service->lock);
	return result;
}

int fao_query(const struct fao_service *service, struct fao_attestation *out)
{
	if (service == NULL || out == NULL)
		return FAO_ERR_ARGUMENT;
	pthread_mutex_lock((pthread_mutex_t *)&service->lock);
	memset(out, 0, sizeof(*out));
	out->event_sequence = service->event_sequence;
	out->sample_sequence = service->last_sample_sequence;
	out->forecast_id = service->forecast.forecast_id;
	out->candidate_id = service->candidate.candidate_id;
	out->policy_generation = service->adaptive->policy_generation;
	out->stage = service->stage;
	out->regression_flags = service->compare.regression_flags;
	out->rollback_count = service->rollback_count;
	memcpy(out->chain_digest, service->chain_digest, FAO_DIGEST_SIZE);
	pthread_mutex_unlock((pthread_mutex_t *)&service->lock);
	return FAO_OK;
}
