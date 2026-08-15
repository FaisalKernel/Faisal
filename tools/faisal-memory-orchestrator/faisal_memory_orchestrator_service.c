#define _GNU_SOURCE
#include "faisal_memory_orchestrator_service.h"
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct fmo_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t reserved;
	struct fmo_record record;
};

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int write_all(int fd, const void *data, size_t len)
{
	const unsigned char *p = data;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return FMO_ERR_IO;
		p += n;
		len -= (size_t)n;
	}
	return FMO_OK;
}

static void copy_string(char *dst, size_t size, const char *src)
{
	size_t len;
	if (!dst || !size)
		return;
	if (!src)
		src = "";
	len = strlen(src);
	if (len >= size)
		len = size - 1;
	memcpy(dst, src, len);
	dst[len] = 0;
}

static int path_for(char *out, size_t size, const char *prefix, const char *suffix)
{
	int n;
	if (!out || !size || !prefix || !*prefix || !suffix)
		return FMO_ERR_ARGUMENT;
	n = snprintf(out, size, "%s-%s", prefix, suffix);
	return n < 0 || (size_t)n >= size ? FMO_ERR_ARGUMENT : FMO_OK;
}

static uint32_t tier_for_class(uint32_t memory_class)
{
	switch (memory_class) {
	case FMO_CLASS_WORKING:
		return AGI_LC_MEMORY_TIER_WORKING;
	case FMO_CLASS_EPISODIC:
	case FMO_CLASS_EXPERIENCE:
		return AGI_LC_MEMORY_TIER_EPISODIC;
	case FMO_CLASS_SEMANTIC:
		return AGI_LC_MEMORY_TIER_SEMANTIC;
	case FMO_CLASS_PROCEDURAL:
		return AGI_LC_MEMORY_TIER_PROCEDURAL;
	case FMO_CLASS_WORLD:
		return AGI_LC_MEMORY_TIER_WORLD_MODEL;
	case FMO_CLASS_SIMULATION:
	case FMO_CLASS_SELF:
		return AGI_LC_MEMORY_TIER_LONG_TERM;
	default:
		return 0;
	}
}

static int valid_truth(uint32_t truth)
{
	return truth >= FMO_TRUTH_REAL_WORLD_FACT &&
	       truth <= FMO_TRUTH_UNCERTAINTY;
}

static int valid_input(const struct fmo_ingest *input)
{
	if (!input || !tier_for_class(input->memory_class) ||
	    !valid_truth(input->truth_class) || !*input->scope ||
	    !*input->topic || !*input->content ||
	    strlen(input->scope) >= FMO_MAX_SCOPE ||
	    strlen(input->topic) >= FMO_MAX_TOPIC ||
	    strlen(input->source) >= FMO_MAX_SOURCE ||
	    strlen(input->content) >= FMO_MAX_CONTENT ||
	    strlen(input->skill) >= FMO_MAX_SKILL ||
	    strlen(input->causal) >= FMO_MAX_CAUSAL ||
	    input->confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    input->importance_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX)
		return 0;
	return 1;
}

static int provenance_complete(const struct fmo_provenance *p)
{
	return p && p->source_id && p->experience_sequence && p->agent_id &&
	       p->task_id && p->event_sequence && p->verification_sequence;
}

static struct fmo_record *find_record(struct fmo_service *service, uint64_t id)
{
	uint32_t i;
	for (i = 0; i < service->record_count; i++)
		if (service->records[i].id == id)
			return &service->records[i];
	return NULL;
}

static const struct fmo_record *find_const(const struct fmo_service *service,
					   uint64_t id)
{
	uint32_t i;
	for (i = 0; i < service->record_count; i++)
		if (service->records[i].id == id)
			return &service->records[i];
	return NULL;
}

static int append_index(struct fmo_service *service, const struct fmo_record *record)
{
	struct fmo_disk_header header;
	if (!service || service->index_fd < 0 || !record)
		return FMO_ERR_ARGUMENT;
	memset(&header, 0, sizeof(header));
	header.magic = FMO_JOURNAL_MAGIC;
	header.version = FMO_JOURNAL_VERSION;
	header.size = sizeof(header);
	header.record = *record;
	if (lseek(service->index_fd, 0, SEEK_END) < 0 ||
	    write_all(service->index_fd, &header, sizeof(header)) != FMO_OK ||
	    fdatasync(service->index_fd) < 0)
		return FMO_ERR_IO;
	return FMO_OK;
}

static int replay_index(struct fmo_service *service)
{
	struct fmo_disk_header header;
	off_t valid_end = 0;
	for (;;) {
		ssize_t n = read(service->index_fd, &header, sizeof(header));
		if (!n)
			break;
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0)
			return FMO_ERR_IO;
		if ((size_t)n < sizeof(header)) {
			if (ftruncate(service->index_fd, valid_end) < 0)
				return FMO_ERR_IO;
			break;
		}
		if (header.magic != FMO_JOURNAL_MAGIC ||
		    header.version != FMO_JOURNAL_VERSION ||
		    header.size != sizeof(header) || !header.record.id ||
		    !header.record.memory_record_id ||
		    header.record.memory_class > FMO_CLASS_MAX ||
		    !valid_truth(header.record.truth_class))
			return FMO_ERR_CORRUPT;
		{
			struct fmo_record *old = find_record(service, header.record.id);
			if (old)
				*old = header.record;
			else {
				if (service->record_count >= FMO_MAX_RECORDS)
					return FMO_ERR_FULL;
				service->records[service->record_count++] = header.record;
			}
		}
		if (header.record.id >= service->next_id)
			service->next_id = header.record.id + 1;
		valid_end += (off_t)sizeof(header);
	}
	return lseek(service->index_fd, 0, SEEK_END) < 0 ? FMO_ERR_IO : FMO_OK;
}

int fmo_open(struct fmo_service *service, const char *journal_prefix)
{
	char path[4096];
	int ret;
	if (!service || !journal_prefix || !*journal_prefix ||
	    strlen(journal_prefix) >= sizeof(service->index_path) - 16)
		return FMO_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->index_fd = -1;
	service->memory.kernel_fd = -1;
	service->memory.journal_fd = -1;
	service->experience.memory.kernel_fd = -1;
	service->experience.memory.journal_fd = -1;
	service->world.memory.kernel_fd = -1;
	service->world.memory.journal_fd = -1;
	service->next_id = 1;
	copy_string(service->journal_prefix, sizeof(service->journal_prefix), journal_prefix);
	if (path_for(path, sizeof(path), journal_prefix, "memory") != FMO_OK ||
	    fms_open(&service->memory, path) != FMS_OK)
		goto fail;
	if (path_for(service->index_path, sizeof(service->index_path), journal_prefix,
		    "orchestrator") != FMO_OK)
		goto fail;
	service->index_fd = open(service->index_path,
				O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (service->index_fd < 0)
		goto fail;
	ret = replay_index(service);
	if (ret != FMO_OK)
		goto fail;
	return FMO_OK;
fail:
	fmo_close(service);
	return FMO_ERR_IO;
}

void fmo_close(struct fmo_service *service)
{
	if (!service)
		return;
	if (service->index_fd >= 0)
		close(service->index_fd);
	service->index_fd = -1;
	fws_close(&service->world);
	fes_close(&service->experience);
	fms_close(&service->memory);
}

static int same_identity(const struct fmo_record *record,
				 const struct fmo_ingest *input)
{
	return record->state != FMO_STATE_DELETED &&
	       record->memory_class == input->memory_class &&
	       !strcmp(record->scope, input->scope) &&
	       !strcmp(record->topic, input->topic);
}

static void populate_record(struct fmo_record *record,
				     const struct fmo_ingest *input,
				     uint64_t id, uint64_t memory_record_id,
				     uint64_t memory_capability, uint64_t sequence)
{
	memset(record, 0, sizeof(*record));
	record->id = id;
	record->memory_sequence = sequence;
	record->memory_record_id = memory_record_id;
	record->memory_capability = memory_capability;
	record->created_at_ns = now_ns();
	record->observed_at_ns = input->observed_at_ns ? input->observed_at_ns : record->created_at_ns;
	record->freshness_deadline_ns = input->freshness_ttl_ns &&
		record->observed_at_ns <= UINT64_MAX - input->freshness_ttl_ns ?
		record->observed_at_ns + input->freshness_ttl_ns : 0;
	record->memory_class = input->memory_class;
	record->truth_class = input->truth_class;
	record->state = FMO_STATE_ACTIVE;
	record->confidence_ppm = input->confidence_ppm;
	record->importance_ppm = input->importance_ppm;
	record->provenance = input->provenance;
	copy_string(record->scope, sizeof(record->scope), input->scope);
	copy_string(record->topic, sizeof(record->topic), input->topic);
	copy_string(record->source, sizeof(record->source), input->source);
	copy_string(record->content, sizeof(record->content), input->content);
	copy_string(record->skill, sizeof(record->skill), input->skill);
	copy_string(record->causal, sizeof(record->causal), input->causal);
}

int fmo_ingest(struct fmo_service *service, const struct fmo_ingest *input,
	       struct fmo_record *out, uint32_t *result)
{
	struct fms_entry memory;
	struct fmo_record *same = NULL;
	struct fmo_record *related = NULL;
	struct fmo_record record;
	uint32_t i;
	int ret;
	if (!service || !valid_input(input) || !out || !result ||
	    service->record_count >= FMO_MAX_RECORDS)
		return !service || !out || !result ? FMO_ERR_ARGUMENT : FMO_ERR_FULL;
	for (i = 0; i < service->record_count; i++) {
		struct fmo_record *candidate = &service->records[i];
		if (!same_identity(candidate, input))
			continue;
		if (!strcmp(candidate->content, input->content) &&
		    candidate->truth_class == input->truth_class) {
			same = candidate;
			break;
		}
		if (!related || candidate->observed_at_ns > related->observed_at_ns)
			related = candidate;
	}
	if (same) {
		same->importance_ppm = input->importance_ppm;
		same->confidence_ppm = input->confidence_ppm;
		if (input->freshness_ttl_ns)
			same->freshness_deadline_ns = input->observed_at_ns + input->freshness_ttl_ns;
		if (append_index(service, same) != FMO_OK)
			return FMO_ERR_IO;
		*out = *same;
		*result = FMO_INGEST_DEDUPLICATED;
		return FMO_OK;
	}
	ret = fms_put(&service->memory, input->content, tier_for_class(input->memory_class),
			  input->confidence_ppm, input->importance_ppm,
			  input->provenance.event_sequence, &memory);
	if (ret != FMS_OK)
		return FMO_ERR_KERNEL;
	if (related && related->observed_at_ns <= input->observed_at_ns) {
		related->state = FMO_STATE_SUPERSEDED;
		related->superseded_by_id = service->next_id;
		if (append_index(service, related) != FMO_OK)
			return FMO_ERR_IO;
	}
	populate_record(&record, input, service->next_id++, memory.record_id,
			memory.authority_capability, memory.sequence);
	if (related && related->observed_at_ns > input->observed_at_ns) {
		record.state = FMO_STATE_CONFLICT;
		record.conflict_with_id = related->id;
		*result = FMO_INGEST_CONFLICT;
	} else if (related) {
		record.supersedes_id = related->id;
		*result = FMO_INGEST_SUPERSEDES;
	} else {
		*result = FMO_INGEST_NEW;
	}
	service->records[service->record_count++] = record;
	if (append_index(service, &record) != FMO_OK)
		return FMO_ERR_IO;
	*out = record;
	return FMO_OK;
}

static void append_text(char *out, size_t size, size_t *offset,
			const char *text)
{
	size_t len;
	if (!out || !offset || *offset >= size || !text)
		return;
	len = strlen(text);
	if (len > size - *offset - 1)
		len = size - *offset - 1;
	memcpy(out + *offset, text, len);
	*offset += len;
	out[*offset] = 0;
}

static void make_experience_content(char *out, size_t size,
				    const struct fmo_experience_input *input)
{
	size_t offset = 0;
	if (!out || !size || !input)
		return;
	out[0] = 0;
	append_text(out, size, &offset, "action=");
	append_text(out, size, &offset, input->action);
	append_text(out, size, &offset, " observation=");
	append_text(out, size, &offset, input->observation);
	append_text(out, size, &offset, " result=");
	append_text(out, size, &offset, input->result);
	append_text(out, size, &offset, " lesson=");
	append_text(out, size, &offset, input->lesson);
}

int fmo_consolidate(struct fmo_service *service,
		   const struct fmo_experience_input *input,
		   uint32_t *records_created)
{
	struct fmo_ingest ingest;
	struct fmo_record record;
	struct fes_service fes;
	struct fws_service fws;
	struct fes_item experience_item;
	struct fws_fact fact;
	uint32_t result;
	uint32_t created = 0;
	char content[FMO_MAX_CONTENT];
	char value[FWS_MAX_VALUE];
	char path[4096];
	int ret;
	if (!service || !input || !records_created || !*input->scope ||
	    !*input->topic || !*input->action || !*input->observation ||
	    !*input->result || !*input->lesson || !*input->skill)
		return FMO_ERR_ARGUMENT;
	memset(&ingest, 0, sizeof(ingest));
	make_experience_content(content, sizeof(content), input);
	ingest.memory_class = FMO_CLASS_EXPERIENCE;
	ingest.truth_class = input->verification_sequence ?
		FMO_TRUTH_REAL_WORLD_FACT : FMO_TRUTH_UNCERTAINTY;
	ingest.confidence_ppm = input->confidence_ppm;
	ingest.importance_ppm = input->importance_ppm;
	ingest.observed_at_ns = input->observed_at_ns;
	ingest.freshness_ttl_ns = input->freshness_ttl_ns;
	ingest.provenance.source_id = input->agent_id ^ input->task_id;
	ingest.provenance.experience_sequence = input->event_sequence;
	ingest.provenance.agent_id = input->agent_id;
	ingest.provenance.task_id = input->task_id;
	ingest.provenance.event_sequence = input->event_sequence;
	ingest.provenance.verification_sequence = input->verification_sequence;
	copy_string(ingest.scope, sizeof(ingest.scope), input->scope);
	copy_string(ingest.topic, sizeof(ingest.topic), input->topic);
	copy_string(ingest.source, sizeof(ingest.source), input->source);
	copy_string(ingest.content, sizeof(ingest.content), content);
	copy_string(ingest.skill, sizeof(ingest.skill), input->skill);
	copy_string(ingest.causal, sizeof(ingest.causal), input->causal);
	ret = fmo_ingest(service, &ingest, &record, &result);
	if (ret != FMO_OK)
		return ret;
	created++;
	if (path_for(path, sizeof(path), service->journal_prefix, "experience") != FMO_OK)
		return FMO_ERR_ARGUMENT;
	memset(&fes, 0, sizeof(fes));
	fes.memory.kernel_fd = -1;
	fes.memory.journal_fd = -1;
	ret = fes_open(&fes, path);
	if (ret != 0)
		return FMO_ERR_KERNEL;
	ret = fes_record_and_evaluate(&fes, input->topic, input->lesson,
				      input->skill,
				      input->verification_sequence != 0,
				      &experience_item);
	fes_close(&fes);
	if (ret != 0)
		return FMO_ERR_KERNEL;
	if (ioctl(service->memory.kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		return FMO_ERR_KERNEL;
	memset(&ingest, 0, sizeof(ingest));
	ingest.memory_class = FMO_CLASS_PROCEDURAL;
	ingest.truth_class = FMO_TRUTH_UNCERTAINTY;
	ingest.confidence_ppm = input->confidence_ppm;
	ingest.importance_ppm = input->importance_ppm;
	ingest.observed_at_ns = input->observed_at_ns;
	ingest.freshness_ttl_ns = input->freshness_ttl_ns;
	ingest.provenance.source_id = record.id;
	ingest.provenance.experience_sequence = experience_item.experience_sequence;
	ingest.provenance.agent_id = input->agent_id;
	ingest.provenance.task_id = input->task_id;
	ingest.provenance.event_sequence = input->event_sequence;
	ingest.provenance.verification_sequence = input->verification_sequence;
	copy_string(ingest.scope, sizeof(ingest.scope), input->scope);
	snprintf(ingest.topic, sizeof(ingest.topic), "%s/skill", input->topic);
	copy_string(ingest.source, sizeof(ingest.source), input->source);
	copy_string(ingest.content, sizeof(ingest.content), input->skill);
	copy_string(ingest.skill, sizeof(ingest.skill), input->skill);
	copy_string(ingest.causal, sizeof(ingest.causal), input->causal);
	ret = fmo_ingest(service, &ingest, &record, &result);
	if (ret != FMO_OK)
		return ret;
	created++;
	if (ioctl(service->memory.kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		return FMO_ERR_KERNEL;
	if (path_for(path, sizeof(path), service->journal_prefix, "world") != FMO_OK)
		return FMO_ERR_ARGUMENT;
	memset(&fws, 0, sizeof(fws));
	fws.memory.kernel_fd = -1;
	fws.memory.journal_fd = -1;
	ret = fws_open(&fws, path);
	if (ret != 0)
		return FMO_ERR_KERNEL;
	memset(value, 0, sizeof(value));
	copy_string(value, sizeof(value), input->result);
	ret = fws_add_fact(&fws, "experience", input->topic, value,
			   input->event_sequence, input->freshness_ttl_ns,
			   input->confidence_ppm, &fact);
	fws_close(&fws);
	if (ret != 0)
		return FMO_ERR_KERNEL;
	if (ioctl(service->memory.kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		return FMO_ERR_KERNEL;
	*records_created = created;
	return FMO_OK;
}

static int contains_token(const char *text, const char *token, size_t len)
{
	const char *p;
	if (!len)
		return 1;
	for (p = text; *p; p++) {
		size_t i;
		if (tolower((unsigned char)*p) != tolower((unsigned char)token[0]))
			continue;
		for (i = 0; i < len && p[i] &&
			     tolower((unsigned char)p[i]) == tolower((unsigned char)token[i]); i++)
			;
		if (i == len)
			return 1;
	}
	return 0;
}

static uint32_t lexical_score(const struct fmo_record *record, const char *query)
{
	char token[FMO_MAX_CONTENT];
	const char *p = query;
	uint32_t score = 0;
	while (*p) {
		size_t len = 0;
		while (*p && !isalnum((unsigned char)*p))
			p++;
		while (p[len] && isalnum((unsigned char)p[len]) &&
		       len + 1 < sizeof(token)) {
			token[len] = p[len];
			len++;
		}
		if (len) {
			token[len] = 0;
			if (contains_token(record->content, token, len) ||
			    contains_token(record->topic, token, len) ||
			    contains_token(record->source, token, len) ||
			    contains_token(record->skill, token, len) ||
			    contains_token(record->causal, token, len))
				score += 100;
			p += len;
		} else if (*p) {
			p++;
		}
	}
	return score;
}

static int class_allowed(uint32_t mask, uint32_t class)
{
	return !mask || (mask & (1U << (class - 1U)));
}

static int truth_allowed(uint32_t mask, uint32_t truth)
{
	return !mask || (mask & (1U << (truth - 1U)));
}

static int is_stale(const struct fmo_record *record, uint64_t now)
{
	return record->freshness_deadline_ns && now >= record->freshness_deadline_ns;
}

static uint32_t result_score(const struct fmo_record *record,
				     const struct fmo_query *query, uint64_t now)
{
	uint32_t score = lexical_score(record, query->query);
	if (!*query->query)
		score += 10;
	if (*query->scope && !strcmp(query->scope, record->scope))
		score += 300;
	if (query->task_id && query->task_id == record->provenance.task_id)
		score += 250;
	if (record->confidence_ppm >= query->minimum_confidence_ppm)
		score += record->confidence_ppm / 10000U;
	if (record->importance_ppm >= query->minimum_importance_ppm)
		score += record->importance_ppm / 10000U;
	if (!is_stale(record, now))
		score += 80;
	if (provenance_complete(&record->provenance))
		score += 100;
	return score;
}

static void copy_result(struct fmo_result *out, const struct fmo_record *record,
			uint32_t score)
{
	memset(out, 0, sizeof(*out));
	out->record_id = record->id;
	out->score = score;
	out->state = record->state;
	out->memory_class = record->memory_class;
	out->truth_class = record->truth_class;
	out->confidence_ppm = record->confidence_ppm;
	out->importance_ppm = record->importance_ppm;
	out->observed_at_ns = record->observed_at_ns;
	out->freshness_deadline_ns = record->freshness_deadline_ns;
	copy_string(out->topic, sizeof(out->topic), record->topic);
	copy_string(out->source, sizeof(out->source), record->source);
	copy_string(out->content, sizeof(out->content), record->content);
}

int fmo_retrieve(struct fmo_service *service, const struct fmo_query *query,
		struct fmo_result *results, uint32_t *count)
{
	uint32_t i, found = 0;
	uint64_t current;
	if (!service || !query || !results || !count || query->top_k > FMO_MAX_RESULTS)
		return FMO_ERR_ARGUMENT;
	current = now_ns();
	for (i = 0; i < service->record_count; i++) {
		struct fmo_record *record = &service->records[i];
		uint32_t score;
		if (record->state == FMO_STATE_DELETED ||
		    (!query->include_stale && is_stale(record, current)) ||
		    (!query->include_simulation && record->truth_class == FMO_TRUTH_SIMULATION_RESULT) ||
		    !class_allowed(query->class_mask, record->memory_class) ||
		    !truth_allowed(query->truth_mask, record->truth_class) ||
		    (*query->scope && strcmp(query->scope, record->scope)) ||
		    record->confidence_ppm < query->minimum_confidence_ppm ||
		    record->importance_ppm < query->minimum_importance_ppm ||
		    (query->task_id && query->task_id != record->provenance.task_id) ||
		    (query->observed_after_ns && record->observed_at_ns < query->observed_after_ns) ||
		    (query->observed_before_ns && record->observed_at_ns > query->observed_before_ns) ||
		    (query->require_provenance && !provenance_complete(&record->provenance)) ||
		    (!*query->query ? 0 : !lexical_score(record, query->query)))
			continue;
		score = result_score(record, query, current);
		if (found < FMO_MAX_RESULTS) {
			uint32_t pos = found++;
			copy_result(&results[pos], record, score);
			while (pos && results[pos - 1].score < results[pos].score) {
				struct fmo_result tmp = results[pos - 1];
				results[pos - 1] = results[pos];
				results[pos] = tmp;
				pos--;
			}
		} else if (score > results[FMO_MAX_RESULTS - 1].score) {
			copy_result(&results[FMO_MAX_RESULTS - 1], record, score);
			for (uint32_t pos = FMO_MAX_RESULTS - 1; pos &&
			     results[pos - 1].score < results[pos].score; pos--) {
				struct fmo_result tmp = results[pos - 1];
				results[pos - 1] = results[pos];
				results[pos] = tmp;
			}
		}
	}
	if (query->top_k && found > query->top_k)
		found = query->top_k;
	*count = found;
	return FMO_OK;
}

int fmo_build_context(struct fmo_service *service, const struct fmo_query *query,
			struct fmo_context *out)
{
	uint32_t i, count, offset = 0;
	int ret;
	if (!service || !query || !out)
		return FMO_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	ret = fmo_retrieve(service, query, out->results, &count);
	if (ret != FMO_OK)
		return ret;
	out->count = count;
	for (i = 0; i < count; i++) {
		int n = snprintf(out->text + offset, sizeof(out->text) - offset,
				 "[%u id=%llu class=%u truth=%u score=%u] %s\n",
				i, (unsigned long long)out->results[i].record_id,
				out->results[i].memory_class, out->results[i].truth_class,
				out->results[i].score, out->results[i].content);
		if (n < 0 || (size_t)n >= sizeof(out->text) - offset) {
			out->truncated = 1;
			break;
		}
		offset += (uint32_t)n;
		out->total_score += out->results[i].score;
	}
	return FMO_OK;
}

int fmo_mark_stale(struct fmo_service *service, uint64_t current,
			uint32_t *expired_count)
{
	uint32_t i, count = 0;
	if (!service || !expired_count)
		return FMO_ERR_ARGUMENT;
	for (i = 0; i < service->record_count; i++) {
		struct fmo_record *record = &service->records[i];
		if (record->state == FMO_STATE_ACTIVE && is_stale(record, current)) {
			record->state = FMO_STATE_EXPIRED;
			if (append_index(service, record) != FMO_OK)
				return FMO_ERR_IO;
			count++;
		}
	}
	*expired_count = count;
	return FMO_OK;
}

int fmo_get(const struct fmo_service *service, uint64_t record_id,
		   struct fmo_record *out)
{
	const struct fmo_record *record;
	if (!service || !record_id || !out)
		return FMO_ERR_ARGUMENT;
	record = find_const(service, record_id);
	if (!record)
		return FMO_ERR_NOT_FOUND;
	*out = *record;
	return FMO_OK;
}

int fmo_stats(const struct fmo_service *service, uint64_t current,
		     struct fmo_stats *out)
{
	uint32_t i;
	if (!service || !out)
		return FMO_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->total_records = service->record_count;
	for (i = 0; i < service->record_count; i++) {
		const struct fmo_record *record = &service->records[i];
		if (record->state == FMO_STATE_ACTIVE)
			out->active_records++;
		if (record->state == FMO_STATE_EXPIRED)
			out->expired_records++;
		if (record->state == FMO_STATE_CONFLICT)
			out->conflict_records++;
		if (record->state == FMO_STATE_SUPERSEDED)
			out->superseded_records++;
		if (is_stale(record, current) && record->state == FMO_STATE_ACTIVE)
			out->stale_records++;
		if (record->truth_class == FMO_TRUTH_SIMULATION_RESULT)
			out->simulation_records++;
		if (provenance_complete(&record->provenance))
			out->provenance_complete_records++;
	}
	return FMO_OK;
}

int fmo_test_simulation_boundary(struct fmo_service *service,
				 const char *scope, uint64_t *record_id)
{
	struct fmo_ingest input;
	struct fmo_record record;
	uint32_t result;
	if (!service || !scope || !*scope || !record_id)
		return FMO_ERR_ARGUMENT;
	memset(&input, 0, sizeof(input));
	input.memory_class = FMO_CLASS_SIMULATION;
	input.truth_class = FMO_TRUTH_SIMULATION_RESULT;
	input.confidence_ppm = 600000;
	input.importance_ppm = 500000;
	input.observed_at_ns = now_ns();
	input.provenance.source_id = 82001;
	input.provenance.experience_sequence = 82002;
	input.provenance.agent_id = 82003;
	input.provenance.task_id = 82004;
	input.provenance.event_sequence = 82005;
	input.provenance.verification_sequence = 0;
	copy_string(input.scope, sizeof(input.scope), scope);
	copy_string(input.topic, sizeof(input.topic), "simulation/scenario-1");
	copy_string(input.source, sizeof(input.source), "simulation://faisal-m82-fixture");
	copy_string(input.content, sizeof(input.content), "simulated outcome: bounded population favored branch B");
	if (fmo_ingest(service, &input, &record, &result) != FMO_OK)
		return FMO_ERR_IO;
	*record_id = record.id;
	return FMO_OK;
}

int fmo_test_contradiction_lifecycle(struct fmo_service *service,
				     const char *scope, uint64_t observed_at,
				     uint64_t *new_record_id)
{
	struct fmo_ingest input;
	struct fmo_record old_record, new_record;
	uint32_t result;
	if (!service || !scope || !*scope || !new_record_id)
		return FMO_ERR_ARGUMENT;
	memset(&input, 0, sizeof(input));
	input.memory_class = FMO_CLASS_SEMANTIC;
	input.truth_class = FMO_TRUTH_REAL_WORLD_FACT;
	input.confidence_ppm = 800000;
	input.importance_ppm = 700000;
	input.observed_at_ns = observed_at;
	input.freshness_ttl_ns = 1000000000ULL;
	input.provenance.source_id = 83001;
	input.provenance.experience_sequence = 83002;
	input.provenance.agent_id = 83003;
	input.provenance.task_id = 83004;
	input.provenance.event_sequence = 83005;
	input.provenance.verification_sequence = 83006;
	copy_string(input.scope, sizeof(input.scope), scope);
	copy_string(input.topic, sizeof(input.topic), "world/deployment-target");
	copy_string(input.source, sizeof(input.source), "https://example.test/verified");
	copy_string(input.content, sizeof(input.content), "deployment target=staging");
	if (fmo_ingest(service, &input, &old_record, &result) != FMO_OK)
		return FMO_ERR_IO;
	input.observed_at_ns = observed_at + 1;
	copy_string(input.content, sizeof(input.content), "deployment target=production");
	if (fmo_ingest(service, &input, &new_record, &result) != FMO_OK ||
	    result != FMO_INGEST_SUPERSEDES ||
	    new_record.supersedes_id != old_record.id)
		return FMO_ERR_POLICY;
	*new_record_id = new_record.id;
	return FMO_OK;
}
