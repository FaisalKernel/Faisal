#define _GNU_SOURCE
#include "faisal_experience_evidence.h"

#include <openssl/evp.h>
#include <string.h>

static int digest_init(EVP_MD_CTX **ctx)
{
	*ctx = EVP_MD_CTX_new();
	if (!*ctx)
		return FEE_ERR_CORRUPT;
	if (EVP_DigestInit_ex(*ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(*ctx);
		*ctx = NULL;
		return FEE_ERR_CORRUPT;
	}
	return FEE_OK;
}

static int digest_final(EVP_MD_CTX *ctx, uint8_t digest[FEE_DIGEST_SIZE])
{
	unsigned int length = 0;
	int ret = FEE_ERR_CORRUPT;
	if (EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
	    length == FEE_DIGEST_SIZE)
		ret = FEE_OK;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int update_bytes(EVP_MD_CTX *ctx, const void *data, size_t length)
{
	return EVP_DigestUpdate(ctx, data, length) == 1 ? FEE_OK : FEE_ERR_CORRUPT;
}

static int update_u32(EVP_MD_CTX *ctx, uint32_t value)
{
	return update_bytes(ctx, &value, sizeof(value));
}

static int update_u64(EVP_MD_CTX *ctx, uint64_t value)
{
	return update_bytes(ctx, &value, sizeof(value));
}

static int update_text(EVP_MD_CTX *ctx, const char *text, size_t maximum)
{
	size_t length;
	if (!text)
		return FEE_ERR_ARGUMENT;
	length = strnlen(text, maximum);
	if (length == maximum)
		return FEE_ERR_ARGUMENT;
	if (update_u64(ctx, (uint64_t)length) != FEE_OK)
		return FEE_ERR_CORRUPT;
	return update_bytes(ctx, text, length);
}

static int copy_text(char *destination, size_t capacity, const char *source)
{
	size_t length;
	if (!destination || !source)
		return FEE_ERR_ARGUMENT;
	length = strnlen(source, capacity);
	if (length == 0 || length >= capacity)
		return FEE_ERR_ARGUMENT;
	memcpy(destination, source, length);
	destination[length] = '\0';
	return FEE_OK;
}

static int digest_text(const char *text, size_t maximum,
			       uint8_t digest[FEE_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = NULL;
	int ret;
	if (!text || strnlen(text, maximum) == 0 || strnlen(text, maximum) == maximum)
		return FEE_ERR_ARGUMENT;
	ret = digest_init(&ctx);
	if (ret != FEE_OK)
		return ret;
	ret = update_text(ctx, text, maximum);
	if (ret != FEE_OK) {
		EVP_MD_CTX_free(ctx);
		return ret;
	}
	return digest_final(ctx, digest);
}

static int digest_provenance(const struct fee_provenance *provenance,
			     uint8_t digest[FEE_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = NULL;
	int ret;
	if (!provenance || (provenance->present_mask & ~FEE_PROVENANCE_ALL))
		return FEE_ERR_ARGUMENT;
	ret = digest_init(&ctx);
	if (ret != FEE_OK)
		return ret;
	ret = update_u32(ctx, provenance->present_mask);
	ret |= update_u64(ctx, provenance->source_sequence);
	ret |= update_u64(ctx, provenance->provider_generation);
	ret |= update_u64(ctx, provenance->sandbox_generation);
	ret |= update_u64(ctx, provenance->verifier_sequence);
	ret |= update_u64(ctx, provenance->observed_at_ns);
	ret |= update_u64(ctx, provenance->expires_at_ns);
	ret |= update_text(ctx, provenance->source, sizeof(provenance->source));
	ret |= update_text(ctx, provenance->provider, sizeof(provenance->provider));
	ret |= update_text(ctx, provenance->model, sizeof(provenance->model));
	ret |= update_text(ctx, provenance->tool, sizeof(provenance->tool));
	ret |= update_text(ctx, provenance->sandbox, sizeof(provenance->sandbox));
	ret |= update_text(ctx, provenance->verifier, sizeof(provenance->verifier));
	if (ret != FEE_OK) {
		EVP_MD_CTX_free(ctx);
		return FEE_ERR_ARGUMENT;
	}
	return digest_final(ctx, digest);
}

static uint32_t clamp_score(uint64_t score)
{
	return score > FEE_SCORE_MAX ? FEE_SCORE_MAX : (uint32_t)score;
}

static uint32_t compute_importance(const struct fee_input *input)
{
	uint64_t base;
	uint64_t verification_bonus =
		input->verification_status == FEE_VERIFICATION_VERIFIED ? 125000ULL : 0ULL;
	base = (uint64_t)input->confidence_ppm * 2ULL +
	       (uint64_t)input->impact_ppm * 3ULL +
	       (uint64_t)input->novelty_ppm * 2ULL +
	       (uint64_t)input->recurrence_ppm;
	return clamp_score(base / 8ULL + verification_bonus);
}

static int provenance_allowed(const struct fee_service *service,
			      const struct fee_provenance *provenance)
{
	uint32_t mask;
	if (!service || !provenance)
		return 0;
	mask = service->policy.required_provenance_mask;
	return (provenance->present_mask & mask) == mask;
}

static int valid_provenance(const struct fee_provenance *provenance)
{
	if (!provenance || (provenance->present_mask & ~FEE_PROVENANCE_ALL))
		return 0;
	if (provenance->observed_at_ns == 0)
		return 0;
	if (provenance->expires_at_ns &&
	    provenance->expires_at_ns <= provenance->observed_at_ns)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_SOURCE) &&
	    strnlen(provenance->source, sizeof(provenance->source)) == 0)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_PROVIDER) &&
	    strnlen(provenance->provider, sizeof(provenance->provider)) == 0)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_MODEL) &&
	    strnlen(provenance->model, sizeof(provenance->model)) == 0)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_TOOL) &&
	    strnlen(provenance->tool, sizeof(provenance->tool)) == 0)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_SANDBOX) &&
	    strnlen(provenance->sandbox, sizeof(provenance->sandbox)) == 0)
		return 0;
	if ((provenance->present_mask & FEE_PROVENANCE_VERIFIER) &&
	    strnlen(provenance->verifier, sizeof(provenance->verifier)) == 0)
		return 0;
	return 1;
}

static struct fee_record *find_sequence(struct fee_service *service,
					uint64_t sequence)
{
	uint32_t i;
	for (i = 0; i < service->count; i++)
		if (service->records[i].sequence == sequence)
			return &service->records[i];
	return NULL;
}

static const struct fee_record *find_sequence_const(const struct fee_service *service,
						uint64_t sequence)
{
	uint32_t i;
	for (i = 0; i < service->count; i++)
		if (service->records[i].sequence == sequence)
			return &service->records[i];
	return NULL;
}

static int digest_record_binding(const struct fee_record *record,
					uint8_t digest[FEE_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = NULL;
	uint8_t provenance_digest[FEE_DIGEST_SIZE];
	int ret;
	if (!record || digest_provenance(&record->provenance, provenance_digest) != FEE_OK)
		return FEE_ERR_ARGUMENT;
	ret = digest_init(&ctx);
	if (ret != FEE_OK)
		return ret;
	ret = update_u64(ctx, record->sequence);
	ret |= update_u64(ctx, record->request_sequence);
	ret |= update_u64(ctx, record->supersedes_sequence);
	ret |= update_u32(ctx, record->state);
	ret |= update_u32(ctx, record->verification_status);
	ret |= update_u32(ctx, record->confidence_ppm);
	ret |= update_u32(ctx, record->importance_ppm);
	ret |= update_u64(ctx, record->created_at_ns);
	ret |= update_bytes(ctx, provenance_digest, sizeof(provenance_digest));
	ret |= update_bytes(ctx, record->action_digest, FEE_DIGEST_SIZE);
	ret |= update_bytes(ctx, record->observation_digest, FEE_DIGEST_SIZE);
	ret |= update_bytes(ctx, record->result_digest, FEE_DIGEST_SIZE);
	ret |= update_bytes(ctx, record->lesson_digest, FEE_DIGEST_SIZE);
	ret |= update_bytes(ctx, record->skill_digest, FEE_DIGEST_SIZE);
	ret |= update_text(ctx, record->key, sizeof(record->key));
	if (ret != FEE_OK) {
		EVP_MD_CTX_free(ctx);
		return FEE_ERR_CORRUPT;
	}
	return digest_final(ctx, digest);
}

void fee_init(struct fee_service *service, const struct fee_policy *policy)
{
	if (!service)
		return;
	memset(service, 0, sizeof(*service));
	service->next_sequence = 1;
	if (policy)
		service->policy = *policy;
}

int fee_record(struct fee_service *service, const struct fee_input *input,
	       struct fee_record *out)
{
	struct fee_record record;
	struct fee_record *superseded = NULL;
	struct fee_record *existing = NULL;
	uint8_t provenance_digest[FEE_DIGEST_SIZE];
	uint32_t i;

	memset(&record, 0, sizeof(record));
	if (!service || !input || !out || service->count >= FEE_MAX_RECORDS ||
	    input->request_sequence == 0 ||
	    !valid_provenance(&input->provenance) ||
	    input->confidence_ppm > FEE_SCORE_MAX || input->impact_ppm > FEE_SCORE_MAX ||
	    input->novelty_ppm > FEE_SCORE_MAX || input->recurrence_ppm > FEE_SCORE_MAX ||
	    !input->now_ns || input->now_ns < input->provenance.observed_at_ns ||
	    copy_text(record.key, sizeof(record.key), input->key) != FEE_OK ||
	    copy_text(record.action, sizeof(record.action), input->action) != FEE_OK ||
	    copy_text(record.observation, sizeof(record.observation), input->observation) != FEE_OK ||
	    copy_text(record.result, sizeof(record.result), input->result) != FEE_OK ||
	    copy_text(record.lesson, sizeof(record.lesson), input->lesson) != FEE_OK ||
	    copy_text(record.skill, sizeof(record.skill), input->skill) != FEE_OK)
		return FEE_ERR_ARGUMENT;
	if (input->request_sequence <= service->last_request_sequence)
		return FEE_ERR_REPLAY;
	if (input->verification_status > FEE_VERIFICATION_REJECTED)
		return FEE_ERR_ARGUMENT;
	if (input->verification_status == FEE_VERIFICATION_VERIFIED &&
	    (!input->authority_grant || !provenance_allowed(service, &input->provenance)))
		return FEE_ERR_POLICY;
	if (digest_provenance(&input->provenance, provenance_digest) != FEE_OK)
		return FEE_ERR_CORRUPT;

	record.sequence = service->next_sequence++;
	record.request_sequence = input->request_sequence;
	record.supersedes_sequence = input->supersedes_sequence;
	record.created_at_ns = input->now_ns;
	record.verification_status = input->verification_status;
	record.confidence_ppm = input->confidence_ppm;
	record.importance_ppm = compute_importance(input);
	record.provenance = input->provenance;
	memcpy(record.action_digest, (uint8_t[FEE_DIGEST_SIZE]){0}, FEE_DIGEST_SIZE);
	if (digest_text(record.action, sizeof(record.action), record.action_digest) != FEE_OK ||
	    digest_text(record.observation, sizeof(record.observation), record.observation_digest) != FEE_OK ||
	    digest_text(record.result, sizeof(record.result), record.result_digest) != FEE_OK ||
	    digest_text(record.lesson, sizeof(record.lesson), record.lesson_digest) != FEE_OK ||
	    digest_text(record.skill, sizeof(record.skill), record.skill_digest) != FEE_OK)
		return FEE_ERR_CORRUPT;

	for (i = 0; i < service->count; i++) {
		struct fee_record *candidate = &service->records[i];
		if (strcmp(candidate->key, record.key) != 0)
			continue;
		if (input->supersedes_sequence == candidate->sequence) {
			if (candidate->state != FEE_STATE_REUSABLE &&
			    candidate->state != FEE_STATE_CONFLICT)
				return FEE_ERR_POLICY;
			superseded = candidate;
			continue;
		}
		if (candidate->state == FEE_STATE_REUSABLE ||
		    candidate->state == FEE_STATE_RECORDED) {
			if (memcmp(candidate->result_digest, record.result_digest,
				   FEE_DIGEST_SIZE) != 0)
				existing = candidate;
			else
				return FEE_ERR_REPLAY;
		}
	}
	if (input->supersedes_sequence && !superseded)
		return FEE_ERR_NOT_FOUND;
	if (existing) {
		existing->state = FEE_STATE_CONFLICT;
		record.state = FEE_STATE_CONFLICT;
	} else if (input->verification_status == FEE_VERIFICATION_VERIFIED &&
		   input->authority_grant && provenance_allowed(service, &input->provenance)) {
		record.state = FEE_STATE_REUSABLE;
	} else if (input->verification_status == FEE_VERIFICATION_REJECTED) {
		record.state = FEE_STATE_REJECTED;
	} else {
		record.state = FEE_STATE_RECORDED;
	}
	if (superseded)
		superseded->state = FEE_STATE_SUPERSEDED;
	if (digest_record_binding(&record, record.binding_digest) != FEE_OK)
		return FEE_ERR_CORRUPT;
	service->records[service->count++] = record;
	service->last_request_sequence = input->request_sequence;
	*out = record;
	return existing ? FEE_ERR_CONFLICT : FEE_OK;
}

int fee_verify(const struct fee_service *service, const struct fee_record *record)
{
	struct fee_record canonical;
	uint8_t digest[FEE_DIGEST_SIZE];
	(void)service;
	if (!record || !record->sequence || !record->request_sequence ||
	    !valid_provenance(&record->provenance))
		return FEE_ERR_CORRUPT;
	canonical = *record;
	if (digest_text(canonical.action, sizeof(canonical.action), canonical.action_digest) != FEE_OK ||
	    digest_text(canonical.observation, sizeof(canonical.observation), canonical.observation_digest) != FEE_OK ||
	    digest_text(canonical.result, sizeof(canonical.result), canonical.result_digest) != FEE_OK ||
	    digest_text(canonical.lesson, sizeof(canonical.lesson), canonical.lesson_digest) != FEE_OK ||
	    digest_text(canonical.skill, sizeof(canonical.skill), canonical.skill_digest) != FEE_OK ||
	    digest_record_binding(&canonical, digest) != FEE_OK)
		return FEE_ERR_CORRUPT;
	return memcmp(digest, record->binding_digest, FEE_DIGEST_SIZE) == 0 ?
		FEE_OK : FEE_ERR_CORRUPT;
}

int fee_retrieve(const struct fee_service *service, const char *key,
		 uint64_t now_ns, struct fee_record *out)
{
	const struct fee_record *best = NULL;
	uint64_t best_score = 0;
	uint32_t i;
	if (!service || !key || !out || !*key || !now_ns)
		return FEE_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++) {
		const struct fee_record *record = &service->records[i];
		uint64_t score;
		if (strcmp(record->key, key) != 0 || record->state != FEE_STATE_REUSABLE)
			continue;
		if (record->provenance.expires_at_ns &&
		    now_ns >= record->provenance.expires_at_ns)
			continue;
		if (record->confidence_ppm < service->policy.minimum_confidence_ppm ||
		    record->importance_ppm < service->policy.minimum_importance_ppm ||
		    !provenance_allowed(service, &record->provenance))
			continue;
		if (fee_verify(service, record) != FEE_OK)
			return FEE_ERR_CORRUPT;
		score = (uint64_t)record->importance_ppm * 2ULL + record->confidence_ppm;
		if (!best || score > best_score ||
		    (score == best_score && record->sequence > best->sequence)) {
			best = record;
			best_score = score;
		}
	}
	if (!best)
		return FEE_ERR_NOT_FOUND;
	*out = *best;
	return FEE_OK;
}

int fee_reuse(struct fee_service *service, uint64_t sequence, uint64_t now_ns,
	      struct fee_record *out)
{
	struct fee_record *record;
	if (!service || !sequence || !now_ns || !out)
		return FEE_ERR_ARGUMENT;
	record = find_sequence(service, sequence);
	if (!record)
		return FEE_ERR_NOT_FOUND;
	if (fee_verify(service, record) != FEE_OK)
		return FEE_ERR_CORRUPT;
	if (record->state != FEE_STATE_REUSABLE)
		return FEE_ERR_POLICY;
	if (record->provenance.expires_at_ns && now_ns >= record->provenance.expires_at_ns) {
		record->state = FEE_STATE_EXPIRED;
		return FEE_ERR_EXPIRED;
	}
	if (record->reuse_count >= FEE_MAX_REUSE)
		return FEE_ERR_POLICY;
	record->reuse_count++;
	record->last_reused_at_ns = now_ns;
	*out = *record;
	return FEE_OK;
}

int fee_correct(struct fee_service *service, uint64_t sequence,
		const struct fee_input *correction, struct fee_record *out)
{
	struct fee_input input;
	if (!service || !correction || !sequence || !out ||
	    !find_sequence_const(service, sequence))
		return FEE_ERR_NOT_FOUND;
	input = *correction;
	input.supersedes_sequence = sequence;
	return fee_record(service, &input, out);
}

int fee_expire(struct fee_service *service, uint64_t now_ns,
	       uint32_t *expired_count)
{
	uint32_t i;
	uint32_t count = 0;
	if (!service || !now_ns || !expired_count)
		return FEE_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++) {
		struct fee_record *record = &service->records[i];
		if ((record->state == FEE_STATE_REUSABLE ||
		     record->state == FEE_STATE_RECORDED) &&
		    record->provenance.expires_at_ns &&
		    now_ns >= record->provenance.expires_at_ns) {
			record->state = FEE_STATE_EXPIRED;
			count++;
		}
	}
	*expired_count = count;
	return FEE_OK;
}

int fee_stats_get(const struct fee_service *service, uint64_t now_ns,
		 struct fee_stats *out)
{
	uint32_t i;
	if (!service || !out || !now_ns)
		return FEE_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	for (i = 0; i < service->count; i++) {
		const struct fee_record *record = &service->records[i];
		if (record->provenance.expires_at_ns &&
		    now_ns >= record->provenance.expires_at_ns &&
		    (record->state == FEE_STATE_REUSABLE ||
		     record->state == FEE_STATE_RECORDED))
			out->expired++;
		switch (record->state) {
		case FEE_STATE_RECORDED: out->recorded++; break;
		case FEE_STATE_REUSABLE: out->reusable++; break;
		case FEE_STATE_SUPERSEDED: out->superseded++; break;
		case FEE_STATE_CONFLICT: out->conflicts++; break;
		case FEE_STATE_EXPIRED: out->expired++; break;
		case FEE_STATE_REJECTED: out->rejected++; break;
		default: return FEE_ERR_CORRUPT;
		}
		if (record->verification_status == FEE_VERIFICATION_VERIFIED)
			out->verified++;
		if ((record->provenance.present_mask & service->policy.required_provenance_mask) ==
		    service->policy.required_provenance_mask)
			out->provenance_complete++;
	}
	return FEE_OK;
}
