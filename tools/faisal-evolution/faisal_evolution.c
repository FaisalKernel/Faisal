#include "faisal_evolution.h"

#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct fev_disk_record {
	uint32_t magic;
	uint32_t version;
	uint64_t sequence;
	uint32_t event;
	uint32_t reserved;
	uint8_t previous_digest[FEV_DIGEST_SIZE];
	struct fev_candidate candidate;
	uint8_t record_digest[FEV_DIGEST_SIZE];
};

enum fev_event {
	FEV_EVENT_PROPOSE = 1,
	FEV_EVENT_ISOLATE = 2,
	FEV_EVENT_VALIDATE = 3,
	FEV_EVENT_PROMOTE = 4,
	FEV_EVENT_ROLLBACK = 5
};

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FEV_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if ((!data && length) || !digest)
		return FEV_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FEV_ERR_TAMPER;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    (length && EVP_DigestUpdate(ctx, data, length) != 1) ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FEV_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FEV_ERR_TAMPER;
	}
	EVP_MD_CTX_free(ctx);
	return FEV_OK;
}

static int all_zero(const uint8_t *value, size_t length)
{
	uint8_t result = 0;
	size_t i;

	if (!value)
		return 1;
	for (i = 0; i < length; i++)
		result |= value[i];
	return result == 0;
}

static int copy_text(char *destination, size_t size, const char *source)
{
	int length;

	if (!destination || !size || !source || !source[0])
		return FEV_ERR_ARGUMENT;
	length = snprintf(destination, size, "%s", source);
	return length < 0 || (size_t)length >= size ? FEV_ERR_ARGUMENT : FEV_OK;
}

static struct fev_candidate *find_candidate(struct fev_service *service,
					    uint64_t candidate_id)
{
	size_t i;

	for (i = 0; i < service->count; i++)
		if (service->candidates[i].candidate_id == candidate_id)
			return &service->candidates[i];
	return NULL;
}

static const struct fev_candidate *find_candidate_const(
		const struct fev_service *service, uint64_t candidate_id)
{
	size_t i;

	for (i = 0; i < service->count; i++)
		if (service->candidates[i].candidate_id == candidate_id)
			return &service->candidates[i];
	return NULL;
}

static int record_digest(const struct fev_disk_record *record,
			 uint8_t digest[FEV_DIGEST_SIZE])
{
	struct fev_disk_record copy;

	if (!record || !digest)
		return FEV_ERR_ARGUMENT;
	copy = *record;
	memset(copy.record_digest, 0, sizeof(copy.record_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int write_all(int fd, const void *data, size_t length)
{
	const uint8_t *bytes = data;
	size_t written = 0;

	while (written < length) {
		ssize_t result = write(fd, bytes + written, length - written);
		if (result <= 0)
			return FEV_ERR_IO;
		written += (size_t)result;
	}
	return FEV_OK;
}

static int read_all(int fd, void *data, size_t length)
{
	uint8_t *bytes = data;
	size_t read_bytes = 0;

	while (read_bytes < length) {
		ssize_t result = read(fd, bytes + read_bytes, length - read_bytes);
		if (result == 0 && read_bytes == 0)
			return 1;
		if (result <= 0)
			return FEV_ERR_IO;
		read_bytes += (size_t)result;
	}
	return FEV_OK;
}

static int append_record(struct fev_service *service, uint32_t event,
			 const struct fev_candidate *candidate,
			 struct fev_receipt *receipt)
{
	struct fev_disk_record record;
	uint8_t digest[FEV_DIGEST_SIZE];
	int rc;

	if (!service || !candidate || service->journal_fd < 0)
		return FEV_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.magic = FEV_JOURNAL_MAGIC;
	record.version = FEV_JOURNAL_VERSION;
	record.sequence = service->next_sequence++;
	record.event = event;
	memcpy(record.previous_digest, service->last_digest, FEV_DIGEST_SIZE);
	record.candidate = *candidate;
	rc = record_digest(&record, digest);
	if (rc != FEV_OK)
		return rc;
	memcpy(record.record_digest, digest, FEV_DIGEST_SIZE);
	if (write_all(service->journal_fd, &record, sizeof(record)) != FEV_OK ||
	    fsync(service->journal_fd) < 0)
		return FEV_ERR_IO;
	memcpy(service->last_digest, digest, FEV_DIGEST_SIZE);
	if (receipt) {
		memset(receipt, 0, sizeof(*receipt));
		receipt->journal_sequence = record.sequence;
		receipt->candidate_id = candidate->candidate_id;
		receipt->state = candidate->state;
		memcpy(receipt->candidate_digest, candidate->candidate_digest,
		       FEV_DIGEST_SIZE);
		if (digest_bytes(receipt, offsetof(struct fev_receipt, receipt_digest),
				 receipt->receipt_digest) != FEV_OK)
			return FEV_ERR_TAMPER;
	}
	return FEV_OK;
}

static int upsert_replay(struct fev_service *service,
			 const struct fev_candidate *candidate)
{
	struct fev_candidate *existing;

	existing = find_candidate(service, candidate->candidate_id);
	if (existing) {
		*existing = *candidate;
		return FEV_OK;
	}
	if (service->count >= FEV_MAX_CANDIDATES)
		return FEV_ERR_FULL;
	service->candidates[service->count++] = *candidate;
	return FEV_OK;
}

static int replay(struct fev_service *service)
{
	struct fev_disk_record record;
	uint8_t expected[FEV_DIGEST_SIZE];
	uint64_t expected_sequence = 1;
	int rc;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FEV_ERR_IO;
	service->count = 0;
	service->next_sequence = 1;
	memset(service->last_digest, 0, FEV_DIGEST_SIZE);
	for (;;) {
		rc = read_all(service->journal_fd, &record, sizeof(record));
		if (rc == 1)
			break;
		if (rc != FEV_OK || record.magic != FEV_JOURNAL_MAGIC ||
		    record.version != FEV_JOURNAL_VERSION ||
		    record.sequence != expected_sequence ||
		    memcmp(record.previous_digest, service->last_digest,
			   FEV_DIGEST_SIZE) != 0 || record.candidate.candidate_id == 0)
			return FEV_ERR_TAMPER;
		if (record_digest(&record, expected) != FEV_OK ||
		    memcmp(expected, record.record_digest, FEV_DIGEST_SIZE) != 0)
			return FEV_ERR_TAMPER;
		if (upsert_replay(service, &record.candidate) != FEV_OK)
			return FEV_ERR_FULL;
		memcpy(service->last_digest, record.record_digest, FEV_DIGEST_SIZE);
		expected_sequence++;
	}
	service->next_sequence = expected_sequence;
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FEV_ERR_IO;
	return FEV_OK;
}

static int set_state(struct fev_service *service, struct fev_candidate *candidate,
			 uint32_t state, uint32_t event, struct fev_receipt *receipt)
{
	candidate->state = state;
	candidate->generation++;
	return append_record(service, event, candidate, receipt);
}

static int compute_metrics(const struct fev_candidate *candidate,
			   uint64_t value, uint64_t *improvement,
			   uint64_t *regression)
{
	uint64_t numerator;

	if (!candidate || !improvement || !regression || candidate->baseline_metric == 0)
		return FEV_ERR_ARGUMENT;
	*improvement = 0;
	*regression = 0;
	if (candidate->metric_kind == FEV_METRIC_HIGHER_BETTER) {
		if (value >= candidate->baseline_metric) {
			if (value - candidate->baseline_metric > UINT64_MAX / 1000000ULL)
				return FEV_ERR_OVERFLOW;
			numerator = (value - candidate->baseline_metric) * 1000000ULL;
			*improvement = numerator / candidate->baseline_metric;
		} else {
			if (candidate->baseline_metric - value > UINT64_MAX / 1000000ULL)
				return FEV_ERR_OVERFLOW;
			numerator = (candidate->baseline_metric - value) * 1000000ULL;
			*regression = numerator / candidate->baseline_metric;
		}
	} else {
		if (value <= candidate->baseline_metric) {
			if (candidate->baseline_metric - value > UINT64_MAX / 1000000ULL)
				return FEV_ERR_OVERFLOW;
			numerator = (candidate->baseline_metric - value) * 1000000ULL;
			*improvement = numerator / candidate->baseline_metric;
		} else {
			if (value - candidate->baseline_metric > UINT64_MAX / 1000000ULL)
				return FEV_ERR_OVERFLOW;
			numerator = (value - candidate->baseline_metric) * 1000000ULL;
			*regression = numerator / candidate->baseline_metric;
		}
	}
	return FEV_OK;
}

int fev_open(struct fev_service *service, const char *path)
{
	int rc;

	if (!service || !path || !path[0])
		return FEV_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = open(path, O_CREAT | O_RDWR | O_APPEND | O_CLOEXEC,
				   0600);
	if (service->journal_fd < 0)
		return FEV_ERR_IO;
	rc = replay(service);
	if (rc != FEV_OK) {
		close(service->journal_fd);
		service->journal_fd = -1;
	}
	return rc;
}

void fev_close(struct fev_service *service)
{
	if (!service)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

int fev_propose(struct fev_service *service, uint64_t candidate_id,
		uint64_t generation, uint32_t flags, uint32_t metric_kind,
		uint64_t baseline_metric, const char *source_head,
		const char *parent_head, const char *rollback_tag,
		const uint8_t research_digest[FEV_DIGEST_SIZE],
		const uint8_t baseline_digest[FEV_DIGEST_SIZE],
		const uint8_t candidate_digest[FEV_DIGEST_SIZE],
		const struct fev_policy *policy, struct fev_candidate *out)
{
	struct fev_candidate candidate;

	if (!service || service->journal_fd < 0 || !out || !candidate_id || !generation ||
	    !baseline_metric || (flags & ~FEV_FLAGS_ALL) ||
	    (metric_kind != FEV_METRIC_LOWER_BETTER &&
	     metric_kind != FEV_METRIC_HIGHER_BETTER) || !source_head ||
	    !parent_head || !rollback_tag || !research_digest || !baseline_digest ||
	    !candidate_digest || all_zero(baseline_digest, FEV_DIGEST_SIZE) ||
    all_zero(candidate_digest, FEV_DIGEST_SIZE) || !policy ||
    policy->min_improvement_ppm > 1000000U ||

	    policy->max_regression_ppm > 1000000U || policy->reserved[0] ||
	    policy->reserved[1] || (policy->require_rollback && !rollback_tag[0]) ||
	    (policy->require_research && all_zero(research_digest, FEV_DIGEST_SIZE)))
		return FEV_ERR_ARGUMENT;
	if (find_candidate(service, candidate_id))
		return FEV_ERR_CONFLICT;
	if (service->count >= FEV_MAX_CANDIDATES)
		return FEV_ERR_FULL;
	memset(&candidate, 0, sizeof(candidate));
	candidate.candidate_id = candidate_id;
	candidate.generation = generation;
	candidate.state = FEV_STATE_DRAFT;
	candidate.flags = flags;
	candidate.metric_kind = metric_kind;
	candidate.baseline_metric = baseline_metric;
	candidate.policy = *policy;
	if (copy_text(candidate.source_head, sizeof(candidate.source_head), source_head) != FEV_OK ||
	    copy_text(candidate.parent_head, sizeof(candidate.parent_head), parent_head) != FEV_OK ||
	    copy_text(candidate.rollback_tag, sizeof(candidate.rollback_tag), rollback_tag) != FEV_OK)
		return FEV_ERR_ARGUMENT;
	memcpy(candidate.research_digest, research_digest, FEV_DIGEST_SIZE);
	memcpy(candidate.baseline_digest, baseline_digest, FEV_DIGEST_SIZE);
	memcpy(candidate.candidate_digest, candidate_digest, FEV_DIGEST_SIZE);
	if (append_record(service, FEV_EVENT_PROPOSE, &candidate, NULL) != FEV_OK)
		return FEV_ERR_IO;
	service->candidates[service->count++] = candidate;
	*out = candidate;
	return FEV_OK;
}

int fev_isolate(struct fev_service *service, uint64_t candidate_id,
		struct fev_candidate *out)
{
	struct fev_candidate *candidate;
	int rc;

	if (!service || !out || !candidate_id)
		return FEV_ERR_ARGUMENT;
	candidate = find_candidate(service, candidate_id);
	if (!candidate)
		return FEV_ERR_NOT_FOUND;
	if (candidate->state != FEV_STATE_DRAFT)
		return FEV_ERR_STATE;
	rc = set_state(service, candidate, FEV_STATE_ISOLATED, FEV_EVENT_ISOLATE, NULL);
	if (rc != FEV_OK)
		return rc;
	*out = *candidate;
	return FEV_OK;
}

int fev_record_validation(struct fev_service *service, uint64_t candidate_id,
		uint32_t validation_passed, uint32_t reproducible,
		uint64_t candidate_metric, const uint8_t evidence_digest[FEV_DIGEST_SIZE],
		const uint8_t approval_digest[FEV_DIGEST_SIZE],
		struct fev_candidate *out)
{
	struct fev_candidate *candidate;
	uint64_t improvement;
	uint64_t regression;
	int rc;

	if (!service || !out || !candidate_id || validation_passed > 1U ||
	    reproducible > 1U || !candidate_metric || !evidence_digest ||
	    all_zero(evidence_digest, FEV_DIGEST_SIZE))
		return FEV_ERR_ARGUMENT;
	candidate = find_candidate(service, candidate_id);
	if (!candidate)
		return FEV_ERR_NOT_FOUND;
	if (candidate->state != FEV_STATE_ISOLATED)
		return FEV_ERR_STATE;
	rc = compute_metrics(candidate, candidate_metric, &improvement, &regression);
	if (rc != FEV_OK)
		return rc;
	candidate->candidate_metric = candidate_metric;
	candidate->improvement_ppm = improvement;
	candidate->regression_ppm = regression;
	candidate->validation_passed = validation_passed;
	candidate->reproducible = reproducible;
	candidate->validation_sequence++;
	memcpy(candidate->evidence_digest, evidence_digest, FEV_DIGEST_SIZE);
	if (approval_digest)
		memcpy(candidate->approval_digest, approval_digest, FEV_DIGEST_SIZE);
	if (!validation_passed ||
	    (candidate->policy.require_reproducible && !reproducible) ||
	    regression > candidate->policy.max_regression_ppm ||
	    improvement < candidate->policy.min_improvement_ppm ||
	    (candidate->policy.require_external_approval &&
	     all_zero(candidate->approval_digest, FEV_DIGEST_SIZE))) {
		candidate->state = FEV_STATE_REJECTED;
		(void)snprintf(candidate->reason, sizeof(candidate->reason),
			       "candidate rejected: validation=%u reproducible=%u improvement_ppm=%llu regression_ppm=%llu",
			       validation_passed, reproducible,
			       (unsigned long long)improvement,
			       (unsigned long long)regression);
		rc = append_record(service, FEV_EVENT_VALIDATE, candidate, NULL);
		if (rc != FEV_OK)
			return rc;
		*out = *candidate;
		return FEV_ERR_POLICY;
	}
	candidate->state = FEV_STATE_VALIDATED;
	(void)snprintf(candidate->reason, sizeof(candidate->reason),
		       "candidate validated: improvement_ppm=%llu regression_ppm=%llu",
		       (unsigned long long)improvement,
		       (unsigned long long)regression);
	rc = append_record(service, FEV_EVENT_VALIDATE, candidate, NULL);
	if (rc != FEV_OK)
		return rc;
	*out = *candidate;
	return FEV_OK;
}

int fev_promote(struct fev_service *service, uint64_t candidate_id,
		struct fev_candidate *out, struct fev_receipt *receipt)
{
	struct fev_candidate *candidate;
	int rc;

	if (!service || !out || !candidate_id)
		return FEV_ERR_ARGUMENT;
	candidate = find_candidate(service, candidate_id);
	if (!candidate)
		return FEV_ERR_NOT_FOUND;
	if (candidate->state != FEV_STATE_VALIDATED)
		return FEV_ERR_STATE;
	if ((candidate->policy.require_rollback && !candidate->rollback_tag[0]) ||
	        (candidate->policy.require_research &&
     all_zero(candidate->research_digest, FEV_DIGEST_SIZE)) ||
    (candidate->policy.require_reproducible && !candidate->reproducible) ||
    ((candidate->flags & FEV_FLAG_MODEL_PROPOSAL) &&
     all_zero(candidate->approval_digest, FEV_DIGEST_SIZE)))

		return FEV_ERR_POLICY;
	rc = set_state(service, candidate, FEV_STATE_PROMOTED, FEV_EVENT_PROMOTE,
		       receipt);
	if (rc != FEV_OK)
		return rc;
	*out = *candidate;
	return FEV_OK;
}

int fev_rollback(struct fev_service *service, uint64_t candidate_id,
		const uint8_t reason_digest[FEV_DIGEST_SIZE],
		struct fev_candidate *out, struct fev_receipt *receipt)
{
	struct fev_candidate *candidate;
	int rc;

	if (!service || !out || !candidate_id || !reason_digest ||
	    all_zero(reason_digest, FEV_DIGEST_SIZE))
		return FEV_ERR_ARGUMENT;
	candidate = find_candidate(service, candidate_id);
	if (!candidate)
		return FEV_ERR_NOT_FOUND;
	if (candidate->state != FEV_STATE_PROMOTED &&
	    candidate->state != FEV_STATE_VALIDATED)
		return FEV_ERR_STATE;
	memcpy(candidate->rollback_reason_digest, reason_digest, FEV_DIGEST_SIZE);
	rc = set_state(service, candidate, FEV_STATE_ROLLED_BACK, FEV_EVENT_ROLLBACK,
		       receipt);
	if (rc != FEV_OK)
		return rc;
	*out = *candidate;
	return FEV_OK;
}

int fev_query(const struct fev_service *service, uint64_t candidate_id,
	      struct fev_candidate *out)
{
	const struct fev_candidate *candidate;

	if (!service || !out || !candidate_id)
		return FEV_ERR_ARGUMENT;
	candidate = find_candidate_const(service, candidate_id);
	if (!candidate)
		return FEV_ERR_NOT_FOUND;
	*out = *candidate;
	return FEV_OK;
}

int fev_verify_candidate(const struct fev_candidate *candidate)
{
	if (!candidate || !candidate->candidate_id || !candidate->generation ||
	    candidate->state < FEV_STATE_DRAFT || candidate->state > FEV_STATE_REJECTED ||
	    !candidate->source_head[0] || !candidate->parent_head[0] ||
	    !candidate->rollback_tag[0] || candidate->baseline_metric == 0 ||
	    all_zero(candidate->baseline_digest, FEV_DIGEST_SIZE) ||
	    all_zero(candidate->candidate_digest, FEV_DIGEST_SIZE))
		return FEV_ERR_TAMPER;
	return FEV_OK;
}

int fev_verify_receipt(const struct fev_receipt *receipt)
{
	uint8_t digest[FEV_DIGEST_SIZE];

	if (!receipt || !receipt->journal_sequence || !receipt->candidate_id ||
	    !receipt->state)
		return FEV_ERR_ARGUMENT;
	if (digest_bytes(receipt, offsetof(struct fev_receipt, receipt_digest),
			 digest) != FEV_OK)
		return FEV_ERR_TAMPER;
	return memcmp(digest, receipt->receipt_digest, FEV_DIGEST_SIZE) == 0 ?
		FEV_OK : FEV_ERR_TAMPER;
}
