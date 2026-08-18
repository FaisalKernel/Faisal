#include "faisal_snapshot_index.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FSI_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if ((!data && length) || !digest)
		return FSI_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FSI_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    (length && EVP_DigestUpdate(ctx, data, length) != 1) ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FSI_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FSI_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FSI_OK;
}

static int write_full(int fd, const void *data, size_t length)
{
	const uint8_t *cursor = data;
	size_t written = 0;

	while (written < length) {
		ssize_t count = write(fd, cursor + written, length - written);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return FSI_ERR_IO;
		}
		if (count == 0)
			return FSI_ERR_IO;
		written += (size_t)count;
	}
	return FSI_OK;
}

static int read_full(int fd, void *data, size_t length, size_t *read_bytes)
{
	uint8_t *cursor = data;
	size_t received = 0;

	while (received < length) {
		ssize_t count = read(fd, cursor + received, length - received);
		if (count < 0) {
			if (errno == EINTR)
				continue;
			return FSI_ERR_IO;
		}
		if (count == 0)
			break;
		received += (size_t)count;
	}
	if (read_bytes)
		*read_bytes = received;
	return FSI_OK;
}

static int snapshot_digest(const struct fsi_snapshot *snapshot,
			   uint8_t digest[FSI_DIGEST_SIZE])
{
	struct fsi_snapshot copy;

	if (!snapshot || !digest)
		return FSI_ERR_ARGUMENT;
	copy = *snapshot;
	memset(copy.snapshot_digest, 0, sizeof(copy.snapshot_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

static int record_digest(const struct fsi_disk_record *record,
			 uint8_t digest[FSI_DIGEST_SIZE])
{
	struct fsi_disk_record copy;

	if (!record || !digest)
		return FSI_ERR_ARGUMENT;
	copy = *record;
	memset(copy.record_digest, 0, sizeof(copy.record_digest));
	return digest_bytes(&copy, sizeof(copy), digest);
}

int fsi_verify_snapshot(const struct fsi_snapshot *snapshot)
{
	uint8_t payload_digest[FSI_DIGEST_SIZE];
	uint8_t snapshot_digest_value[FSI_DIGEST_SIZE];
	int rc;

	if (!snapshot || snapshot->snapshot_id == 0 || snapshot->sequence == 0 ||
	    snapshot->objective_id == 0 || snapshot->task_id == 0 ||
	    snapshot->agent_id == 0 || snapshot->objective_generation == 0 ||
	    snapshot->task_generation == 0 || snapshot->payload_len > FSI_MAX_PAYLOAD ||
	    snapshot->state < FSI_STATE_ACTIVE || snapshot->state > FSI_STATE_EXPIRED ||
	    snapshot->retention_class < FSI_RETENTION_EPHEMERAL ||
	    snapshot->retention_class > FSI_RETENTION_PINNED ||
	    snapshot->flags & ~FSI_FLAGS_ALL)
		return FSI_ERR_ARGUMENT;
	rc = digest_bytes(snapshot->payload, snapshot->payload_len, payload_digest);
	if (rc != FSI_OK)
		return rc;
	if (memcmp(payload_digest, snapshot->payload_digest, FSI_DIGEST_SIZE) != 0)
		return FSI_ERR_TAMPER;
	rc = snapshot_digest(snapshot, snapshot_digest_value);
	if (rc != FSI_OK)
		return rc;
	if (memcmp(snapshot_digest_value, snapshot->snapshot_digest,
		   FSI_DIGEST_SIZE) != 0)
		return FSI_ERR_TAMPER;
	return FSI_OK;
}

int fsi_verify_record(const struct fsi_disk_record *record,
		      const uint8_t previous_digest[FSI_DIGEST_SIZE])
{
	uint8_t digest[FSI_DIGEST_SIZE];
	int rc;

	if (!record || !previous_digest || record->magic != FSI_MAGIC ||
	    record->version != FSI_VERSION ||
	    (record->kind != FSI_KIND_SNAPSHOT &&
	     record->kind != FSI_KIND_COMPACT &&
	     record->kind != FSI_KIND_EXPIRE) ||
	    record->record_sequence == 0 ||
	    memcmp(record->previous_digest, previous_digest, FSI_DIGEST_SIZE) != 0)
		return FSI_ERR_CORRUPT;
	rc = fsi_verify_snapshot(&record->snapshot);
	if (rc != FSI_OK)
		return rc;
	rc = record_digest(record, digest);
	if (rc != FSI_OK)
		return rc;
	return memcmp(digest, record->record_digest, FSI_DIGEST_SIZE) == 0 ?
		FSI_OK : FSI_ERR_TAMPER;
}

static int find_snapshot(const struct fsi_service *service, uint64_t snapshot_id)
{
	size_t i;

	if (!service)
		return -1;
	for (i = 0; i < service->count; i++)
		if (service->snapshots[i].snapshot_id == snapshot_id)
			return (int)i;
	return -1;
}

static int append_record(struct fsi_service *service, uint16_t kind,
			 const struct fsi_snapshot *snapshot)
{
	struct fsi_disk_record record;
	uint8_t digest[FSI_DIGEST_SIZE];
	int rc;

	if (!service || service->journal_fd < 0 || !snapshot ||
	    service->next_sequence == UINT64_MAX)
		return FSI_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.magic = FSI_MAGIC;
	record.version = FSI_VERSION;
	record.kind = kind;
	record.record_sequence = service->next_sequence++;
	memcpy(record.previous_digest, service->chain_digest, FSI_DIGEST_SIZE);
	record.snapshot = *snapshot;
	rc = record_digest(&record, digest);
	if (rc != FSI_OK)
		return rc;
	memcpy(record.record_digest, digest, FSI_DIGEST_SIZE);
	if (write_full(service->journal_fd, &record, sizeof(record)) != FSI_OK ||
	    fsync(service->journal_fd) != 0)
		return FSI_ERR_IO;
	memcpy(service->chain_digest, record.record_digest, FSI_DIGEST_SIZE);
	service->journal_records++;
	return FSI_OK;
}

static void rebuild_active_index(struct fsi_service *service)
{
	size_t i;

	service->active_count = 0;
	for (i = 0; i < service->count; i++) {
		if (service->snapshots[i].state == FSI_STATE_ACTIVE)
			service->active_indices[service->active_count++] = i;
	}
}

static int upsert_snapshot(struct fsi_service *service,
			   const struct fsi_snapshot *snapshot)
{
	int index;

	if (!service || !snapshot)
		return FSI_ERR_ARGUMENT;
	index = find_snapshot(service, snapshot->snapshot_id);
	if (index >= 0) {
		service->snapshots[index] = *snapshot;
		rebuild_active_index(service);
		return FSI_OK;
	}
	if (service->count >= FSI_MAX_SNAPSHOTS)
		return FSI_ERR_FULL;
	service->snapshots[service->count++] = *snapshot;
	rebuild_active_index(service);
	return FSI_OK;
}

int fsi_replay(struct fsi_service *service)
{
	struct fsi_disk_record record;
	uint8_t chain[FSI_DIGEST_SIZE] = { 0 };
	size_t received;
	int rc;

	if (!service || service->journal_fd < 0)
		return FSI_ERR_ARGUMENT;
	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FSI_ERR_IO;
	service->count = 0;
	service->active_count = 0;
	service->next_snapshot_id = 1;
	service->next_sequence = 1;
	service->journal_records = 0;
	memset(service->chain_digest, 0, FSI_DIGEST_SIZE);
	for (;;) {
		rc = read_full(service->journal_fd, &record, sizeof(record), &received);
		if (rc != FSI_OK)
			return rc;
		if (received == 0)
			break;
		if (received != sizeof(record))
			return FSI_ERR_CORRUPT;
		rc = fsi_verify_record(&record, chain);
		if (rc != FSI_OK)
			return rc;
		rc = upsert_snapshot(service, &record.snapshot);
		if (rc != FSI_OK)
			return rc;
		memcpy(chain, record.record_digest, FSI_DIGEST_SIZE);
		memcpy(service->chain_digest, chain, FSI_DIGEST_SIZE);
		service->journal_records++;
		if (record.snapshot.snapshot_id >= service->next_snapshot_id)
			service->next_snapshot_id = record.snapshot.snapshot_id + 1U;
		if (record.record_sequence >= service->next_sequence)
			service->next_sequence = record.record_sequence + 1U;
	}
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FSI_ERR_IO;
	return FSI_OK;
}

int fsi_open(struct fsi_service *service, const char *journal_path)
{
	if (!service || !journal_path || !journal_path[0] ||
	    strlen(journal_path) >= sizeof(service->journal_path))
		return FSI_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->journal_fd = open(journal_path, O_CREAT | O_RDWR | O_APPEND, 0600);
	if (service->journal_fd < 0)
		return FSI_ERR_IO;
	memcpy(service->journal_path, journal_path, strlen(journal_path) + 1U);
	if (fsi_replay(service) != FSI_OK) {
		close(service->journal_fd);
		service->journal_fd = -1;
		return FSI_ERR_CORRUPT;
	}
	return FSI_OK;
}

void fsi_close(struct fsi_service *service)
{
	if (!service)
		return;
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->journal_fd = -1;
}

int fsi_append(struct fsi_service *service,
	       const struct fsi_snapshot_request *request,
	       const uint8_t *payload, size_t payload_len,
	       const uint8_t parent_digest[FSI_DIGEST_SIZE],
	       uint64_t expires_ns, uint32_t importance_ppm,
	       struct fsi_snapshot *out)
{
	struct fsi_snapshot snapshot;
	uint8_t zero_digest[FSI_DIGEST_SIZE] = { 0 };
	int rc;

	if (!service || !request || !payload || !out || payload_len > FSI_MAX_PAYLOAD ||
	    request->objective_id == 0 || request->task_id == 0 || request->agent_id == 0 ||
	    request->objective_generation == 0 || request->task_generation == 0 ||
	    request->now_ns == 0 || expires_ns <= request->now_ns ||
	    request->retention_class < FSI_RETENTION_EPHEMERAL ||
	    request->retention_class > FSI_RETENTION_PINNED ||
	    importance_ppm > 1000000U || (request->flags & ~FSI_FLAGS_ALL))
		return FSI_ERR_ARGUMENT;
	if (service->count >= FSI_MAX_SNAPSHOTS || service->next_snapshot_id == UINT64_MAX)
		return FSI_ERR_FULL;
	memset(&snapshot, 0, sizeof(snapshot));
	snapshot.snapshot_id = service->next_snapshot_id++;
	snapshot.objective_id = request->objective_id;
	snapshot.task_id = request->task_id;
	snapshot.agent_id = request->agent_id;
	snapshot.objective_generation = request->objective_generation;
	snapshot.task_generation = request->task_generation;
	snapshot.sequence = service->next_sequence;
	snapshot.created_ns = request->now_ns;
	snapshot.expires_ns = expires_ns;
	snapshot.state = FSI_STATE_ACTIVE;
	snapshot.retention_class = request->retention_class;
	snapshot.importance_ppm = importance_ppm;
	snapshot.flags = request->flags;
	snapshot.payload_len = (uint32_t)payload_len;
	memcpy(snapshot.parent_digest, parent_digest ? parent_digest : zero_digest,
	       FSI_DIGEST_SIZE);
	memcpy(snapshot.payload, payload, payload_len);
	rc = digest_bytes(snapshot.payload, snapshot.payload_len,
			  snapshot.payload_digest);
	if (rc != FSI_OK)
		return rc;
	rc = snapshot_digest(&snapshot, snapshot.snapshot_digest);
	if (rc != FSI_OK)
		return rc;
	rc = append_record(service, FSI_KIND_SNAPSHOT, &snapshot);
	if (rc != FSI_OK)
		return rc;
	if (upsert_snapshot(service, &snapshot) != FSI_OK)
		return FSI_ERR_FULL;
	*out = snapshot;
	return FSI_OK;
}

int fsi_restore_latest(const struct fsi_service *service,
		       const struct fsi_snapshot_request *request,
		       struct fsi_snapshot *out)
{
	const struct fsi_snapshot *best = NULL;
	int saw_generation_mismatch = 0;
	size_t i;

	if (!service || !request || !out || request->objective_id == 0 ||
	    request->task_id == 0 || request->agent_id == 0 ||
	    request->objective_generation == 0 || request->task_generation == 0 ||
	    request->now_ns == 0)
		return FSI_ERR_ARGUMENT;
	for (i = 0; i < service->active_count; i++) {
		const struct fsi_snapshot *snapshot =
			&service->snapshots[service->active_indices[i]];
		uint64_t age;

		if (snapshot->objective_id != request->objective_id ||
		    snapshot->task_id != request->task_id ||
		    snapshot->agent_id != request->agent_id ||
		    snapshot->state != FSI_STATE_ACTIVE)
			continue;
		if (snapshot->objective_generation != request->objective_generation ||
		    snapshot->task_generation != request->task_generation) {
			saw_generation_mismatch = 1;
			continue;
		}
		if (request->retention_class &&
		    snapshot->retention_class != request->retention_class)
			continue;
		if (snapshot->importance_ppm < request->minimum_importance_ppm ||
		    snapshot->expires_ns <= request->now_ns)
			continue;
		age = request->now_ns - snapshot->created_ns;
		if (request->max_age_ns && age > request->max_age_ns)
			continue;
		if (!best || snapshot->sequence > best->sequence)
			best = snapshot;
	}
	if (!best)
		return saw_generation_mismatch ? FSI_ERR_GENERATION : FSI_ERR_NOT_FOUND;
	*out = *best;
	return fsi_verify_snapshot(out);
}

static int mark_state(struct fsi_service *service, size_t index,
		      uint32_t state, uint16_t kind)
{
	struct fsi_snapshot snapshot;
	int rc;

	if (!service || index >= service->count)
		return FSI_ERR_ARGUMENT;
	snapshot = service->snapshots[index];
	snapshot.state = state;
	rc = snapshot_digest(&snapshot, snapshot.snapshot_digest);
	if (rc != FSI_OK)
		return rc;
	rc = append_record(service, kind, &snapshot);
	if (rc != FSI_OK)
		return rc;
	service->snapshots[index] = snapshot;
	rebuild_active_index(service);
	return FSI_OK;
}

int fsi_expire(struct fsi_service *service, uint64_t now_ns,
	       uint32_t *expired_count)
{
	uint32_t count = 0;
	size_t i;

	if (!service || !expired_count || now_ns == 0)
		return FSI_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++) {
		if (service->snapshots[i].state != FSI_STATE_ACTIVE ||
		    service->snapshots[i].retention_class == FSI_RETENTION_PINNED ||
		    service->snapshots[i].expires_ns > now_ns)
			continue;
		if (mark_state(service, i, FSI_STATE_EXPIRED, FSI_KIND_EXPIRE) != FSI_OK)
			return FSI_ERR_IO;
		count++;
	}
	*expired_count = count;
	return FSI_OK;
}

static int has_newer_active(const struct fsi_service *service,
			    const struct fsi_snapshot *candidate)
{
	size_t i;

	for (i = 0; i < service->count; i++) {
		const struct fsi_snapshot *other = &service->snapshots[i];
		if (other->state == FSI_STATE_ACTIVE &&
		    other->objective_id == candidate->objective_id &&
		    other->task_id == candidate->task_id &&
		    other->agent_id == candidate->agent_id &&
		    other->objective_generation == candidate->objective_generation &&
		    other->task_generation == candidate->task_generation &&
		    other->sequence > candidate->sequence)
			return 1;
	}
	return 0;
}

int fsi_compact(struct fsi_service *service,
		const struct fsi_compaction_policy *policy,
		uint32_t *compacted_count)
{
	uint32_t count = 0;
	uint32_t live = 0;
	size_t i;

	if (!service || !policy || !compacted_count || policy->now_ns == 0 ||
	    policy->maximum_live_snapshots > FSI_MAX_SNAPSHOTS)
		return FSI_ERR_ARGUMENT;
	for (i = 0; i < service->count; i++)
		if (service->snapshots[i].state == FSI_STATE_ACTIVE)
			live++;
	for (i = 0; i < service->count; i++) {
		const struct fsi_snapshot *snapshot = &service->snapshots[i];
		uint64_t age;
		int over_limit;
		int low_importance;

		if (snapshot->state != FSI_STATE_ACTIVE ||
		    (policy->preserve_pinned &&
		     snapshot->retention_class == FSI_RETENTION_PINNED) ||
		    !has_newer_active(service, snapshot))
			continue;
		age = policy->now_ns > snapshot->created_ns ?
			policy->now_ns - snapshot->created_ns : 0;
		over_limit = policy->maximum_live_snapshots &&
			live > policy->maximum_live_snapshots;
		low_importance = snapshot->importance_ppm < policy->minimum_importance_ppm;
		if (age < policy->minimum_age_ns || (!over_limit && !low_importance))
			continue;
		if (mark_state(service, i, FSI_STATE_COMPACTED, FSI_KIND_COMPACT) != FSI_OK)
			return FSI_ERR_IO;
		if (live)
			live--;
		count++;
	}
	*compacted_count = count;
	return FSI_OK;
}

int fsi_query_attestation(const struct fsi_service *service,
			  struct fsi_attestation *out)
{
	size_t i;

	if (!service || !out)
		return FSI_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->next_snapshot_id = service->next_snapshot_id;
	out->next_sequence = service->next_sequence;
	out->journal_records = service->journal_records;
	memcpy(out->chain_digest, service->chain_digest, FSI_DIGEST_SIZE);
	for (i = 0; i < service->count; i++) {
		switch (service->snapshots[i].state) {
		case FSI_STATE_ACTIVE:
			out->active_snapshots++;
			break;
		case FSI_STATE_COMPACTED:
			out->compacted_snapshots++;
			break;
		case FSI_STATE_EXPIRED:
			out->expired_snapshots++;
			break;
		default:
			return FSI_ERR_CORRUPT;
		}
	}
	return FSI_OK;
}
