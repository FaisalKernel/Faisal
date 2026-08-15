#define _GNU_SOURCE
#include "faisal_memory_service.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FMS_SIDECAR_MAGIC 0x464d5343U
#define FMS_SIDECAR_VERSION 1U

struct fms_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t content_len;
	uint64_t sequence;
	uint64_t record_id;
	uint64_t kernel_generation;
	uint64_t provenance_sequence;
	uint32_t tier;
	uint32_t confidence_ppm;
	uint32_t importance_ppm;
	uint32_t reserved;
	uint8_t digest[FMS_DIGEST_SIZE];
};

struct fms_sidecar {
	uint32_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t reserved;
	struct fms_checkpoint_state state;
};

static int write_all(int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len) {
		ssize_t n = write(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return FMS_ERR_IO;
		}
		if (!n)
			return FMS_ERR_IO;
		p += n;
		len -= (size_t)n;
	}
	return FMS_OK;
}

static int read_all(int fd, void *buf, size_t len)
{
	unsigned char *p = buf;
	while (len) {
		ssize_t n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return FMS_ERR_IO;
		}
		if (!n)
			return FMS_ERR_CORRUPT;
		p += n;
		len -= (size_t)n;
	}
	return FMS_OK;
}

static int digest_bytes(const void *data, size_t len,
			 unsigned char digest[FMS_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 0;
	int ret = FMS_ERR_IO;
	if (!ctx)
		return FMS_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, len) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
	    out_len == FMS_DIGEST_SIZE)
		ret = FMS_OK;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int digest_entries(const struct fms_service *service,
			   unsigned char digest[FMS_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 0;
	size_t i;
	int ret = FMS_ERR_IO;
	if (!ctx)
		return FMS_ERR_IO;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto out;
	for (i = 0; i < service->entry_count; i++) {
		if (EVP_DigestUpdate(ctx, &service->entries[i].sequence,
				     sizeof(service->entries[i].sequence)) != 1 ||
		    EVP_DigestUpdate(ctx, service->entries[i].digest,
				     FMS_DIGEST_SIZE) != 1 ||
		    EVP_DigestUpdate(ctx, &service->entries[i].provenance_sequence,
				     sizeof(service->entries[i].provenance_sequence)) != 1 ||
		    EVP_DigestUpdate(ctx, &service->entries[i].tier,
				     sizeof(service->entries[i].tier)) != 1)
			goto out;
	}
	if (EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
	    out_len == FMS_DIGEST_SIZE)
		ret = FMS_OK;
out:
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int kernel_session_open(struct fms_service *service)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_light_agent agent = {
		.size = sizeof(agent),
		.role = AGI_LC_LIGHT_AGENT_ROLE_MEMORY,
		.workload = AGI_LC_WORKLOAD_BACKGROUND_LEARNING,
		.correlation = 71001,
	};
	struct agi_lc_agent selected = { .size = sizeof(selected) };

	service->kernel_fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC);
	if (service->kernel_fd < 0)
		return FMS_ERR_KERNEL;
	if (ioctl(service->kernel_fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(service->kernel_fd, AGI_LC_LIGHT_AGENT_REGISTER, &agent) < 0 ||
	    !agent.agent_id || !agent.capability)
		return FMS_ERR_KERNEL;
	selected.agent_id = agent.agent_id;
	selected.correlation = 71002;
	if (ioctl(service->kernel_fd, AGI_LC_SET_AGENT, &selected) < 0)
		return FMS_ERR_KERNEL;
	service->session_id = create.session_id;
	service->agent_id = agent.agent_id;
	service->agent_capability = agent.capability;
	return FMS_OK;
}

static int sidecar_path(const struct fms_service *service, char *path,
			 size_t path_size)
{
	int n = snprintf(path, path_size, "%s.ckpt", service->journal_path);
	return n < 0 || (size_t)n >= path_size ? FMS_ERR_ARGUMENT : FMS_OK;
}

static int sidecar_save(const struct fms_service *service)
{
	struct fms_sidecar sidecar;
	char path[4096];
	int fd, ret;

	if (sidecar_path(service, path, sizeof(path)) != FMS_OK)
		return FMS_ERR_ARGUMENT;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return FMS_ERR_IO;
	memset(&sidecar, 0, sizeof(sidecar));
	sidecar.magic = FMS_SIDECAR_MAGIC;
	sidecar.version = FMS_SIDECAR_VERSION;
	sidecar.size = sizeof(sidecar);
	sidecar.state = service->checkpoint;
	ret = write_all(fd, &sidecar, sizeof(sidecar));
	if (ret == FMS_OK && fdatasync(fd) < 0)
		ret = FMS_ERR_IO;
	close(fd);
	return ret;
}

static int sidecar_load(struct fms_service *service)
{
	struct fms_sidecar sidecar;
	char path[4096];
	int fd, ret;

	if (sidecar_path(service, path, sizeof(path)) != FMS_OK)
		return FMS_ERR_ARGUMENT;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return FMS_OK;
		return FMS_ERR_IO;
	}
	ret = read_all(fd, &sidecar, sizeof(sidecar));
	close(fd);
	if (ret != FMS_OK || sidecar.magic != FMS_SIDECAR_MAGIC ||
	    sidecar.version != FMS_SIDECAR_VERSION || sidecar.size != sizeof(sidecar))
		return FMS_ERR_CORRUPT;
	service->checkpoint = sidecar.state;
	service->checkpoint_valid = 1;
	return FMS_OK;
}

static int kernel_memory_create(struct fms_service *service,
				const struct fms_entry *entry,
				struct agi_lc_persistent_memory *out)
{
	struct agi_lc_persistent_memory request;

	memset(&request, 0, sizeof(request));
	request.size = sizeof(request);
	request.operation = AGI_LC_MEMORY_RECORD_CREATE;
	request.flags = AGI_LC_MEMORY_RECORD_FLAG_DURABLE;
	request.tier = entry->tier;
	request.scope_id = service->scope_id;
	request.provenance_sequence = entry->provenance_sequence;
	request.confidence_ppm = entry->confidence_ppm;
	request.importance_ppm = entry->importance_ppm;
	request.freshness_state = AGI_LC_MEMORY_FRESH;
	memcpy(request.content_digest, entry->digest, FMS_DIGEST_SIZE);
	request.correlation = 71010 + entry->sequence;
	if (ioctl(service->kernel_fd, AGI_LC_MEMORY_RECORD, &request) < 0)
		return FMS_ERR_KERNEL;
	*out = request;
	return FMS_OK;
}

static int journal_append(struct fms_service *service,
			  const struct fms_entry *entry)
{
	struct fms_disk_header header;

	memset(&header, 0, sizeof(header));
	header.magic = FMS_JOURNAL_MAGIC;
	header.version = FMS_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.content_len = entry->content_len;
	header.sequence = entry->sequence;
	header.record_id = entry->record_id;
	header.kernel_generation = entry->kernel_generation;
	header.provenance_sequence = entry->provenance_sequence;
	header.tier = entry->tier;
	header.confidence_ppm = entry->confidence_ppm;
	header.importance_ppm = entry->importance_ppm;
	memcpy(header.digest, entry->digest, FMS_DIGEST_SIZE);
	if (write_all(service->journal_fd, &header, sizeof(header)) != FMS_OK ||
	    write_all(service->journal_fd, entry->content, entry->content_len) != FMS_OK ||
	    fdatasync(service->journal_fd) < 0)
		return FMS_ERR_IO;
	return FMS_OK;
}

static struct fms_entry *find_entry(struct fms_service *service, uint64_t record_id)
{
	size_t i;
	for (i = 0; i < service->entry_count; i++)
		if (service->entries[i].record_id == record_id)
			return &service->entries[i];
	return NULL;
}

int fms_replay(struct fms_service *service)
{
	struct fms_disk_header header;
	struct fms_entry entry;
	off_t valid_end = 0;
	int ret;

	if (lseek(service->journal_fd, 0, SEEK_SET) < 0)
		return FMS_ERR_IO;
	service->entry_count = 0;
	service->next_sequence = 1;
	for (;;) {
		ssize_t n = read(service->journal_fd, &header, sizeof(header));
		if (!n)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return FMS_ERR_IO;
		}
		if ((size_t)n < sizeof(header)) {
			if (ftruncate(service->journal_fd, valid_end) < 0)
				return FMS_ERR_IO;
			break;
		}
		if (header.magic != FMS_JOURNAL_MAGIC ||
		    header.version != FMS_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    !header.content_len || header.content_len > FMS_MAX_CONTENT)
			return FMS_ERR_CORRUPT;
		memset(&entry, 0, sizeof(entry));
		entry.sequence = header.sequence;
		entry.record_id = header.record_id;
		entry.kernel_generation = header.kernel_generation;
		entry.provenance_sequence = header.provenance_sequence;
		entry.tier = header.tier;
		entry.confidence_ppm = header.confidence_ppm;
		entry.importance_ppm = header.importance_ppm;
		entry.content_len = header.content_len;
		memcpy(entry.digest, header.digest, FMS_DIGEST_SIZE);
		ret = read_all(service->journal_fd, entry.content, entry.content_len);
		if (ret != FMS_OK) {
			if (ftruncate(service->journal_fd, valid_end) < 0)
				return FMS_ERR_IO;
			break;
		}
		if (digest_bytes(entry.content, entry.content_len, header.digest) != FMS_OK)
			return FMS_ERR_IO;
		if (memcmp(header.digest, entry.digest, FMS_DIGEST_SIZE))
			return FMS_ERR_CORRUPT;
		if (!entry.record_id)
			return FMS_ERR_CORRUPT;
		if (service->entry_count >= FMS_MAX_RECORDS)
			return FMS_ERR_FULL;
		{
			struct fms_entry *old = find_entry(service, entry.record_id);
			if (old)
				*old = entry;
			else
				service->entries[service->entry_count++] = entry;
		}
		if (entry.sequence >= service->next_sequence)
			service->next_sequence = entry.sequence + 1;
		valid_end += (off_t)sizeof(header) + entry.content_len;
	}
	if (lseek(service->journal_fd, 0, SEEK_END) < 0)
		return FMS_ERR_IO;
	return FMS_OK;
}

static int rehydrate_kernel_records(struct fms_service *service)
{
	size_t i;
	for (i = 0; i < service->entry_count; i++) {
		struct agi_lc_persistent_memory kernel_record;
		int ret = kernel_memory_create(service, &service->entries[i], &kernel_record);
		if (ret != FMS_OK)
			return ret;
		service->entries[i].record_id = kernel_record.record_id;
		service->entries[i].authority_capability = kernel_record.authority_capability;
		service->entries[i].kernel_generation = kernel_record.generation;
	}
	return FMS_OK;
}

int fms_open(struct fms_service *service, const char *journal_path)
{
	int ret;

	if (!service || !journal_path || strlen(journal_path) >= sizeof(service->journal_path))
		return FMS_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->kernel_fd = -1;
	service->journal_fd = -1;
	service->scope_id = 0x46414953414c7101ULL;
	strncpy(service->journal_path, journal_path, sizeof(service->journal_path) - 1);
	service->journal_fd = open(journal_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (service->journal_fd < 0)
		return FMS_ERR_IO;
	ret = fms_replay(service);
	if (ret != FMS_OK)
		return ret;
	ret = sidecar_load(service);
	if (ret != FMS_OK)
		return ret;
	ret = kernel_session_open(service);
	if (ret != FMS_OK)
		return ret;
	return rehydrate_kernel_records(service);
}

void fms_close(struct fms_service *service)
{
	if (!service)
		return;
	if (service->kernel_fd >= 0)
		close(service->kernel_fd);
	if (service->journal_fd >= 0)
		close(service->journal_fd);
	service->kernel_fd = -1;
	service->journal_fd = -1;
}

int fms_put(struct fms_service *service, const char *content,
	    uint32_t tier, uint32_t confidence_ppm, uint32_t importance_ppm,
	    uint64_t provenance_sequence, struct fms_entry *out)
{
	struct fms_entry entry;
	struct agi_lc_persistent_memory kernel_record;
	unsigned char digest[FMS_DIGEST_SIZE];
	size_t len;
	int ret;

	if (!service || !content || !out || tier == 0 ||
	    confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
	    importance_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX)
		return FMS_ERR_ARGUMENT;
	len = strlen(content);
	if (!len || len >= FMS_MAX_CONTENT || service->entry_count >= FMS_MAX_RECORDS)
		return FMS_ERR_ARGUMENT;
	if (digest_bytes(content, len, digest) != FMS_OK)
		return FMS_ERR_IO;
	{
		size_t i;
		for (i = 0; i < service->entry_count; i++)
			if (!memcmp(service->entries[i].digest, digest, FMS_DIGEST_SIZE)) {
				*out = service->entries[i];
				return FMS_OK;
			}
	}
	memset(&entry, 0, sizeof(entry));
	entry.sequence = service->next_sequence++;
	entry.provenance_sequence = provenance_sequence;
	entry.tier = tier;
	entry.confidence_ppm = confidence_ppm;
	entry.importance_ppm = importance_ppm;
	entry.content_len = (uint32_t)len;
	memcpy(entry.digest, digest, FMS_DIGEST_SIZE);
	memcpy(entry.content, content, len);
	ret = kernel_memory_create(service, &entry, &kernel_record);
	if (ret != FMS_OK)
		return ret;
	entry.record_id = kernel_record.record_id;
	entry.authority_capability = kernel_record.authority_capability;
	entry.kernel_generation = kernel_record.generation;
	ret = journal_append(service, &entry);
	if (ret != FMS_OK)
		return ret;
	service->entries[service->entry_count++] = entry;
	*out = entry;
	return FMS_OK;
}

int fms_get(const struct fms_service *service, uint64_t record_id,
	   struct fms_entry *out)
{
	size_t i;
	if (!service || !out || !record_id)
		return FMS_ERR_ARGUMENT;
	for (i = 0; i < service->entry_count; i++)
		if (service->entries[i].record_id == record_id) {
			*out = service->entries[i];
			return FMS_OK;
		}
	return FMS_ERR_NOT_FOUND;
}

int fms_checkpoint(struct fms_service *service)
{
	struct agi_lc_checkpoint checkpoint;
	struct agi_lc_checkpoint_manifest manifest;
	struct agi_lc_verify verify;
	struct agi_lc_handoff handoff;
	struct agi_lc_gate gate;
	unsigned char digest[FMS_DIGEST_SIZE];
	int ret;

	if (!service)
		return FMS_ERR_ARGUMENT;
	if (digest_entries(service, digest) != FMS_OK)
		return FMS_ERR_IO;
	memset(&gate, 0, sizeof(gate));
	gate.size = sizeof(gate);
	gate.correlation = 71019;
	if (ioctl(service->kernel_fd, AGI_LC_SET_GATE, &gate) < 0)
		return FMS_ERR_KERNEL;
	memset(&checkpoint, 0, sizeof(checkpoint));
	checkpoint.size = sizeof(checkpoint);
	checkpoint.checkpoint_id = 0x7100000000000000ULL + service->next_sequence;
	memcpy(checkpoint.state_digest, digest, FMS_DIGEST_SIZE);
	checkpoint.correlation = 71020;
	if (ioctl(service->kernel_fd, AGI_LC_CHECKPOINT, &checkpoint) < 0)
		return FMS_ERR_KERNEL;
	memset(&manifest, 0, sizeof(manifest));
	manifest.size = sizeof(manifest);
	manifest.checkpoint_id = checkpoint.checkpoint_id;
	manifest.scope_flags = AGI_LC_CHECKPOINT_SCOPE_USER_STATE;
	manifest.resource_policy = AGI_LC_CHECKPOINT_RESOURCE_USERSPACE;
	manifest.user_state_digest[0] = digest[0];
	memcpy(manifest.user_state_digest, digest, FMS_DIGEST_SIZE);
	manifest.correlation = 71021;
	if (ioctl(service->kernel_fd, AGI_LC_CHECKPOINT_MANIFEST, &manifest) < 0)
		return FMS_ERR_KERNEL;
	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.checkpoint_id = checkpoint.checkpoint_id;
	verify.checkpoint_sequence = checkpoint.checkpoint_sequence;
	verify.parent_sequence = checkpoint.parent_sequence;
	memcpy(verify.state_digest, digest, FMS_DIGEST_SIZE);
	verify.correlation = 71022;
	if (ioctl(service->kernel_fd, AGI_LC_VERIFY_CHECKPOINT, &verify) < 0 ||
	    verify.status != 0 || verify.state != AGI_LC_VERIFY_MATCHED)
		return FMS_ERR_KERNEL;
	memset(&handoff, 0, sizeof(handoff));
	handoff.size = sizeof(handoff);
	if (ioctl(service->kernel_fd, AGI_LC_EXPORT_CHECKPOINT, &handoff) < 0 ||
	    !handoff.validated)
		return FMS_ERR_KERNEL;
	memset(&service->checkpoint, 0, sizeof(service->checkpoint));
	service->checkpoint.checkpoint_id = checkpoint.checkpoint_id;
	service->checkpoint.checkpoint_sequence = checkpoint.checkpoint_sequence;
	service->checkpoint.parent_sequence = checkpoint.parent_sequence;
	memcpy(service->checkpoint.state_digest, digest, FMS_DIGEST_SIZE);
	memcpy(service->checkpoint.manifest_digest, manifest.manifest_digest,
	       FMS_DIGEST_SIZE);
	service->checkpoint.handoff = handoff;
	service->checkpoint_valid = 1;
	ret = sidecar_save(service);
	return ret;
}

int fms_mark_crash(struct fms_service *service)
{
	struct agi_lc_recovery recovery;
	if (!service || !service->checkpoint_valid)
		return FMS_ERR_ARGUMENT;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_MARK_CRASH;
	recovery.checkpoint_id = service->checkpoint.checkpoint_id;
	memcpy(recovery.user_state_digest, service->checkpoint.state_digest,
	       FMS_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, service->checkpoint.manifest_digest,
	       FMS_DIGEST_SIZE);
	recovery.correlation = 71023;
	return ioctl(service->kernel_fd, AGI_LC_RECOVERY, &recovery) < 0 ?
		FMS_ERR_KERNEL : FMS_OK;
}

int fms_restore(struct fms_service *service)
{
	struct agi_lc_recovery recovery;
	struct agi_lc_verify verify;
	struct agi_lc_handoff handoff;
	struct agi_lc_gate gate;
	unsigned char digest[FMS_DIGEST_SIZE];

	if (!service || !service->checkpoint_valid)
		return FMS_ERR_ARGUMENT;
	if (digest_entries(service, digest) != FMS_OK)
		return FMS_ERR_IO;
	if (memcmp(digest, service->checkpoint.state_digest, FMS_DIGEST_SIZE))
		return FMS_ERR_CORRUPT;
	memset(&gate, 0, sizeof(gate));
	gate.size = sizeof(gate);
	gate.correlation = 71023;
	if (ioctl(service->kernel_fd, AGI_LC_SET_GATE, &gate) < 0)
		return FMS_ERR_KERNEL;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_RESTORE_BEGIN;
	recovery.checkpoint_id = service->checkpoint.checkpoint_id;
	recovery.checkpoint_sequence = service->checkpoint.checkpoint_sequence;
	recovery.parent_sequence = service->checkpoint.parent_sequence;
	memcpy(recovery.user_state_digest, service->checkpoint.state_digest,
	       FMS_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, service->checkpoint.manifest_digest,
	       FMS_DIGEST_SIZE);
	recovery.correlation = 71024;
	if (ioctl(service->kernel_fd, AGI_LC_RECOVERY, &recovery) < 0)
		return FMS_ERR_KERNEL;
	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.checkpoint_id = service->checkpoint.checkpoint_id;
	verify.checkpoint_sequence = service->checkpoint.checkpoint_sequence;
	verify.parent_sequence = service->checkpoint.parent_sequence;
	memcpy(verify.state_digest, service->checkpoint.state_digest,
	       FMS_DIGEST_SIZE);
	verify.correlation = 71025;
	if (ioctl(service->kernel_fd, AGI_LC_VERIFY_CHECKPOINT, &verify) < 0 ||
	    verify.state != AGI_LC_VERIFY_MATCHED)
		return FMS_ERR_KERNEL;
	handoff = service->checkpoint.handoff;
	handoff.validated = 0;
	handoff.correlation = 71026;
	if (ioctl(service->kernel_fd, AGI_LC_IMPORT_CHECKPOINT, &handoff) < 0 ||
	    !handoff.validated)
		return FMS_ERR_KERNEL;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_CONTINUE;
	recovery.checkpoint_id = service->checkpoint.checkpoint_id;
	recovery.correlation = 71027;
	memcpy(recovery.user_state_digest, service->checkpoint.state_digest,
	       FMS_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, service->checkpoint.manifest_digest,
	       FMS_DIGEST_SIZE);
	if (ioctl(service->kernel_fd, AGI_LC_RECOVERY, &recovery) < 0)
		return FMS_ERR_KERNEL;
	memset(&gate, 0, sizeof(gate));
	gate.size = sizeof(gate);
	gate.open = 1;
	gate.correlation = 71028;
	return ioctl(service->kernel_fd, AGI_LC_SET_GATE, &gate) < 0 ?
		FMS_ERR_KERNEL : FMS_OK;
}

int fms_test_stale_capability(struct fms_service *service, uint64_t record_id)
{
	struct fms_entry entry;
	struct agi_lc_persistent_memory query;
	if (fms_get(service, record_id, &entry) != FMS_OK)
		return FMS_ERR_NOT_FOUND;
	memset(&query, 0, sizeof(query));
	query.size = sizeof(query);
	query.operation = AGI_LC_MEMORY_RECORD_QUERY;
	query.record_id = entry.record_id;
	query.authority_capability = entry.authority_capability ^ 1ULL;
	query.correlation = 71030;
	if (ioctl(service->kernel_fd, AGI_LC_MEMORY_RECORD, &query) == 0)
		return FMS_ERR_CAPABILITY;
	return errno == EACCES ? FMS_OK : FMS_ERR_KERNEL;
}
