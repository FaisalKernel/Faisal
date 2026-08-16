#include "faisal_memory_transaction.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct m83_manifest {
	uint32_t magic;
	uint32_t version;
	uint32_t state;
	uint32_t operation_count;
	uint64_t transaction_id;
	uint32_t digest[FMS_DIGEST_SIZE / sizeof(uint32_t)];
	char journal_path[M83_MAX_OPS][M83_PATH_MAX];
	char backup_path[M83_MAX_OPS][M83_PATH_MAX];
	uint64_t committed_record_id[M83_MAX_OPS];
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;
	while (length) {
		ssize_t written = write(fd, cursor, length);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return M83_ERR_IO;
		}
		if (!written)
			return M83_ERR_IO;
		cursor += written;
		length -= (size_t)written;
	}
	return M83_OK;
}

static int read_all(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	while (length) {
		ssize_t read_count = read(fd, cursor, length);
		if (read_count < 0) {
			if (errno == EINTR)
				continue;
			return M83_ERR_IO;
		}
		if (!read_count)
			return M83_ERR_CORRUPT;
		cursor += read_count;
		length -= (size_t)read_count;
	}
	return M83_OK;
}

static int manifest_path(const char *coordinator, char *path, size_t size)
{
	int n = snprintf(path, size, "%s.manifest", coordinator);
	return n < 0 || (size_t)n >= size ? M83_ERR_ARGUMENT : M83_OK;
}

static int backup_path(const char *journal, char *path, size_t size)
{
	int n = snprintf(path, size, "%s.m83bak", journal);
	return n < 0 || (size_t)n >= size ? M83_ERR_ARGUMENT : M83_OK;
}

static int copy_file(const char *source, const char *destination)
{
	char buffer[4096];
	int input = open(source, O_RDONLY | O_CLOEXEC);
	int output;
	if (input < 0)
		return M83_ERR_IO;
	output = open(destination, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (output < 0) {
		close(input);
		return M83_ERR_IO;
	}
	for (;;) {
		ssize_t count = read(input, buffer, sizeof(buffer));
		if (!count)
			break;
		if (count < 0) {
			if (errno == EINTR)
				continue;
			close(input);
			close(output);
			return M83_ERR_IO;
		}
		if (write_all(output, buffer, (size_t)count) != M83_OK) {
			close(input);
			close(output);
			return M83_ERR_IO;
		}
	}
	if (fdatasync(output) < 0) {
		close(input);
		close(output);
		return M83_ERR_IO;
	}
	close(input);
	close(output);
	return M83_OK;
}

static int manifest_write(const char *coordinator, const struct m83_manifest *manifest)
{
	char path[4096];
	int fd;
	int ret;
	if (manifest_path(coordinator, path, sizeof(path)) != M83_OK)
		return M83_ERR_ARGUMENT;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return M83_ERR_IO;
	ret = write_all(fd, manifest, sizeof(*manifest));
	if (ret == M83_OK && fdatasync(fd) < 0)
		ret = M83_ERR_IO;
	close(fd);
	return ret;
}

static int manifest_load(const char *coordinator, struct m83_manifest *manifest)
{
	char path[4096];
	int fd;
	int ret;
	if (manifest_path(coordinator, path, sizeof(path)) != M83_OK)
		return M83_ERR_ARGUMENT;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? M83_ERR_INCOMPLETE : M83_ERR_IO;
	ret = read_all(fd, manifest, sizeof(*manifest));
	close(fd);
	if (ret != M83_OK || manifest->magic != M83_TXN_MAGIC ||
	    manifest->version != M83_TXN_VERSION ||
	    manifest->operation_count == 0 || manifest->operation_count > M83_MAX_OPS ||
	    manifest->state > M83_STATE_ABORTED)
		return M83_ERR_CORRUPT;
	return M83_OK;
}

static int validate_transaction(const struct m83_transaction *transaction)
{
	unsigned int i;
	if (!transaction || !transaction->transaction_id ||
	    !transaction->operation_count || transaction->operation_count > M83_MAX_OPS ||
	    !transaction->coordinator_path[0])
		return M83_ERR_ARGUMENT;
	for (i = 0; i < transaction->operation_count; i++) {
		unsigned int j;
		if (!transaction->operations[i].journal_path[0] ||
		    !transaction->operations[i].content[0] ||
		    transaction->operations[i].tier == 0 ||
		    transaction->operations[i].confidence_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX ||
		    transaction->operations[i].importance_ppm > AGI_LC_MEMORY_CONFIDENCE_MAX)
			return M83_ERR_ARGUMENT;
		for (j = i + 1; j < transaction->operation_count; j++)
			if (!strcmp(transaction->operations[i].journal_path,
				   transaction->operations[j].journal_path))
				return M83_ERR_ARGUMENT;
	}
	return M83_OK;
}

int m83_begin(struct m83_transaction *transaction, const char *coordinator_path,
	      uint64_t transaction_id)
{
	if (!transaction || !coordinator_path || !coordinator_path[0] ||
	    strlen(coordinator_path) >= sizeof(transaction->coordinator_path) ||
	    !transaction_id)
		return M83_ERR_ARGUMENT;
	memset(transaction, 0, sizeof(*transaction));
	transaction->transaction_id = transaction_id;
	strncpy(transaction->coordinator_path, coordinator_path,
		sizeof(transaction->coordinator_path) - 1);
	return M83_OK;
}

int m83_add_operation(struct m83_transaction *transaction, unsigned int index,
		      const char *journal_path, const char *content,
		      uint32_t tier, uint32_t confidence_ppm,
		      uint32_t importance_ppm, uint64_t provenance_sequence)
{
	struct m83_operation *operation;
	if (!transaction || index >= M83_MAX_OPS || !journal_path || !content ||
	    !journal_path[0] || !content[0] || strlen(journal_path) >= M83_PATH_MAX ||
	    strlen(content) >= M83_CONTENT_MAX)
		return M83_ERR_ARGUMENT;
	operation = &transaction->operations[index];
	memset(operation, 0, sizeof(*operation));
	strncpy(operation->journal_path, journal_path, sizeof(operation->journal_path) - 1);
	strncpy(operation->content, content, sizeof(operation->content) - 1);
	operation->tier = tier;
	operation->confidence_ppm = confidence_ppm;
	operation->importance_ppm = importance_ppm;
	operation->provenance_sequence = provenance_sequence;
	if (index >= transaction->operation_count)
		transaction->operation_count = index + 1;
	return M83_OK;
}

static void manifest_from_transaction(const struct m83_transaction *transaction,
				      struct m83_manifest *manifest)
{
	unsigned int i;
	memset(manifest, 0, sizeof(*manifest));
	manifest->magic = M83_TXN_MAGIC;
	manifest->version = M83_TXN_VERSION;
	manifest->state = M83_STATE_PREPARED;
	manifest->operation_count = transaction->operation_count;
	manifest->transaction_id = transaction->transaction_id;
	for (i = 0; i < transaction->operation_count; i++) {
		strncpy(manifest->journal_path[i], transaction->operations[i].journal_path,
			sizeof(manifest->journal_path[i]) - 1);
		backup_path(transaction->operations[i].journal_path,
			    manifest->backup_path[i], sizeof(manifest->backup_path[i]));
	}
}

int m83_commit(struct m83_transaction *transaction, unsigned int fail_after)
{
	struct m83_manifest manifest;
	struct fms_service services[M83_MAX_OPS];
	struct fms_entry entries[M83_MAX_OPS];
	unsigned int i;
	int ret;
	if (validate_transaction(transaction) != M83_OK)
		return M83_ERR_ARGUMENT;
	memset(services, 0, sizeof(services));
	for (i = 0; i < M83_MAX_OPS; i++) {
		services[i].kernel_fd = -1;
		services[i].journal_fd = -1;
	}
	memset(entries, 0, sizeof(entries));
	manifest_from_transaction(transaction, &manifest);
	for (i = 0; i < transaction->operation_count; i++) {
		if (copy_file(transaction->operations[i].journal_path,
			      manifest.backup_path[i]) != M83_OK)
			goto fail_io;
	}
	if (manifest_write(transaction->coordinator_path, &manifest) != M83_OK)
		goto fail_io;
	for (i = 0; i < transaction->operation_count; i++) {
		if (fms_open(&services[i], transaction->operations[i].journal_path) != FMS_OK)
			goto fail_io;
		if (fms_reactivate(&services[i]) != FMS_OK)
			goto fail_io;
		ret = fms_put(&services[i], transaction->operations[i].content,
			      transaction->operations[i].tier,
			      transaction->operations[i].confidence_ppm,
			      transaction->operations[i].importance_ppm,
			      transaction->operations[i].provenance_sequence, &entries[i]);
		if (ret != FMS_OK)
			goto fail_io;
		manifest.committed_record_id[i] = entries[i].record_id;
		if (fail_after && i + 1 == fail_after) {
			for (unsigned int j = 0; j <= i; j++)
				fms_close(&services[j]);
			return M83_ERR_INJECTED_CRASH;
		}
	}
	for (i = 0; i < transaction->operation_count; i++)
		fms_close(&services[i]);
	manifest.state = M83_STATE_COMMITTED;
	if (manifest_write(transaction->coordinator_path, &manifest) != M83_OK)
		return M83_ERR_IO;
	for (i = 0; i < transaction->operation_count; i++)
		unlink(manifest.backup_path[i]);
	return M83_OK;

fail_io:
	for (i = 0; i < transaction->operation_count; i++)
		if (services[i].journal_fd >= 0 || services[i].kernel_fd >= 0)
			fms_close(&services[i]);
	return M83_ERR_IO;
}

int m83_recover(const char *coordinator_path)
{
	struct m83_manifest manifest;
	unsigned int i;
	int ret = manifest_load(coordinator_path, &manifest);
	if (ret != M83_OK)
		return ret;
	if (manifest.state == M83_STATE_COMMITTED)
		return M83_OK;
	if (manifest.state != M83_STATE_PREPARED)
		return M83_ERR_CORRUPT;
	for (i = 0; i < manifest.operation_count; i++) {
		if (!manifest.backup_path[i][0] ||
		    copy_file(manifest.backup_path[i], manifest.journal_path[i]) != M83_OK)
			return M83_ERR_IO;
		unlink(manifest.backup_path[i]);
	}
	manifest.state = M83_STATE_ABORTED;
	return manifest_write(coordinator_path, &manifest);
}

int m83_read_manifest(const char *coordinator_path, uint32_t *state,
		      uint64_t *transaction_id)
{
	struct m83_manifest manifest;
	int ret;
	if (!state || !transaction_id)
		return M83_ERR_ARGUMENT;
	ret = manifest_load(coordinator_path, &manifest);
	if (ret != M83_OK)
		return ret;
	*state = manifest.state;
	*transaction_id = manifest.transaction_id;
	return M83_OK;
}
