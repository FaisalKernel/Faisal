#define _GNU_SOURCE

#include "faisal_tool_service.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define M99_RECORD_TOOL 1U
#define M99_RECORD_INVOCATION 2U
#define M99_MAX_RISK 100U

enum m99_reason {
	M99_REASON_NONE = 0,
	M99_REASON_REVOKED = 1,
	M99_REASON_VERIFICATION = 2,
	M99_REASON_POLICY = 3
};

struct m99_disk_header {
	uint32_t magic;
	uint32_t version;
	uint32_t header_size;
	uint32_t record_size;
	uint64_t sequence;
	uint32_t kind;
	uint32_t reserved;
	uint8_t record_digest[M99_DIGEST_SIZE];
};

struct m99_record {
	uint32_t kind;
	uint32_t reserved;
	union {
		struct m99_tool_spec tool;
		struct m99_invocation invocation;
	} value;
};

static int write_all(int fd, const void *buffer, size_t length)
{
	const unsigned char *cursor = buffer;

	while (length) {
		ssize_t written = write(fd, cursor, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return M99_ERR_IO;
		}
		if (!written)
			return M99_ERR_IO;
		cursor += (size_t)written;
		length -= (size_t)written;
	}
	return M99_OK;
}

static int read_exact_or_eof(int fd, void *buffer, size_t length)
{
	unsigned char *cursor = buffer;
	size_t total = 0;

	while (total < length) {
		ssize_t received = read(fd, cursor + total, length - total);

		if (received < 0) {
			if (errno == EINTR)
				continue;
			return M99_ERR_IO;
		}
		if (!received)
			return total ? M99_ERR_CORRUPT : 1;
		total += (size_t)received;
	}
	return M99_OK;
}

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[M99_DIGEST_SIZE])
{
	EVP_MD_CTX *context = EVP_MD_CTX_new();
	unsigned int output_length = 0;
	int result = M99_ERR_IO;

	if (!context || !data || !digest)
		goto out;
	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(context, data, length) == 1 &&
	    EVP_DigestFinal_ex(context, digest, &output_length) == 1 &&
	    output_length == M99_DIGEST_SIZE)
		result = M99_OK;
out:
	EVP_MD_CTX_free(context);
	return result;
}

static int nonzero_digest(const uint8_t digest[M99_DIGEST_SIZE])
{
	unsigned int index;

	if (!digest)
		return 0;
	for (index = 0; index < M99_DIGEST_SIZE; index++)
		if (digest[index])
			return 1;
	return 0;
}

static int copy_text(char *destination, size_t destination_size,
			     const char *source, int allow_empty)
{
	size_t length;

	if (!destination || !destination_size || !source)
		return M99_ERR_ARGUMENT;
	length = strnlen(source, destination_size);
	if ((!allow_empty && !length) || length >= destination_size)
		return M99_ERR_ARGUMENT;
	memcpy(destination, source, length + 1);
	return M99_OK;
}

static int digest_tool(const struct m99_tool_spec *tool,
			       uint8_t digest[M99_DIGEST_SIZE])
{
	struct m99_tool_spec canonical;

	if (!tool)
		return M99_ERR_ARGUMENT;
	canonical = *tool;
	memset(canonical.definition_digest, 0, sizeof(canonical.definition_digest));
	return digest_bytes(&canonical, sizeof(canonical), digest);
}

static int digest_record(const struct m99_record *record,
			 uint8_t digest[M99_DIGEST_SIZE])
{
	return digest_bytes(record, sizeof(*record), digest);
}

static int lock_service(struct m99_service *service)
{
	if (!service || !service->lock_initialized)
		return M99_ERR_ARGUMENT;
	return pthread_mutex_lock(&service->lock) == 0 ? M99_OK : M99_ERR_STATE;
}

static void unlock_service(struct m99_service *service)
{
	(void)pthread_mutex_unlock(&service->lock);
}

static struct m99_tool_spec *find_tool(struct m99_service *service,
					       uint64_t tool_id)
{
	size_t index;

	for (index = 0; index < service->tool_count; index++)
		if (service->tools[index].tool_id == tool_id)
			return &service->tools[index];
	return NULL;
}

static const struct m99_tool_spec *find_tool_const(const struct m99_service *service,
						   uint64_t tool_id)
{
	size_t index;

	for (index = 0; index < service->tool_count; index++)
		if (service->tools[index].tool_id == tool_id)
			return &service->tools[index];
	return NULL;
}

static struct m99_invocation *find_invocation(struct m99_service *service,
						 uint64_t invocation_id)
{
	size_t index;

	for (index = 0; index < service->invocation_count; index++)
		if (service->invocations[index].invocation_id == invocation_id)
			return &service->invocations[index];
	return NULL;
}

static const struct m99_invocation *find_invocation_const(
		const struct m99_service *service, uint64_t invocation_id)
{
	size_t index;

	for (index = 0; index < service->invocation_count; index++)
		if (service->invocations[index].invocation_id == invocation_id)
			return &service->invocations[index];
	return NULL;
}

static int append_record(struct m99_service *service, uint32_t kind,
				 const void *value)
{
	struct m99_disk_header header;
	struct m99_record record;
	uint8_t digest[M99_DIGEST_SIZE];
	uint64_t sequence;
	int result;

	if (!service || service->tool_fd < 0 || !value ||
	    (kind != M99_RECORD_TOOL && kind != M99_RECORD_INVOCATION))
		return M99_ERR_ARGUMENT;
	memset(&record, 0, sizeof(record));
	record.kind = kind;
	if (kind == M99_RECORD_TOOL)
		record.value.tool = *(const struct m99_tool_spec *)value;
	else
		record.value.invocation = *(const struct m99_invocation *)value;
	result = digest_record(&record, digest);
	if (result != M99_OK)
		return result;
	sequence = service->tool_sequence + 1;
	memset(&header, 0, sizeof(header));
	header.magic = M99_TOOL_JOURNAL_MAGIC;
	header.version = M99_TOOL_JOURNAL_VERSION;
	header.header_size = sizeof(header);
	header.record_size = sizeof(header) + sizeof(record);
	header.sequence = sequence;
	header.kind = kind;
	memcpy(header.record_digest, digest, sizeof(header.record_digest));
	result = write_all(service->tool_fd, &header, sizeof(header));
	if (result == M99_OK)
		result = write_all(service->tool_fd, &record, sizeof(record));
	if (result == M99_OK && fdatasync(service->tool_fd) < 0)
		result = M99_ERR_IO;
	if (result == M99_OK)
		service->tool_sequence = sequence;
	return result;
}

static int apply_tool(struct m99_service *service,
			      const struct m99_tool_spec *tool)
{
	struct m99_tool_spec *existing = find_tool(service, tool->tool_id);

	if (existing) {
		*existing = *tool;
		return M99_OK;
	}
	if (service->tool_count >= M99_MAX_TOOLS)
		return M99_ERR_FULL;
	service->tools[service->tool_count++] = *tool;
	return M99_OK;
}

static int apply_invocation(struct m99_service *service,
				const struct m99_invocation *invocation)
{
	struct m99_invocation *existing = find_invocation(service,
							 invocation->invocation_id);

	if (existing) {
		*existing = *invocation;
		return M99_OK;
	}
	if (service->invocation_count >= M99_MAX_TOOLS)
		return M99_ERR_FULL;
	service->invocations[service->invocation_count++] = *invocation;
	return M99_OK;
}

static int replay_unlocked(struct m99_service *service)
{
	struct m99_disk_header header;
	uint64_t last_sequence = 0;
	int result;

	if (lseek(service->tool_fd, 0, SEEK_SET) < 0)
		return M99_ERR_IO;
	service->tool_count = 0;
	service->invocation_count = 0;
	service->tool_sequence = 0;
	service->next_tool_id = 1;
	service->next_invocation_id = 1;
	for (;;) {
		struct m99_record record;
		uint8_t digest[M99_DIGEST_SIZE];

		result = read_exact_or_eof(service->tool_fd, &header, sizeof(header));
		if (result == 1)
			break;
		if (result != M99_OK || header.magic != M99_TOOL_JOURNAL_MAGIC ||
		    header.version != M99_TOOL_JOURNAL_VERSION ||
		    header.header_size != sizeof(header) ||
		    header.record_size != sizeof(header) + sizeof(record) ||
		    header.sequence <= last_sequence ||
		    (header.kind != M99_RECORD_TOOL && header.kind != M99_RECORD_INVOCATION))
			return M99_ERR_CORRUPT;
		result = read_exact_or_eof(service->tool_fd, &record, sizeof(record));
		if (result != M99_OK || record.kind != header.kind ||
		    digest_record(&record, digest) != M99_OK ||
		    memcmp(digest, header.record_digest, sizeof(digest)) != 0)
			return M99_ERR_CORRUPT;
		if (record.kind == M99_RECORD_TOOL) {
			const struct m99_tool_spec *tool = &record.value.tool;

			if (!tool->tool_id || !tool->registry_generation ||
			    !tool->revocation_generation ||
			    tool->state < M99_TOOL_REGISTERED ||
			    tool->state > M99_TOOL_REVOKED ||
			    tool->operation_class > AGI_LC_INTENT_OP_MAX ||
			    !tool->operation_class || !tool->resource_mask ||
			    !tool->risk_class || tool->risk_class > M99_MAX_RISK ||
			    tool->flags & ~M99_TOOL_FLAGS_ALL ||
			    !nonzero_digest(tool->definition_digest) ||
			    !nonzero_digest(tool->implementation_digest) ||
			    apply_tool(service, tool) != M99_OK)
				return M99_ERR_CORRUPT;
			if (tool->tool_id >= service->next_tool_id)
				service->next_tool_id = tool->tool_id + 1;
		} else {
			const struct m99_invocation *invocation =
				&record.value.invocation;

			if (!invocation->invocation_id || !invocation->tool_id ||
			    !invocation->mission_id || !invocation->task_id ||
			    invocation->state < M99_INVOCATION_ADMITTED ||
			    invocation->state > M99_INVOCATION_REVOKED ||
			    !nonzero_digest(invocation->input_digest) ||
			    !nonzero_digest(invocation->model_provenance_digest) ||
			    apply_invocation(service, invocation) != M99_OK)
				return M99_ERR_CORRUPT;
			if (invocation->invocation_id >= service->next_invocation_id)
				service->next_invocation_id = invocation->invocation_id + 1;
		}
		last_sequence = header.sequence;
	}
	service->tool_sequence = last_sequence;
	return lseek(service->tool_fd, 0, SEEK_END) < 0 ? M99_ERR_IO : M99_OK;
}

int m99_replay(struct m99_service *service)
{
	int result;

	if (!service)
		return M99_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	result = replay_unlocked(service);
	unlock_service(service);
	return result;
}

int m99_open(struct m99_service *service, const char *journal_prefix,
		     int require_kernel)
{
	int result;

	if (!service || !journal_prefix || !*journal_prefix)
		return M99_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->tool_fd = -1;
	result = m98_open(&service->mission, journal_prefix, require_kernel);
	if (result != M98_OK)
		return result;
	if (snprintf(service->tool_path, sizeof(service->tool_path), "%s.tools",
		     journal_prefix) >= (int)sizeof(service->tool_path)) {
		m98_close(&service->mission);
		return M99_ERR_ARGUMENT;
	}
	service->tool_fd = open(service->tool_path, O_RDWR | O_CREAT | O_APPEND,
			0600);
	if (service->tool_fd < 0) {
		m98_close(&service->mission);
		return M99_ERR_IO;
	}
	if (pthread_mutex_init(&service->lock, NULL) != 0) {
		close(service->tool_fd);
		service->tool_fd = -1;
		m98_close(&service->mission);
		return M99_ERR_STATE;
	}
	service->lock_initialized = 1;
	service->next_tool_id = 1;
	service->next_invocation_id = 1;
	result = replay_unlocked(service);
	if (result != M99_OK) {
		pthread_mutex_destroy(&service->lock);
		service->lock_initialized = 0;
		close(service->tool_fd);
		service->tool_fd = -1;
		m98_close(&service->mission);
		return result;
	}
	return M99_OK;
}

void m99_close(struct m99_service *service)
{
	if (!service)
		return;
	if (service->lock_initialized) {
		(void)pthread_mutex_lock(&service->lock);
		if (service->tool_fd >= 0) {
			(void)fdatasync(service->tool_fd);
			close(service->tool_fd);
			service->tool_fd = -1;
		}
		(void)pthread_mutex_unlock(&service->lock);
		pthread_mutex_destroy(&service->lock);
		service->lock_initialized = 0;
	} else if (service->tool_fd >= 0) {
		close(service->tool_fd);
		service->tool_fd = -1;
	}
	m98_close(&service->mission);
}

static int validate_tool_request(const char *name, const char *description,
					 uint32_t operation_class,
					 uint32_t resource_mask, uint32_t risk_class,
					 uint32_t flags, uint64_t cpu_cost_ns,
					 uint64_t money_cost_micro,
					 const uint8_t implementation_digest[M99_DIGEST_SIZE])
{
	if (!name || !description || !*name || !*description ||
	    operation_class == 0 || operation_class > AGI_LC_INTENT_OP_MAX ||
	    !resource_mask || !risk_class || risk_class > M99_MAX_RISK ||
	    flags & ~M99_TOOL_FLAGS_ALL || !cpu_cost_ns ||
	    money_cost_micro == UINT64_MAX || !nonzero_digest(implementation_digest))
		return M99_ERR_ARGUMENT;
	if (strnlen(name, M99_MAX_NAME) >= M99_MAX_NAME ||
	    strnlen(description, M99_MAX_DESCRIPTION) >= M99_MAX_DESCRIPTION)
		return M99_ERR_ARGUMENT;
	return M99_OK;
}

int m99_register(struct m99_service *service, const char *name,
			 const char *description, uint32_t operation_class,
			 uint32_t resource_mask, uint32_t risk_class,
			 uint32_t flags, uint64_t cpu_cost_ns,
			 uint64_t money_cost_micro,
			 const uint8_t implementation_digest[M99_DIGEST_SIZE],
			 struct m99_tool_spec *out)
{
	struct m99_tool_spec tool;
	size_t index;
	int result;

	result = validate_tool_request(name, description, operation_class,
				       resource_mask, risk_class, flags, cpu_cost_ns,
				       money_cost_micro, implementation_digest);
	if (result != M99_OK || !service || !out)
		return result != M99_OK ? result : M99_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	for (index = 0; index < service->tool_count; index++)
		if (!strcmp(service->tools[index].name, name)) {
			result = M99_ERR_CONFLICT;
			goto out_unlock;
		}
	if (service->tool_count >= M99_MAX_TOOLS) {
		result = M99_ERR_FULL;
		goto out_unlock;
	}
	memset(&tool, 0, sizeof(tool));
	tool.tool_id = service->next_tool_id++;
	tool.registry_generation = service->tool_sequence + 1;
	tool.revocation_generation = 1;
	tool.operation_class = operation_class;
	tool.resource_mask = resource_mask;
	tool.risk_class = risk_class;
	tool.flags = flags;
	tool.state = M99_TOOL_REGISTERED;
	tool.cpu_cost_ns = cpu_cost_ns;
	tool.money_cost_micro = money_cost_micro;
	memcpy(tool.implementation_digest, implementation_digest,
	       sizeof(tool.implementation_digest));
	result = copy_text(tool.name, sizeof(tool.name), name, 0);
	if (result == M99_OK)
		result = copy_text(tool.description, sizeof(tool.description),
				   description, 0);
	if (result == M99_OK)
		result = digest_tool(&tool, tool.definition_digest);
	if (result == M99_OK)
		result = append_record(service, M99_RECORD_TOOL, &tool);
	if (result == M99_OK) {
		service->tools[service->tool_count++] = tool;
		*out = tool;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m99_revoke(struct m99_service *service, uint64_t tool_id,
		       uint64_t now_ns, const char *reason,
		       struct m99_tool_spec *out)
{
	struct m99_tool_spec revoked;
	struct m99_tool_spec *existing;
	int result;

	(void)now_ns;
	if (!service || !out || !reason || !*reason)
		return M99_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	existing = find_tool(service, tool_id);
	if (!existing) {
		result = M99_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (existing->state == M99_TOOL_REVOKED) {
		result = M99_ERR_REVOKED;
		goto out_unlock;
	}
	revoked = *existing;
	revoked.state = M99_TOOL_REVOKED;
	revoked.revocation_generation++;
	result = copy_text(revoked.revocation_reason,
			   sizeof(revoked.revocation_reason), reason, 0);
	if (result == M99_OK)
		result = digest_tool(&revoked, revoked.definition_digest);
	if (result == M99_OK)
		result = append_record(service, M99_RECORD_TOOL, &revoked);
	if (result == M99_OK) {
		*existing = revoked;
		*out = revoked;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m99_tool_query(const struct m99_service *service, uint64_t tool_id,
			  struct m99_tool_spec *out)
{
	const struct m99_tool_spec *tool;
	struct m99_service *mutable_service = (struct m99_service *)service;
	int result;

	if (!service || !out)
		return M99_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M99_OK)
		return result;
	tool = find_tool_const(service, tool_id);
	if (!tool)
		result = M99_ERR_NOT_FOUND;
	else
		*out = *tool;
	unlock_service(mutable_service);
	return result;
}

static int authority_matches_tool(const struct fts_authority_ref *authority,
					  const struct m99_tool_spec *tool)
{
	if (!authority || !tool || !authority->lease_id || !authority->grant_id ||
	    !authority->grant_capability || !authority->agent_id ||
	    !authority->agent_capability || !authority->operation_class ||
	    authority->operation_class != tool->operation_class ||
	    (authority->resource_mask & tool->resource_mask) != tool->resource_mask ||
	    !nonzero_digest(authority->intent_digest))
		return 0;
	return 1;
}

int m99_admit(struct m99_service *service, uint64_t mission_id,
		     uint64_t now_ns, const struct fts_authority_ref *authority,
		     uint64_t tool_id, const uint8_t input_digest[M99_DIGEST_SIZE],
		     struct m99_invocation *out)
{
	struct m98_mission mission;
	struct m99_tool_spec *tool;
	struct m99_invocation invocation;
	int result;

	if (!service || !authority || !input_digest || !out ||
	    !nonzero_digest(input_digest))
		return M99_ERR_ARGUMENT;
	result = m98_query(&service->mission, mission_id, &mission);
	if (result != M98_OK)
		return M99_ERR_NOT_FOUND;
	if (mission.state != M98_MISSION_EXECUTION_PENDING || !mission.branch_id ||
	    mission.step >= mission.max_steps)
		return M99_ERR_STATE;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	tool = find_tool(service, tool_id);
	if (!tool) {
		result = M99_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (tool->state != M99_TOOL_REGISTERED) {
		result = M99_ERR_REVOKED;
		goto out_unlock;
	}
	if (tool->risk_class > mission.risk_ceiling) {
		result = M99_ERR_POLICY;
		goto out_unlock;
	}
	if ((tool->flags & M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL) &&
	    (!mission.supervisor_nonce || !mission.operator_nonce)) {
		result = M99_ERR_APPROVAL;
		goto out_unlock;
	}
	if (!authority_matches_tool(authority, tool)) {
		result = M99_ERR_AUTHORITY;
		goto out_unlock;
	}
	if (tool->cpu_cost_ns > mission.cpu_budget_ns -
	    (mission.consumed_cpu_ns > mission.cpu_budget_ns ?
	     mission.cpu_budget_ns : mission.consumed_cpu_ns) ||
	    tool->money_cost_micro > mission.money_budget_micro -
	    (mission.consumed_money_micro > mission.money_budget_micro ?
	     mission.money_budget_micro : mission.consumed_money_micro)) {
		result = M99_ERR_BUDGET;
		goto out_unlock;
	}
	if (service->invocation_count >= M99_MAX_TOOLS) {
		result = M99_ERR_FULL;
		goto out_unlock;
	}
	memset(&invocation, 0, sizeof(invocation));
	invocation.invocation_id = service->next_invocation_id++;
	invocation.tool_id = tool->tool_id;
	invocation.mission_id = mission.mission_id;
	invocation.task_id = mission.task_id;
	invocation.branch_id = mission.branch_id;
	invocation.capsule_id = mission.capsule_id;
	invocation.authority_lease_id = authority->lease_id;
	invocation.agent_id = authority->agent_id;
	invocation.event_sequence = mission.event_sequence;
	invocation.admitted_at_ns = now_ns;
	invocation.registry_generation = tool->registry_generation;
	invocation.revocation_generation = tool->revocation_generation;
	invocation.cpu_cost_ns = tool->cpu_cost_ns;
	invocation.money_cost_micro = tool->money_cost_micro;
	invocation.risk_class = tool->risk_class;
	invocation.resource_mask = tool->resource_mask;
	invocation.state = M99_INVOCATION_ADMITTED;
	memcpy(invocation.input_digest, input_digest,
	       sizeof(invocation.input_digest));
	memcpy(invocation.model_provenance_digest, mission.model_provenance_digest,
	       sizeof(invocation.model_provenance_digest));
	if (!nonzero_digest(invocation.model_provenance_digest)) {
		result = M99_ERR_PROVENANCE;
		goto out_unlock;
	}
	result = append_record(service, M99_RECORD_INVOCATION, &invocation);
	if (result == M99_OK) {
		service->invocations[service->invocation_count++] = invocation;
		*out = invocation;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m99_execute(struct m99_service *service, uint64_t invocation_id,
		       uint64_t now_ns, struct m99_invocation *out)
{
	struct m99_invocation *invocation;
	struct m99_tool_spec *tool;
	struct m99_invocation updated;
	int result;

	(void)now_ns;
	if (!service || !out)
		return M99_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	invocation = find_invocation(service, invocation_id);
	if (!invocation) {
		result = M99_ERR_NOT_FOUND;
		goto out_unlock;
	}
	tool = find_tool(service, invocation->tool_id);
	if (!tool || tool->state != M99_TOOL_REGISTERED ||
	    tool->revocation_generation != invocation->revocation_generation) {
		updated = *invocation;
		updated.state = M99_INVOCATION_REVOKED;
		result = append_record(service, M99_RECORD_INVOCATION, &updated);
		if (result == M99_OK) {
			*invocation = updated;
			*out = updated;
		}
		result = M99_ERR_REVOKED;
		goto out_unlock;
	}
	if (invocation->state != M99_INVOCATION_ADMITTED) {
		result = M99_ERR_STATE;
		goto out_unlock;
	}
	updated = *invocation;
	updated.state = M99_INVOCATION_EXECUTING;
	result = append_record(service, M99_RECORD_INVOCATION, &updated);
	if (result == M99_OK) {
		*invocation = updated;
		*out = updated;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m99_complete(struct m99_service *service, uint64_t invocation_id,
			 uint64_t now_ns, uint32_t result_code,
			 uint32_t verification_ok,
			 const uint8_t result_digest[M99_DIGEST_SIZE],
			 const char *result_text, struct m99_invocation *out)
{
	struct m99_invocation *invocation;
	struct m99_tool_spec *tool;
	struct m99_invocation updated;
	struct m98_mission completed_mission;
	int result;
	int mission_result;

	if (!service || !result_digest || !result_text || !out ||
	    !nonzero_digest(result_digest) ||
	    strnlen(result_text, M99_MAX_RESULT) >= M99_MAX_RESULT)
		return M99_ERR_ARGUMENT;
	result = lock_service(service);
	if (result != M99_OK)
		return result;
	invocation = find_invocation(service, invocation_id);
	if (!invocation) {
		result = M99_ERR_NOT_FOUND;
		goto out_unlock;
	}
	if (invocation->state != M99_INVOCATION_EXECUTING) {
		result = M99_ERR_STATE;
		goto out_unlock;
	}
	tool = find_tool(service, invocation->tool_id);
	if (!tool || tool->state != M99_TOOL_REGISTERED ||
	    tool->revocation_generation != invocation->revocation_generation) {
		updated = *invocation;
		updated.state = M99_INVOCATION_REVOKED;
		result = append_record(service, M99_RECORD_INVOCATION, &updated);
		if (result == M99_OK) {
			*invocation = updated;
			*out = updated;
		}
		result = M99_ERR_REVOKED;
		goto out_unlock;
	}
	if ((tool->flags & M99_TOOL_FLAG_REQUIRES_VERIFICATION) && !verification_ok) {
		updated = *invocation;
		updated.state = M99_INVOCATION_FAILED;
		updated.result_code = result_code;
		updated.verification_ok = verification_ok;
		updated.completed_at_ns = now_ns;
		(void)copy_text(updated.result, sizeof(updated.result), result_text, 1);
		memcpy(updated.result_digest, result_digest, sizeof(updated.result_digest));
		result = append_record(service, M99_RECORD_INVOCATION, &updated);
		if (result == M99_OK) {
			*invocation = updated;
			*out = updated;
		}
		result = M99_ERR_VERIFICATION;
		goto out_unlock;
	}
	if (result_code != 0 || !verification_ok) {
		updated = *invocation;
		updated.state = M99_INVOCATION_FAILED;
		updated.result_code = result_code;
		updated.verification_ok = verification_ok;
		updated.completed_at_ns = now_ns;
		(void)copy_text(updated.result, sizeof(updated.result), result_text, 1);
		memcpy(updated.result_digest, result_digest, sizeof(updated.result_digest));
		result = append_record(service, M99_RECORD_INVOCATION, &updated);
		if (result == M99_OK) {
			*invocation = updated;
			*out = updated;
		}
		result = M99_ERR_VERIFICATION;
		goto out_unlock;
	}
	mission_result = m98_execute_result(&service->mission, invocation->mission_id,
				now_ns, tool->cpu_cost_ns, tool->money_cost_micro,
				M98_DECISION_CONTINUE, 1, result_text, &completed_mission);
	if (mission_result != M98_OK) {
		result = mission_result == M98_ERR_STALE ? M99_ERR_STATE :
			M99_ERR_VERIFICATION;
		goto out_unlock;
	}
	updated = *invocation;
	updated.state = M99_INVOCATION_COMPLETED;
	updated.result_code = result_code;
	updated.verification_ok = verification_ok;
	updated.completed_at_ns = now_ns;
	memcpy(updated.result_digest, result_digest, sizeof(updated.result_digest));
	result = copy_text(updated.result, sizeof(updated.result), result_text, 1);
	if (result == M99_OK)
		result = append_record(service, M99_RECORD_INVOCATION, &updated);
	if (result == M99_OK) {
		*invocation = updated;
		*out = updated;
	}
out_unlock:
	unlock_service(service);
	return result;
}

int m99_invocation_query(const struct m99_service *service,
				uint64_t invocation_id, struct m99_invocation *out)
{
	const struct m99_invocation *invocation;
	struct m99_service *mutable_service = (struct m99_service *)service;
	int result;

	if (!service || !out)
		return M99_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M99_OK)
		return result;
	invocation = find_invocation_const(service, invocation_id);
	if (!invocation)
		result = M99_ERR_NOT_FOUND;
	else
		*out = *invocation;
	unlock_service(mutable_service);
	return result;
}

int m99_test_corrupt_tail(const struct m99_service *service)
{
	const struct m99_service *const_service = service;
	struct m99_service *mutable_service = (struct m99_service *)const_service;
	unsigned char corrupt = 0xa5;
	int result;

	if (!service)
		return M99_ERR_ARGUMENT;
	result = lock_service(mutable_service);
	if (result != M99_OK)
		return result;
	if (write(mutable_service->tool_fd, &corrupt, sizeof(corrupt)) !=
	    (ssize_t)sizeof(corrupt))
		result = M99_ERR_IO;
	else if (fdatasync(mutable_service->tool_fd) < 0)
		result = M99_ERR_IO;
	else
		result = M99_OK;
	unlock_service(mutable_service);
	return result;
}
