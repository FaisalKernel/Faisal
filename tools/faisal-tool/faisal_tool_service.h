#ifndef FAISAL_TOOL_SERVICE_H
#define FAISAL_TOOL_SERVICE_H

#include <stdint.h>
#include <pthread.h>
#include "../faisal-mission/faisal_mission_service.h"

#define M99_MAX_TOOLS 32U
#define M99_MAX_NAME 64U
#define M99_MAX_DESCRIPTION 160U
#define M99_MAX_RESULT 160U
#define M99_TOOL_JOURNAL_MAGIC 0x464d3939U
#define M99_TOOL_JOURNAL_VERSION 1U
#define M99_DIGEST_SIZE FTS_DIGEST_SIZE
#define M99_TOOL_FLAG_REQUIRES_OBSERVATION (1U << 0)
#define M99_TOOL_FLAG_REQUIRES_VERIFICATION (1U << 1)
#define M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL (1U << 2)
#define M99_TOOL_FLAGS_ALL ((1U << 3) - 1)

enum m99_tool_state {
	M99_TOOL_REGISTERED = 1,
	M99_TOOL_REVOKED = 2
};

enum m99_invocation_state {
	M99_INVOCATION_ADMITTED = 1,
	M99_INVOCATION_EXECUTING = 2,
	M99_INVOCATION_COMPLETED = 3,
	M99_INVOCATION_FAILED = 4,
	M99_INVOCATION_REVOKED = 5
};

enum m99_status {
	M99_OK = 0,
	M99_ERR_ARGUMENT = -1,
	M99_ERR_IO = -2,
	M99_ERR_CORRUPT = -3,
	M99_ERR_FULL = -4,
	M99_ERR_NOT_FOUND = -5,
	M99_ERR_STATE = -6,
	M99_ERR_POLICY = -7,
	M99_ERR_AUTHORITY = -8,
	M99_ERR_REVOKED = -9,
	M99_ERR_PROVENANCE = -10,
	M99_ERR_VERIFICATION = -11,
	M99_ERR_BUDGET = -12,
	M99_ERR_APPROVAL = -13,
	M99_ERR_CONFLICT = -14
};

struct m99_tool_spec {
	uint64_t tool_id;
	uint64_t registry_generation;
	uint64_t revocation_generation;
	uint64_t cpu_cost_ns;
	uint64_t money_cost_micro;
	uint32_t operation_class;
	uint32_t resource_mask;
	uint32_t risk_class;
	uint32_t flags;
	uint32_t state;
	uint32_t reserved;
	uint8_t definition_digest[M99_DIGEST_SIZE];
	uint8_t implementation_digest[M99_DIGEST_SIZE];
	char name[M99_MAX_NAME];
	char description[M99_MAX_DESCRIPTION];
	char revocation_reason[M99_MAX_DESCRIPTION];
};

struct m99_invocation {
	uint64_t invocation_id;
	uint64_t tool_id;
	uint64_t mission_id;
	uint64_t task_id;
	uint64_t branch_id;
	uint64_t capsule_id;
	uint64_t authority_lease_id;
	uint64_t agent_id;
	uint64_t event_sequence;
	uint64_t admitted_at_ns;
	uint64_t completed_at_ns;
	uint64_t cpu_cost_ns;
	uint64_t money_cost_micro;
	uint64_t registry_generation;
	uint64_t revocation_generation;
	uint32_t state;
	uint32_t result_code;
	uint32_t verification_ok;
	uint32_t risk_class;
	uint32_t resource_mask;
	uint32_t reserved;
	uint8_t input_digest[M99_DIGEST_SIZE];
	uint8_t model_provenance_digest[M99_DIGEST_SIZE];
	uint8_t result_digest[M99_DIGEST_SIZE];
	char result[M99_MAX_RESULT];
};

struct m99_service {
	struct m98_service mission;
	int tool_fd;
	int lock_initialized;
	uint64_t next_tool_id;
	uint64_t next_invocation_id;
	uint64_t tool_sequence;
	char tool_path[FTS_MAX_JOURNAL_PATH];
	struct m99_tool_spec tools[M99_MAX_TOOLS];
	struct m99_invocation invocations[M99_MAX_TOOLS];
	size_t tool_count;
	size_t invocation_count;
	pthread_mutex_t lock;
};

int m99_open(struct m99_service *service, const char *journal_prefix,
		     int require_kernel);
void m99_close(struct m99_service *service);
int m99_replay(struct m99_service *service);
int m99_register(struct m99_service *service, const char *name,
			 const char *description, uint32_t operation_class,
			 uint32_t resource_mask, uint32_t risk_class,
			 uint32_t flags, uint64_t cpu_cost_ns,
			 uint64_t money_cost_micro,
			 const uint8_t implementation_digest[M99_DIGEST_SIZE],
			 struct m99_tool_spec *out);
int m99_revoke(struct m99_service *service, uint64_t tool_id,
		       uint64_t now_ns, const char *reason,
		       struct m99_tool_spec *out);
int m99_tool_query(const struct m99_service *service, uint64_t tool_id,
			  struct m99_tool_spec *out);
int m99_admit(struct m99_service *service, uint64_t mission_id,
		     uint64_t now_ns, const struct fts_authority_ref *authority,
		     uint64_t tool_id, const uint8_t input_digest[M99_DIGEST_SIZE],
		     struct m99_invocation *out);
int m99_execute(struct m99_service *service, uint64_t invocation_id,
		       uint64_t now_ns, struct m99_invocation *out);
int m99_complete(struct m99_service *service, uint64_t invocation_id,
			 uint64_t now_ns, uint32_t result_code,
			 uint32_t verification_ok,
			 const uint8_t result_digest[M99_DIGEST_SIZE],
			 const char *result, struct m99_invocation *out);
int m99_invocation_query(const struct m99_service *service,
				 uint64_t invocation_id, struct m99_invocation *out);
int m99_test_corrupt_tail(const struct m99_service *service);

#endif
