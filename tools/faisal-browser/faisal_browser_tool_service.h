#ifndef FAISAL_BROWSER_TOOL_SERVICE_H
#define FAISAL_BROWSER_TOOL_SERVICE_H

#include <stdint.h>
#include "../faisal-memory/faisal_memory_service.h"

#define FBT_MAX_URL 192
#define FBT_MAX_SCOPE 64
#define FBT_MAX_CONTENT 512
#define FBT_DIGEST_SIZE FMS_DIGEST_SIZE

#define FBT_POLICY_ALLOW_NAVIGATE (1U << 0)
#define FBT_POLICY_ALLOW_TRANSFER (1U << 1)
#define FBT_POLICY_ALLOW_COORDINATE (1U << 2)
#define FBT_POLICY_REQUIRE_OPERATOR_TRANSFER (1U << 3)

enum fbt_decision {
	FBT_DENIED = 0,
	FBT_ALLOWED = 1,
	FBT_HOSTILE_CONTENT = 2,
	FBT_SCOPE_DENIED = 3,
	FBT_CANCELLED = 4
};

struct fbt_policy {
	uint32_t flags;
	uint32_t policy_generation;
	uint64_t allowed_url_hash;
	uint64_t upload_scope_hash;
	uint64_t download_scope_hash;
};

struct fbt_action_request {
	uint32_t kind;
	uint32_t flags;
	uint32_t operator_confirmed;
	uint32_t reserved;
	uint64_t page_id;
	uint64_t locator_hash;
	uint64_t input_hash;
	uint64_t observation_hash;
	uint64_t result_hash;
	uint64_t artifact_id;
	char url[FBT_MAX_URL];
	char scope[FBT_MAX_SCOPE];
	char content[FBT_MAX_CONTENT];
};

struct fbt_action_result {
	uint32_t decision;
	int32_t kernel_status;
	uint64_t action_id;
	uint64_t event_sequence;
	uint64_t memory_record_id;
	uint64_t memory_capability;
	uint64_t policy_generation;
	uint8_t content_digest[FBT_DIGEST_SIZE];
};

struct fbt_service {
	struct fms_service memory;
	struct fbt_policy policy;
	struct agi_lc_capability_grant grant;
	struct agi_lc_network_policy network;
	struct agi_lc_browser_session browser;
	uint32_t cancelled;
	uint32_t hostile_count;
	uint32_t action_count;
};

void fbt_policy_default(struct fbt_policy *policy);
uint64_t fbt_scope_hash(const char *scope);
int fbt_open(struct fbt_service *service, const char *journal_path);
void fbt_close(struct fbt_service *service);
int fbt_browser_open(struct fbt_service *service);
int fbt_action(struct fbt_service *service,
	       const struct fbt_action_request *request,
	       struct fbt_action_result *result);
int fbt_browser_close(struct fbt_service *service);
int fbt_browser_cancel(struct fbt_service *service);
int fbt_query(struct fbt_service *service,
	      struct agi_lc_browser_session *out);
int fbt_test_hostile_content(struct fbt_service *service);
int fbt_test_scope_denials(struct fbt_service *service);

#endif
