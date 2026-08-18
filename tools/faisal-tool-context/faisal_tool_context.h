#ifndef FAISAL_TOOL_CONTEXT_H
#define FAISAL_TOOL_CONTEXT_H

#include <stddef.h>
#include <stdint.h>

#define FTC_ABI_VERSION 1U
#define FTC_DIGEST_SIZE 32U
#define FTC_MAX_TOOLS 128U
#define FTC_MAX_NAME 96U
#define FTC_MAX_SCHEMA 512U
#define FTC_MAX_RESULT 4096U
#define FTC_MAX_REASON 160U
#define FTC_FLAG_VERIFIED_INPUT (1U << 0)
#define FTC_FLAG_MODEL_PROPOSAL (1U << 1)
#define FTC_FLAG_FALLBACK (1U << 2)
#define FTC_FLAGS_ALL (FTC_FLAG_VERIFIED_INPUT | FTC_FLAG_MODEL_PROPOSAL | FTC_FLAG_FALLBACK)

enum ftc_status {
	FTC_OK = 0,
	FTC_ERR_ARGUMENT = -1,
	FTC_ERR_FULL = -2,
	FTC_ERR_NOT_FOUND = -3,
	FTC_ERR_BOUNDS = -4,
	FTC_ERR_GENERATION = -5,
	FTC_ERR_TAMPER = -6,
	FTC_ERR_REPLAY = -7,
	FTC_ERR_POLICY = -8,
	FTC_ERR_CORRUPT = -9,
	FTC_ERR_OVERFLOW = -10
};

enum ftc_tool_kind {
	FTC_TOOL_FUNCTION = 1U,
	FTC_TOOL_RESOURCE = 2U,
	FTC_TOOL_PROMPT = 3U
};

struct ftc_tool {
	uint64_t tool_id;
	uint64_t generation;
	uint32_t kind;
	uint32_t capability_mask;
	uint32_t trust_level;
	uint32_t reserved;
	uint64_t definition_bytes;
	uint64_t result_bytes_hint;
	char server[FTC_MAX_NAME];
	char name[FTC_MAX_NAME];
	char schema[FTC_MAX_SCHEMA];
	uint8_t definition_digest[FTC_DIGEST_SIZE];
};

struct ftc_request {
	uint64_t request_sequence;
	uint64_t now_ns;
	uint64_t tool_generation;
	uint32_t required_capabilities;
	uint32_t maximum_tools;
	uint32_t maximum_definition_bytes;
	uint32_t maximum_result_bytes;
	uint32_t minimum_trust_level;
	uint32_t flags;
};

struct ftc_admission {
	uint64_t request_sequence;
	uint64_t tool_generation;
	uint32_t selected_count;
	uint32_t projected_definition_bytes;
	uint32_t projected_result_bytes;
	uint32_t skipped_count;
	uint32_t flags;
	uint8_t admission_digest[FTC_DIGEST_SIZE];
	uint64_t selected_ids[FTC_MAX_TOOLS];
};

struct ftc_result_projection {
	uint64_t request_sequence;
	uint64_t tool_id;
	uint64_t tool_generation;
	uint32_t original_bytes;
	uint32_t projected_bytes;
	uint32_t truncated;
	uint32_t flags;
	uint8_t original_digest[FTC_DIGEST_SIZE];
	uint8_t projected_digest[FTC_DIGEST_SIZE];
};

struct ftc_receipt {
	uint64_t request_sequence;
	uint64_t tool_generation;
	uint32_t selected_count;
	uint32_t projected_definition_bytes;
	uint32_t projected_result_bytes;
	uint32_t skipped_count;
	uint8_t admission_digest[FTC_DIGEST_SIZE];
	uint8_t receipt_digest[FTC_DIGEST_SIZE];
};

struct ftc_registry {
	struct ftc_tool tools[FTC_MAX_TOOLS];
	size_t count;
	uint64_t next_tool_id;
	uint64_t generation;
};

int ftc_init(struct ftc_registry *registry);
int ftc_register(struct ftc_registry *registry, const char *server,
		 const char *name, uint32_t kind, uint32_t capability_mask,
		 uint32_t trust_level, const char *schema,
		 uint64_t result_bytes_hint, struct ftc_tool *out);
int ftc_bump_generation(struct ftc_registry *registry);
int ftc_admit(const struct ftc_registry *registry,
	      const struct ftc_request *request, struct ftc_admission *out);
int ftc_make_receipt(const struct ftc_registry *registry,
		     const struct ftc_request *request,
		     const struct ftc_admission *admission,
		     struct ftc_receipt *out);
int ftc_verify_receipt(const struct ftc_registry *registry,
		      const struct ftc_request *request,
		      const struct ftc_admission *admission,
		      const struct ftc_receipt *receipt);
int ftc_project_result(const struct ftc_registry *registry,
		       const struct ftc_request *request, uint64_t tool_id,
		       const uint8_t *result, size_t result_bytes,
		       struct ftc_result_projection *out);
int ftc_verify_digest(const uint8_t *data, size_t length,
		      const uint8_t expected[FTC_DIGEST_SIZE]);

#endif
