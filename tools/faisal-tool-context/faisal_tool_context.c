#include "faisal_tool_context.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static int copy_text(char *dst, size_t dst_size, const char *src)
{
	size_t length;

	if (!dst || !dst_size || !src || !src[0])
		return FTC_ERR_ARGUMENT;
	length = strlen(src);
	if (length >= dst_size)
		return FTC_ERR_BOUNDS;
	memcpy(dst, src, length + 1);
	return FTC_OK;
}

static int digest_bytes(const uint8_t *data, size_t length,
			uint8_t digest[FTC_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if ((!data && length) || !digest)
		return FTC_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FTC_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    (length && EVP_DigestUpdate(ctx, data, length) != 1) ||
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FTC_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FTC_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FTC_OK;
}

static void hash_u32(EVP_MD_CTX *ctx, uint32_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_u64(EVP_MD_CTX *ctx, uint64_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_bytes(EVP_MD_CTX *ctx, const uint8_t *data, size_t length)
{
	uint32_t bounded = (uint32_t)length;

	hash_u32(ctx, bounded);
	if (length)
		(void)EVP_DigestUpdate(ctx, data, length);
}

static int digest_admission(const struct ftc_registry *registry,
			   const struct ftc_request *request,
			   const struct ftc_admission *admission,
			   uint8_t digest[FTC_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;
	uint32_t i;

	if (!registry || !request || !admission || !digest ||
	    request->request_sequence == 0 ||
	    request->tool_generation != registry->generation)
		return FTC_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FTC_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return FTC_ERR_CORRUPT;
	}
	hash_u64(ctx, request->request_sequence);
	hash_u64(ctx, request->now_ns);
	hash_u64(ctx, request->tool_generation);
	hash_u32(ctx, request->required_capabilities);
	hash_u32(ctx, request->maximum_tools);
	hash_u32(ctx, request->maximum_definition_bytes);
	hash_u32(ctx, request->maximum_result_bytes);
	hash_u32(ctx, request->minimum_trust_level);
	hash_u32(ctx, request->flags);
	hash_u32(ctx, admission->selected_count);
	hash_u32(ctx, admission->projected_definition_bytes);
	hash_u32(ctx, admission->projected_result_bytes);
	hash_u32(ctx, admission->skipped_count);
	hash_u32(ctx, admission->flags);
	for (i = 0; i < admission->selected_count; i++) {
		const struct ftc_tool *tool = NULL;
		size_t j;

		hash_u64(ctx, admission->selected_ids[i]);
		for (j = 0; j < registry->count; j++) {
			if (registry->tools[j].tool_id == admission->selected_ids[i]) {
				tool = &registry->tools[j];
				break;
			}
		}
		if (!tool || tool->generation != registry->generation) {
			EVP_MD_CTX_free(ctx);
			return FTC_ERR_GENERATION;
		}
		hash_u64(ctx, tool->generation);
		hash_u32(ctx, tool->kind);
		hash_u32(ctx, tool->capability_mask);
		hash_u32(ctx, tool->trust_level);
		hash_u64(ctx, tool->definition_bytes);
		hash_u64(ctx, tool->result_bytes_hint);
		hash_bytes(ctx, tool->definition_digest, FTC_DIGEST_SIZE);
	}
	if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FTC_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FTC_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FTC_OK;
}

static int digest_receipt(const struct ftc_request *request,
			  const struct ftc_receipt *receipt,
			  uint8_t digest[FTC_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if (!request || !receipt || !digest || request->request_sequence == 0)
		return FTC_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FTC_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return FTC_ERR_CORRUPT;
	}
	hash_u64(ctx, request->request_sequence);
	hash_u64(ctx, request->tool_generation);
	hash_u32(ctx, receipt->selected_count);
	hash_u32(ctx, receipt->projected_definition_bytes);
	hash_u32(ctx, receipt->projected_result_bytes);
	hash_u32(ctx, receipt->skipped_count);
	hash_bytes(ctx, receipt->admission_digest, FTC_DIGEST_SIZE);
	if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FTC_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FTC_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FTC_OK;
}

static const struct ftc_tool *find_tool_const(const struct ftc_registry *registry,
					      uint64_t tool_id)
{
	size_t i;

	if (!registry)
		return NULL;
	for (i = 0; i < registry->count; i++)
		if (registry->tools[i].tool_id == tool_id)
			return &registry->tools[i];
	return NULL;
}

int ftc_init(struct ftc_registry *registry)
{
	if (!registry)
		return FTC_ERR_ARGUMENT;
	memset(registry, 0, sizeof(*registry));
	registry->next_tool_id = 1;
	registry->generation = 1;
	return FTC_OK;
}

int ftc_register(struct ftc_registry *registry, const char *server,
		 const char *name, uint32_t kind, uint32_t capability_mask,
		 uint32_t trust_level, const char *schema,
		 uint64_t result_bytes_hint, struct ftc_tool *out)
{
	struct ftc_tool *tool;
	uint8_t digest[FTC_DIGEST_SIZE];
	char canonical[FTC_MAX_NAME * 2U + FTC_MAX_SCHEMA + 3U];
	int length;
	int rc;

	if (!registry || !server || !name || !schema || !out ||
	    !server[0] || !name[0] || !schema[0] ||
	    kind < FTC_TOOL_FUNCTION || kind > FTC_TOOL_PROMPT ||
	    trust_level > 1000000U || result_bytes_hint > FTC_MAX_RESULT)
		return FTC_ERR_ARGUMENT;
	if (registry->count >= FTC_MAX_TOOLS)
		return FTC_ERR_FULL;
	length = snprintf(canonical, sizeof(canonical), "%s\n%s\n%s",
			  server, name, schema);
	if (length < 0 || (size_t)length >= sizeof(canonical))
		return FTC_ERR_BOUNDS;
	rc = digest_bytes((const uint8_t *)canonical, (size_t)length, digest);
	if (rc != FTC_OK)
		return rc;
	tool = &registry->tools[registry->count++];
	memset(tool, 0, sizeof(*tool));
	tool->tool_id = registry->next_tool_id++;
	tool->generation = registry->generation;
	tool->kind = kind;
	tool->capability_mask = capability_mask;
	tool->trust_level = trust_level;
	tool->definition_bytes = (uint64_t)length;
	tool->result_bytes_hint = result_bytes_hint;
	memcpy(tool->definition_digest, digest, FTC_DIGEST_SIZE);
	if (copy_text(tool->server, sizeof(tool->server), server) != FTC_OK ||
	    copy_text(tool->name, sizeof(tool->name), name) != FTC_OK ||
	    copy_text(tool->schema, sizeof(tool->schema), schema) != FTC_OK) {
		registry->count--;
		return FTC_ERR_BOUNDS;
	}
	*out = *tool;
	return FTC_OK;
}

int ftc_bump_generation(struct ftc_registry *registry)
{
	size_t i;

	if (!registry || registry->generation == UINT64_MAX)
		return FTC_ERR_ARGUMENT;
	registry->generation++;
	for (i = 0; i < registry->count; i++)
		registry->tools[i].generation = registry->generation;
	return FTC_OK;
}

int ftc_admit(const struct ftc_registry *registry,
	      const struct ftc_request *request, struct ftc_admission *out)
{
	uint64_t definition_total = 0;
	uint64_t result_total = 0;
	size_t i;
	uint32_t selected = 0;
	uint32_t skipped = 0;
	int rc;

	if (!registry || !request || !out || request->request_sequence == 0 ||
	    request->tool_generation != registry->generation ||
	    request->maximum_tools == 0 || request->maximum_tools > FTC_MAX_TOOLS ||
	    request->maximum_definition_bytes == 0 ||
	    request->maximum_result_bytes == 0 ||
	    (request->flags & ~FTC_FLAGS_ALL))
		return FTC_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->request_sequence = request->request_sequence;
	out->tool_generation = request->tool_generation;
	out->flags = request->flags & FTC_FLAGS_ALL;
	for (i = 0; i < registry->count; i++) {
		const struct ftc_tool *tool = &registry->tools[i];
		uint64_t next_definition;
		uint64_t next_result;

		if (tool->generation != registry->generation ||
		    (tool->capability_mask & request->required_capabilities) !=
			request->required_capabilities ||
		    tool->trust_level < request->minimum_trust_level) {
			skipped++;
			continue;
		}
		if (selected >= request->maximum_tools) {
			skipped++;
			continue;
		}
		next_definition = definition_total + tool->definition_bytes;
		next_result = result_total + tool->result_bytes_hint;
		if (next_definition > request->maximum_definition_bytes ||
		    next_result > request->maximum_result_bytes) {
			skipped++;
			continue;
		}
		out->selected_ids[selected++] = tool->tool_id;
		definition_total = next_definition;
		result_total = next_result;
	}
	if (!selected)
		return FTC_ERR_POLICY;
	out->selected_count = selected;
	out->projected_definition_bytes = (uint32_t)definition_total;
	out->projected_result_bytes = (uint32_t)result_total;
	out->skipped_count = skipped;
	rc = digest_admission(registry, request, out, out->admission_digest);
	return rc;
}

int ftc_make_receipt(const struct ftc_registry *registry,
		     const struct ftc_request *request,
		     const struct ftc_admission *admission,
		     struct ftc_receipt *out)
{
	int rc;

	if (!registry || !request || !admission || !out ||
	    request->request_sequence != admission->request_sequence ||
	    request->tool_generation != admission->tool_generation)
		return FTC_ERR_ARGUMENT;
	memset(out, 0, sizeof(*out));
	out->request_sequence = admission->request_sequence;
	out->tool_generation = admission->tool_generation;
	out->selected_count = admission->selected_count;
	out->projected_definition_bytes = admission->projected_definition_bytes;
	out->projected_result_bytes = admission->projected_result_bytes;
	out->skipped_count = admission->skipped_count;
	memcpy(out->admission_digest, admission->admission_digest,
	       FTC_DIGEST_SIZE);
	rc = digest_receipt(request, out, out->receipt_digest);
	return rc;
}

int ftc_verify_receipt(const struct ftc_registry *registry,
		      const struct ftc_request *request,
		      const struct ftc_admission *admission,
		      const struct ftc_receipt *receipt)
{
	struct ftc_receipt expected;
	uint8_t admission_digest[FTC_DIGEST_SIZE];
	int rc;

	if (!registry || !request || !admission || !receipt)
		return FTC_ERR_ARGUMENT;
	if (request->request_sequence != receipt->request_sequence ||
	    request->tool_generation != registry->generation ||
	    receipt->tool_generation != registry->generation)
		return FTC_ERR_GENERATION;
	if (receipt->selected_count != admission->selected_count ||
	    receipt->projected_definition_bytes != admission->projected_definition_bytes ||
	    receipt->projected_result_bytes != admission->projected_result_bytes ||
	    receipt->skipped_count != admission->skipped_count)
		return FTC_ERR_TAMPER;
	rc = digest_admission(registry, request, admission, admission_digest);
	if (rc != FTC_OK)
		return rc;
	if (memcmp(admission_digest, admission->admission_digest,
		   FTC_DIGEST_SIZE) != 0 ||
	    memcmp(admission_digest, receipt->admission_digest,
		   FTC_DIGEST_SIZE) != 0)
		return FTC_ERR_TAMPER;
	rc = ftc_make_receipt(registry, request, admission, &expected);
	if (rc != FTC_OK)
		return rc;
	if (memcmp(expected.receipt_digest, receipt->receipt_digest,
		   FTC_DIGEST_SIZE) != 0)
		return FTC_ERR_TAMPER;
	return FTC_OK;
}

int ftc_project_result(const struct ftc_registry *registry,
		       const struct ftc_request *request, uint64_t tool_id,
		       const uint8_t *result, size_t result_bytes,
		       struct ftc_result_projection *out)
{
	const struct ftc_tool *tool;
	size_t projected;
	int rc;

	if (!registry || !request || !result || !out || result_bytes > FTC_MAX_RESULT ||
	    request->request_sequence == 0 || request->maximum_result_bytes == 0)
		return FTC_ERR_ARGUMENT;
	tool = find_tool_const(registry, tool_id);
	if (!tool)
		return FTC_ERR_NOT_FOUND;
	if (tool->generation != registry->generation ||
	    request->tool_generation != registry->generation)
		return FTC_ERR_GENERATION;
	projected = result_bytes;
	if (projected > request->maximum_result_bytes)
		projected = request->maximum_result_bytes;
	memset(out, 0, sizeof(*out));
	out->request_sequence = request->request_sequence;
	out->tool_id = tool_id;
	out->tool_generation = tool->generation;
	out->original_bytes = (uint32_t)result_bytes;
	out->projected_bytes = (uint32_t)projected;
	out->truncated = projected != result_bytes;
	out->flags = request->flags & FTC_FLAGS_ALL;
	rc = digest_bytes(result, result_bytes, out->original_digest);
	if (rc != FTC_OK)
		return rc;
	return digest_bytes(result, projected, out->projected_digest);
}

int ftc_verify_digest(const uint8_t *data, size_t length,
		      const uint8_t expected[FTC_DIGEST_SIZE])
{
	uint8_t actual[FTC_DIGEST_SIZE];
	int rc;

	if (!expected)
		return FTC_ERR_ARGUMENT;
	rc = digest_bytes(data, length, actual);
	if (rc != FTC_OK)
		return rc;
	return memcmp(actual, expected, FTC_DIGEST_SIZE) == 0 ?
		FTC_OK : FTC_ERR_TAMPER;
}
