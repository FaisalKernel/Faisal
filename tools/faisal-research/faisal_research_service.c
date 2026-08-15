#define _GNU_SOURCE
#include "faisal_research_service.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

static uint64_t hash_text(const char *text)
{
	uint64_t hash = 1469598103934665603ULL;
	while (text && *text) {
		hash ^= (unsigned char)*text++;
		hash *= 1099511628211ULL;
	}
	return hash;
}

static int digest_text(const char *text, uint8_t digest[FMS_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	int result = -1;
	if (!text || !digest)
		return -1;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, text, strlen(text)) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
	    length == FMS_DIGEST_SIZE)
		result = 0;
	EVP_MD_CTX_free(ctx);
	return result;
}

static int source_kind_weight(uint32_t kind)
{
	switch (kind) {
	case M77_SOURCE_KIND_PRIMARY:
		return 4;
	case M77_SOURCE_KIND_OFFICIAL:
		return 3;
	case M77_SOURCE_KIND_CURATED:
		return 2;
	case M77_SOURCE_KIND_SECONDARY:
		return 1;
	default:
		return 0;
	}
}

static int activate_memory(struct fms_service *memory)
{
	struct agi_lc_agent agent;
	if (!memory || memory->kernel_fd < 0 ||
	    ioctl(memory->kernel_fd, AGI_LC_ATTACH_TASK) < 0)
		return -1;
	memset(&agent, 0, sizeof(agent));
	agent.size = sizeof(agent);
	agent.agent_id = memory->agent_id;
	agent.correlation = 77000 + memory->agent_id;
	return ioctl(memory->kernel_fd, AGI_LC_SET_AGENT, &agent);
}

static int valid_metadata(const struct m77_source *source, uint64_t now_ns)
{
	if (!source || !*source->claim || !*source->uri || !*source->content ||
	    strlen(source->claim) >= M77_MAX_CLAIM ||
	    strlen(source->uri) >= M77_MAX_URI ||
	    strlen(source->content) >= M77_MAX_CONTENT ||
	    !source_kind_weight(source->source_kind) || !source->source_rank ||
	    !source->confidence_ppm ||
	    source->confidence_ppm > AGI_LC_KNOWLEDGE_CONFIDENCE_MAX ||
	    source->knowledge.freshness_ttl_ns > AGI_LC_KNOWLEDGE_MAX_TTL_NS ||
	    (source->knowledge.publication_realtime_ns &&
	     source->knowledge.publication_realtime_ns > now_ns))
		return 0;
	return 1;
}

static struct m77_source *find_source(struct m77_service *service,
				       uint64_t source_id)
{
	uint32_t i;
	if (!service || !source_id)
		return NULL;
	for (i = 0; i < service->source_count; i++)
		if (service->sources[i].source_id == source_id)
			return &service->sources[i];
	return NULL;
}

int m77_open(struct m77_service *service, const char *journal_prefix)
{
	char browser_path[512];
	char world_path[512];
	if (!service || !journal_prefix || !*journal_prefix)
		return -1;
	memset(service, 0, sizeof(*service));
	snprintf(browser_path, sizeof(browser_path), "%s-browser", journal_prefix);
	snprintf(world_path, sizeof(world_path), "%s-world", journal_prefix);
	if (fbt_open(&service->browser, browser_path) != 0)
		return -1;
	if (fbt_browser_open(&service->browser) != 0) {
		fbt_close(&service->browser);
		return -1;
	}
	if (fws_open(&service->world, world_path) != 0) {
		fbt_close(&service->browser);
		return -1;
	}
	service->next_source_id = 1;
	return 0;
}

void m77_close(struct m77_service *service)
{
	if (!service)
		return;
	fbt_close(&service->browser);
	fws_close(&service->world);
}

int m77_collect(struct m77_service *service, const char *claim,
		const char *uri, const char *content, uint32_t source_kind,
		uint32_t source_rank, uint32_t confidence_ppm,
		uint64_t publication_realtime_ns, uint64_t freshness_ttl_ns,
		struct m77_source *out)
{
	struct m77_source source;
	struct fbt_action_request action;
	struct fbt_action_result action_result;
	struct fms_entry memory;
	uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ULL;
	int ret;
	if (!service || !claim || !uri || !content || !out ||
	    !*claim || !*uri || !*content || service->source_count >= M77_MAX_SOURCES ||
	    strlen(claim) >= M77_MAX_CLAIM || strlen(uri) >= M77_MAX_URI ||
	    strlen(content) >= M77_MAX_CONTENT || !source_kind_weight(source_kind) ||
	    !source_rank || !confidence_ppm ||
	    confidence_ppm > AGI_LC_KNOWLEDGE_CONFIDENCE_MAX ||
	    freshness_ttl_ns > AGI_LC_KNOWLEDGE_MAX_TTL_NS ||
	    (publication_realtime_ns && publication_realtime_ns > now_ns))
		return -1;
	if (activate_memory(&service->browser.memory) < 0)
		return -1;
	memset(&action, 0, sizeof(action));
	action.kind = AGI_LC_BROWSER_KIND_NAVIGATE;
	action.flags = AGI_LC_BROWSER_FLAG_SEMANTIC;
	action.page_id = service->source_count + 1;
	action.locator_hash = fbt_scope_hash(claim);
	strncpy(action.url, uri, sizeof(action.url) - 1);
	strncpy(action.content, content, sizeof(action.content) - 1);
	if (fbt_action(&service->browser, &action, &action_result) != 0 ||
	    action_result.decision != FBT_ALLOWED)
		return -1;
	memset(&source, 0, sizeof(source));
	source.source_id = service->next_source_id++;
	source.browser_action_id = action_result.action_id;
	source.browser_event_sequence = action_result.event_sequence;
	source.claim_hash = hash_text(claim);
	source.source_kind = source_kind;
	source.source_rank = source_rank;
	source.confidence_ppm = confidence_ppm;
	strncpy(source.claim, claim, sizeof(source.claim) - 1);
	strncpy(source.uri, uri, sizeof(source.uri) - 1);
	strncpy(source.content, content, sizeof(source.content) - 1);
	if (digest_text(uri, source.source_digest) < 0 ||
	    digest_text(content, source.content_digest) < 0)
		return -1;
	if (fms_put(&service->browser.memory, content, AGI_LC_MEMORY_TIER_SEMANTIC,
		    confidence_ppm, confidence_ppm, action_result.event_sequence,
		    &memory) != FMS_OK)
		return -1;
	source.memory_record_id = memory.record_id;
	memset(&source.knowledge, 0, sizeof(source.knowledge));
	source.knowledge.size = sizeof(source.knowledge);
	source.knowledge.operation = AGI_LC_KNOWLEDGE_PUBLISH;
	source.knowledge.flags = (source_kind == M77_SOURCE_KIND_PRIMARY ||
				 source_kind == M77_SOURCE_KIND_OFFICIAL) ?
				AGI_LC_KNOWLEDGE_FLAG_PRIMARY :
				AGI_LC_KNOWLEDGE_FLAG_SECONDARY;
	source.knowledge.flags |= AGI_LC_KNOWLEDGE_FLAG_INTEGRITY_MEASURED |
				AGI_LC_KNOWLEDGE_FLAG_FRESHNESS_REQUIRED;
	source.knowledge.source_id = source.source_id;
	source.knowledge.source_uri_hash = fbt_scope_hash(uri);
	source.knowledge.source_rank = source_rank;
	source.knowledge.source_kind = source_kind;
	source.knowledge.confidence_ppm = confidence_ppm;
	source.knowledge.publication_realtime_ns = publication_realtime_ns;
	source.knowledge.freshness_ttl_ns = freshness_ttl_ns;
	memcpy(source.knowledge.source_digest, source.source_digest, FMS_DIGEST_SIZE);
	memcpy(source.knowledge.content_digest, source.content_digest, FMS_DIGEST_SIZE);
	source.knowledge.correlation = 77001 + source.source_id;
	ret = ioctl(service->browser.memory.kernel_fd, AGI_LC_KNOWLEDGE,
		    &source.knowledge);
	if (ret < 0)
		return -1;
	source.knowledge_record_id = source.knowledge.record_id;
	source.provenance_sequence = source.knowledge.provenance_sequence;
	source.local_state = source.knowledge.verification_state;
	source.conflict_state = source.knowledge.conflict_state;
	source.knowledge.evidence_digest[0] = 0;
	service->sources[service->source_count++] = source;
	*out = source;
	return 0;
}

int m77_crosscheck(struct m77_service *service, uint64_t source_id,
		  uint64_t related_source_id)
{
	struct m77_source *source;
	struct m77_source *related;
	struct agi_lc_verified_knowledge check;
	int ret;
	if (!service || source_id == related_source_id ||
	    !(source = find_source(service, source_id)) ||
	    !(related = find_source(service, related_source_id)) ||
	    source->claim_hash != related->claim_hash)
		return -1;
	if (activate_memory(&service->browser.memory) < 0)
		return -1;
	memset(&check, 0, sizeof(check));
	check.size = sizeof(check);
	check.operation = AGI_LC_KNOWLEDGE_CROSSCHECK;
	check.record_id = source->knowledge_record_id;
	check.related_record_id = related->knowledge_record_id;
	check.correlation = 77020;
	ret = ioctl(service->browser.memory.kernel_fd, AGI_LC_KNOWLEDGE, &check);
	if (ret < 0 && errno != EUCLEAN)
		return -1;
	memset(&source->knowledge, 0, sizeof(source->knowledge));
	source->knowledge.size = sizeof(source->knowledge);
	source->knowledge.operation = AGI_LC_KNOWLEDGE_QUERY;
	source->knowledge.record_id = source->knowledge_record_id;
	source->knowledge.correlation = 77021;
	if (ioctl(service->browser.memory.kernel_fd, AGI_LC_KNOWLEDGE,
		  &source->knowledge) < 0)
		return -1;
	memset(&related->knowledge, 0, sizeof(related->knowledge));
	related->knowledge.size = sizeof(related->knowledge);
	related->knowledge.operation = AGI_LC_KNOWLEDGE_QUERY;
	related->knowledge.record_id = related->knowledge_record_id;
	related->knowledge.correlation = 77022;
	if (ioctl(service->browser.memory.kernel_fd, AGI_LC_KNOWLEDGE,
		  &related->knowledge) < 0)
		return -1;
	source->local_state = source->knowledge.verification_state;
	source->conflict_state = source->knowledge.conflict_state;
	source->crosscheck_count = (uint32_t)source->knowledge.crosscheck_count;
	related->local_state = related->knowledge.verification_state;
	related->conflict_state = related->knowledge.conflict_state;
	related->crosscheck_count = (uint32_t)related->knowledge.crosscheck_count;
	if (source->conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED ||
	    related->conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED) {
		service->conflict_count++;
		return 1;
	}
	return 0;
}

int m77_verify(struct m77_service *service, uint64_t source_id,
		       const uint8_t evidence_digest[FMS_DIGEST_SIZE])
{
	struct m77_source *source;
	struct agi_lc_verified_knowledge verify;
	if (!service || !evidence_digest ||
	    !(source = find_source(service, source_id)) ||
	    source->local_state == M77_CONFLICT || source->conflict_state ==
			AGI_LC_KNOWLEDGE_CONFLICT_DETECTED)
		return -1;
	if (activate_memory(&service->browser.memory) < 0)
		return -1;
	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.operation = AGI_LC_KNOWLEDGE_VERIFY;
	verify.record_id = source->knowledge_record_id;
	verify.verification_state = AGI_LC_KNOWLEDGE_VERIFY_VERIFIED;
	memcpy(verify.evidence_digest, evidence_digest, FMS_DIGEST_SIZE);
	verify.correlation = 77030;
	if (ioctl(service->browser.memory.kernel_fd, AGI_LC_KNOWLEDGE,
		  &verify) < 0)
		return -1;
	source->local_state = verify.verification_state;
	source->knowledge = verify;
	memcpy(source->evidence_digest, evidence_digest, FMS_DIGEST_SIZE);
	return 0;
}

int m77_promote_verified(struct m77_service *service, uint64_t source_id,
			 struct fws_fact *out)
{
	struct m77_source *source;
	if (!service || !out || !(source = find_source(service, source_id)) ||
	    source->local_state != M77_VERIFIED ||
	    source->conflict_state == AGI_LC_KNOWLEDGE_CONFLICT_DETECTED ||
	    source->knowledge.freshness_state != AGI_LC_KNOWLEDGE_FRESH)
		return -1;
	if (activate_memory(&service->world.memory) < 0)
		return -1;
	if (fws_add_fact(&service->world, source->claim, "verified_value",
			 source->content, source->provenance_sequence,
			 source->knowledge.freshness_ttl_ns, source->confidence_ppm,
			 out) != 0)
		return -1;
	source->promoted = 1;
	source->promoted_fact = *out;
	service->promoted_count++;
	return 0;
}

int m77_preferred(const struct m77_service *service, const char *claim,
			 struct m77_source *out)
{
	const struct m77_source *best = NULL;
	uint32_t i;
	int best_weight = -1;
	if (!service || !claim || !out || !*claim)
		return -1;
	for (i = 0; i < service->source_count; i++) {
		const struct m77_source *candidate = &service->sources[i];
		int weight;
		if (strcmp(candidate->claim, claim) ||
		    candidate->local_state == M77_REJECTED)
			continue;
		weight = source_kind_weight(candidate->source_kind);
		if (!best || weight > best_weight ||
		    (weight == best_weight && candidate->confidence_ppm > best->confidence_ppm)) {
			best = candidate;
			best_weight = weight;
		}
	}
	if (!best)
		return -1;
	*out = *best;
	return 0;
}

int m77_test_unverified_denial(struct m77_service *service,
			       uint64_t source_id)
{
	struct fws_fact fact;
	struct m77_source *source;
	if (!service || !(source = find_source(service, source_id)) ||
	    source->local_state == M77_VERIFIED)
		return -1;
	return m77_promote_verified(service, source_id, &fact) == 0 ? -1 : 0;
}

int m77_test_metadata_fuzz(const struct m77_source *valid_source)
{
	struct m77_source malformed;
	uint64_t now_ns = (uint64_t)time(NULL) * 1000000000ULL;
	unsigned int i;
	if (!valid_source || !valid_metadata(valid_source, now_ns))
		return -1;
	for (i = 0; i < 64; i++) {
		malformed = *valid_source;
		if (i % 4 == 0)
			malformed.claim[0] = '\0';
		else if (i % 4 == 1)
			malformed.content[0] = '\0';
		else if (i % 4 == 2)
			malformed.source_kind = 99;
		else
			malformed.confidence_ppm = 0;
		if (valid_metadata(&malformed, now_ns))
			return -1;
	}
	return 0;
}
