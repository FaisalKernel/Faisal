#ifndef FAISAL_RESEARCH_SERVICE_H
#define FAISAL_RESEARCH_SERVICE_H

#include <stdint.h>
#include "../faisal-browser/faisal_browser_tool_service.h"
#include "../faisal-world/faisal_world_state_service.h"

#define M77_MAX_SOURCES 32
#define M77_MAX_CLAIM 128
#define M77_MAX_URI FBT_MAX_URL
#define M77_MAX_CONTENT FBT_MAX_CONTENT
#define M77_SOURCE_KIND_PRIMARY AGI_LC_KNOWLEDGE_SOURCE_PRIMARY
#define M77_SOURCE_KIND_OFFICIAL AGI_LC_KNOWLEDGE_SOURCE_OFFICIAL
#define M77_SOURCE_KIND_CURATED AGI_LC_KNOWLEDGE_SOURCE_CURATED
#define M77_SOURCE_KIND_SECONDARY AGI_LC_KNOWLEDGE_SOURCE_SECONDARY

enum m77_local_state {
	M77_UNVERIFIED = AGI_LC_KNOWLEDGE_VERIFY_UNVERIFIED,
	M77_VERIFIED = AGI_LC_KNOWLEDGE_VERIFY_VERIFIED,
	M77_STALE = AGI_LC_KNOWLEDGE_VERIFY_STALE,
	M77_CONFLICT = AGI_LC_KNOWLEDGE_VERIFY_CONFLICT,
	M77_REJECTED = AGI_LC_KNOWLEDGE_VERIFY_REJECTED
};

struct m77_source {
	uint64_t source_id;
	uint64_t memory_record_id;
	uint64_t knowledge_record_id;
	uint64_t browser_action_id;
	uint64_t browser_event_sequence;
	uint64_t provenance_sequence;
	uint64_t claim_hash;
	uint32_t source_kind;
	uint32_t source_rank;
	uint32_t confidence_ppm;
	uint32_t local_state;
	uint32_t conflict_state;
	uint32_t crosscheck_count;
	uint32_t promoted;
	struct agi_lc_verified_knowledge knowledge;
	struct fws_fact promoted_fact;
	uint8_t source_digest[FMS_DIGEST_SIZE];
	uint8_t content_digest[FMS_DIGEST_SIZE];
	uint8_t evidence_digest[FMS_DIGEST_SIZE];
	char claim[M77_MAX_CLAIM];
	char uri[M77_MAX_URI];
	char content[M77_MAX_CONTENT];
};

struct m77_service {
	struct fbt_service browser;
	struct fws_service world;
	struct m77_source sources[M77_MAX_SOURCES];
	uint32_t source_count;
	uint32_t conflict_count;
	uint32_t promoted_count;
	uint64_t next_source_id;
};

int m77_open(struct m77_service *service, const char *journal_prefix);
void m77_close(struct m77_service *service);
int m77_collect(struct m77_service *service, const char *claim,
		const char *uri, const char *content, uint32_t source_kind,
		uint32_t source_rank, uint32_t confidence_ppm,
		uint64_t publication_realtime_ns, uint64_t freshness_ttl_ns,
		struct m77_source *out);
int m77_crosscheck(struct m77_service *service, uint64_t source_id,
		  uint64_t related_source_id);
int m77_verify(struct m77_service *service, uint64_t source_id,
		       const uint8_t evidence_digest[FMS_DIGEST_SIZE]);
int m77_promote_verified(struct m77_service *service, uint64_t source_id,
			 struct fws_fact *out);
int m77_preferred(const struct m77_service *service, const char *claim,
			 struct m77_source *out);
int m77_test_unverified_denial(struct m77_service *service,
			       uint64_t source_id);
int m77_test_metadata_fuzz(const struct m77_source *valid_source);

#endif
