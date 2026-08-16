#define _GNU_SOURCE
#include "../../faisal-research/faisal_research_service.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M77_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void cleanup_journals(const char *prefix)
{
	char path[256];
	const char *suffixes[] = { "browser", "world" };
	unsigned int i;
	for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
		snprintf(path, sizeof(path), "%s-%s", prefix, suffixes[i]);
		unlink(path);
		snprintf(path, sizeof(path), "%s-%s.ckpt", prefix, suffixes[i]);
		unlink(path);
	}
}

int main(void)
{
	const char *prefix = "/tmp/faisal-m77-research";
	struct m77_service service;
	struct m77_source primary, secondary, conflict_a, conflict_b, preferred;
	struct fws_fact fact;
	int rc;
	memset(&service, 0, sizeof(service));
	memset(&primary, 0, sizeof(primary));
	memset(&secondary, 0, sizeof(secondary));
	memset(&conflict_a, 0, sizeof(conflict_a));
	memset(&conflict_b, 0, sizeof(conflict_b));
	cleanup_journals(prefix);
	if (m77_open(&service, prefix) != 0)
		return fail("open", -1);
	printf("FAISAL_M77_BROWSER_WORLD_OPEN_OK\n");
	if (m77_collect(&service, "faisal-status", "https://example.test",
			"FAISAL source says status green", M77_SOURCE_KIND_PRIMARY,
			100, 900000, 0, AGI_LC_KNOWLEDGE_MAX_TTL_NS, &primary) != 0)
		return fail("primary collect", -1);
	if (m77_test_unverified_denial(&service, primary.source_id) != 0)
		return fail("unverified promotion denial", -1);
	printf("M77_UNVERIFIED_FACT_DENIAL_OK source=%llu\n",
	       (unsigned long long)primary.source_id);
	if (m77_collect(&service, "faisal-status", "https://example.test",
			"FAISAL source says status green", M77_SOURCE_KIND_SECONDARY,
			50, 800000, 0, AGI_LC_KNOWLEDGE_MAX_TTL_NS, &secondary) != 0)
		return fail("secondary collect", -1);
	if (m77_preferred(&service, "faisal-status", &preferred) != 0 ||
	    preferred.source_id != primary.source_id)
		return fail("primary preference", -1);
	printf("M77_PRIMARY_SOURCE_PREFERENCE_OK source=%llu\n",
	       (unsigned long long)preferred.source_id);
	rc = m77_crosscheck(&service, primary.source_id, secondary.source_id);
	if (rc != 0 || service.sources[0].crosscheck_count == 0 ||
	    service.sources[1].crosscheck_count == 0)
		return fail("equal crosscheck", rc);
	printf("M77_EQUAL_CROSSCHECK_OK count=%u\\n", service.sources[0].crosscheck_count);
	if (m77_verify(&service, primary.source_id, primary.content_digest) != 0 ||
	    m77_promote_verified(&service, primary.source_id, &fact) != 0 ||
	    fact.memory_record_id == 0 || service.sources[0].promoted != 1)
		return fail("verified promotion", -1);
	printf("M77_VERIFIED_WORLD_PROMOTION_OK knowledge=%llu memory=%llu\n",
	       (unsigned long long)primary.knowledge_record_id,
	       (unsigned long long)fact.memory_record_id);
	if (m77_collect(&service, "faisal-conflict", "https://example.test",
			"FAISAL source says status red", M77_SOURCE_KIND_PRIMARY,
			100, 950000, 0, AGI_LC_KNOWLEDGE_MAX_TTL_NS, &conflict_a) != 0 ||
	    m77_collect(&service, "faisal-conflict", "https://example.test",
			"FAISAL source says status blue", M77_SOURCE_KIND_SECONDARY,
			50, 700000, 0, AGI_LC_KNOWLEDGE_MAX_TTL_NS, &conflict_b) != 0)
		return fail("conflict collect", -1);
	rc = m77_crosscheck(&service, conflict_a.source_id, conflict_b.source_id);
	if (rc != 1 || service.sources[2].local_state != M77_CONFLICT ||
	    service.sources[3].local_state != M77_CONFLICT ||
	    m77_verify(&service, conflict_a.source_id, conflict_a.content_digest) == 0 ||
	    m77_test_unverified_denial(&service, conflict_a.source_id) != 0)
		return fail("conflict retention", rc);
	printf("M77_CONFLICT_RETENTION_OK sources=%llu,%llu\n",
	       (unsigned long long)conflict_a.source_id,
	       (unsigned long long)conflict_b.source_id);
	if (m77_test_metadata_fuzz(&primary) != 0)
		return fail("metadata fuzz", -1);
	printf("M77_METADATA_FUZZ_REJECT_OK iterations=64\n");
	m77_close(&service);
	printf("M77_SELFTEST_EXIT=0\n");
	return 0;
}
