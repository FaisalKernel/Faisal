#define _GNU_SOURCE
#include "../../faisal-memory-orchestrator/faisal_memory_orchestrator_service.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M82_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void clean_prefix(const char *prefix)
{
	char path[512];
	const char *suffixes[] = {
		"memory", "memory.ckpt", "experience", "experience.ckpt",
		"world", "world.ckpt", "orchestrator"
	};
	unsigned int i;
	for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
		snprintf(path, sizeof(path), "%s-%s", prefix, suffixes[i]);
		unlink(path);
	}
}

static void fill_base(struct fmo_ingest *input, uint32_t memory_class,
			      const char *topic, const char *content)
{
	memset(input, 0, sizeof(*input));
	input->memory_class = memory_class;
	input->truth_class = FMO_TRUTH_REAL_WORLD_FACT;
	input->confidence_ppm = 900000;
	input->importance_ppm = 800000;
	input->observed_at_ns = 1000 + memory_class;
	input->freshness_ttl_ns = 1000000000ULL;
	input->provenance.source_id = 91000 + memory_class;
	input->provenance.experience_sequence = 92000 + memory_class;
	input->provenance.agent_id = 93000;
	input->provenance.task_id = 94000 + memory_class;
	input->provenance.event_sequence = 95000 + memory_class;
	input->provenance.verification_sequence = 96000 + memory_class;
	strncpy(input->scope, "m82-agent", sizeof(input->scope) - 1);
	strncpy(input->topic, topic, sizeof(input->topic) - 1);
	strncpy(input->source, "https://example.test/source", sizeof(input->source) - 1);
	strncpy(input->content, content, sizeof(input->content) - 1);
}

int main(void)
{
	const char *prefix = "/tmp/faisal-m82-memory";
	struct fmo_service service, restarted;
	struct fmo_experience_input experience;
	struct fmo_ingest input, bad;
	struct fmo_record record, old_record;
	struct fmo_query query;
	struct fmo_result results[FMO_MAX_RESULTS];
	struct fmo_context context;
	struct fmo_stats stats;
	uint32_t created, result, count, classes = 0, expired;
	uint64_t simulation_id, contradiction_id;
	unsigned int memory_class;
	int rc;

	clean_prefix(prefix);
	memset(&service, 0, sizeof(service));
	rc = fmo_open(&service, prefix);
	if (rc != FMO_OK)
		return fail("open", rc);

	memset(&experience, 0, sizeof(experience));
	experience.agent_id = 1001;
	experience.task_id = 2001;
	experience.event_sequence = 3001;
	experience.verification_sequence = 4001;
	experience.observed_at_ns = 0;
	experience.freshness_ttl_ns = 0;
	experience.confidence_ppm = 880000;
	experience.importance_ppm = 850000;
	strncpy(experience.scope, "m82-agent", sizeof(experience.scope) - 1);
	strncpy(experience.topic, "skill/research", sizeof(experience.topic) - 1);
	strncpy(experience.source, "https://example.test/experience", sizeof(experience.source) - 1);
	strncpy(experience.action, "collect primary sources", sizeof(experience.action) - 1);
	strncpy(experience.observation, "two authoritative documents agreed", sizeof(experience.observation) - 1);
	strncpy(experience.result, "verified research bundle", sizeof(experience.result) - 1);
	strncpy(experience.lesson, "prefer primary sources and record conflicts", sizeof(experience.lesson) - 1);
	strncpy(experience.skill, "verified-research", sizeof(experience.skill) - 1);
	strncpy(experience.causal, "source quality -> verification confidence", sizeof(experience.causal) - 1);
	rc = fmo_consolidate(&service, &experience, &created);

	if (rc != FMO_OK || created != 2)
		return fail("consolidation", rc);
	printf("M82_CONSOLIDATION_OK records=%u\n", created);

	memset(&query, 0, sizeof(query));
	strncpy(query.query, "primary sources", sizeof(query.query) - 1);
	strncpy(query.scope, "m82-agent", sizeof(query.scope) - 1);
	query.top_k = FMO_MAX_RESULTS;
	query.require_provenance = 1;
	rc = fmo_retrieve(&service, &query, results, &count);
	if (rc != FMO_OK || !count)
		return fail("hybrid retrieval", rc);
	printf("M82_HYBRID_RETRIEVAL_OK results=%u top_score=%u\n", count, results[0].score);
	if (fmo_build_context(&service, &query, &context) != FMO_OK ||
	    !context.count || context.truncated || strlen(context.text) >= FMO_MAX_CONTEXT)
		return fail("bounded context", -1);
	printf("M82_CONTEXT_BOUND_OK count=%u bytes=%zu\n", context.count, strlen(context.text));

	for (memory_class = FMO_CLASS_WORKING; memory_class <= FMO_CLASS_MAX; memory_class++) {
		char topic[64];
		snprintf(topic, sizeof(topic), "class/%u", memory_class);
		fill_base(&input, memory_class, topic, "class coverage record");
		if (fmo_ingest(&service, &input, &record, &result) != FMO_OK)
			return fail("memory class ingest", memory_class);
		classes++;
	}
	printf("M82_MEMORY_CLASSES_OK classes=%u\n", classes);

	if (fmo_test_simulation_boundary(&service, "m82-agent", &simulation_id) != FMO_OK)
		return fail("simulation fixture", -1);
	memset(&query, 0, sizeof(query));
	strncpy(query.query, "simulated outcome", sizeof(query.query) - 1);
	strncpy(query.scope, "m82-agent", sizeof(query.scope) - 1);
	query.top_k = FMO_MAX_RESULTS;
	if (fmo_retrieve(&service, &query, results, &count) != FMO_OK || count)
		return fail("simulation leaked into factual retrieval", (int)count);
	query.include_simulation = 1;
	if (fmo_retrieve(&service, &query, results, &count) != FMO_OK || !count ||
	    results[0].record_id != simulation_id ||
	    results[0].truth_class != FMO_TRUTH_SIMULATION_RESULT)
		return fail("simulation explicit retrieval", -1);
	printf("M82_SIMULATION_TRUTH_BOUNDARY_OK record=%llu\n",
	       (unsigned long long)simulation_id);

	rc = fmo_test_contradiction_lifecycle(&service, "m82-agent", 7000,
					      &contradiction_id);
	if (rc != FMO_OK || fmo_get(&service, contradiction_id, &record) != FMO_OK ||
	    !record.supersedes_id ||
	    fmo_get(&service, record.supersedes_id, &old_record) != FMO_OK ||
	    old_record.state != FMO_STATE_SUPERSEDED)
		return fail("contradiction lifecycle", rc);
	printf("M82_CONTRADICTION_SUPERSESSION_OK new=%llu old=%llu\n",
	       (unsigned long long)record.id,
	       (unsigned long long)old_record.id);

	fill_base(&input, FMO_CLASS_SEMANTIC, "freshness/short", "short-lived fact");
	input.observed_at_ns = 10000;
	input.freshness_ttl_ns = 10;
	if (fmo_ingest(&service, &input, &record, &result) != FMO_OK ||
	    fmo_mark_stale(&service, 10011, &expired) != FMO_OK || expired != 1)
		return fail("freshness expiry", -1);
	memset(&query, 0, sizeof(query));
	strncpy(query.query, "short-lived", sizeof(query.query) - 1);
	query.top_k = FMO_MAX_RESULTS;
	if (fmo_retrieve(&service, &query, results, &count) != FMO_OK || count)
		return fail("expired factual retrieval", (int)count);
	query.include_stale = 1;
	if (fmo_retrieve(&service, &query, results, &count) != FMO_OK || !count)
		return fail("explicit expired retrieval", -1);
	printf("M82_FRESHNESS_EXPIRY_OK expired=%u\n", expired);

	bad = input;
	bad.memory_class = 0;
	if (fmo_ingest(&service, &bad, &record, &result) == FMO_OK)
		return fail("malformed ingest accepted", -1);
	printf("M82_MALFORMED_INGEST_REJECT_OK\n");
	if (fmo_stats(&service, 10011, &stats) != FMO_OK ||
	    stats.provenance_complete_records < classes || !stats.simulation_records)
		return fail("stats", -1);
	printf("M82_PROVENANCE_STATS_OK total=%u complete=%u simulation=%u\n",
	       stats.total_records, stats.provenance_complete_records,
	       stats.simulation_records);
	fmo_close(&service);

	memset(&restarted, 0, sizeof(restarted));
	if (fmo_open(&restarted, prefix) != FMO_OK ||
	    fmo_stats(&restarted, 10011, &stats) != FMO_OK ||
	    stats.total_records < classes + 5)
		return fail("restart replay", -1);
	printf("M82_RESTART_REPLAY_OK total=%u\n", stats.total_records);
	fmo_close(&restarted);
	clean_prefix(prefix);
	printf("M82_SELFTEST_EXIT=0\n");
	return 0;
}
