#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../faisal-collab/faisal_collaboration_service.h"
#include "../../faisal-memory-unified/faisal_unified_memory.h"

static void fail(const char *marker, int rc)
{
	printf("M109_FAIL %s rc=%d\n", marker, rc);
	exit(1);
}
#define COK(expr, marker) do { int _rc=(expr); if(_rc!=FCL_OK)fail((marker),_rc); } while(0)
#define MOK(expr, marker) do { int _rc=(expr); if(_rc!=FUM_OK)fail((marker),_rc); } while(0)
#define CEQ(expr, expected, marker) do { int _rc=(expr); if(_rc!=(expected))fail((marker),_rc); } while(0)

int main(void)
{
	char cp[] = "/tmp/faisal-m109-collab-XXXXXX";
	char mp[] = "/tmp/faisal-m109-memory-XXXXXX";
	struct fcl_service collab;
	struct fum_service memory;
	struct fcl_agent a, b, c, recovered;
	struct fcl_capability cap_a, cap_b, found_cap;
	struct fcl_team team;
	struct fcl_message message;
	struct fcl_vote vote;
	struct fum_backend relational, graph, vector;
	struct fum_record record, semantic, newer, expired, query[4];
	struct fum_query q;
	uint8_t subject[32] = { 1, 2, 3, 4 };
	uint32_t redistributed, forgotten;
	size_t found;
	int fd;

	fd = mkstemp(cp); if (fd < 0) fail("COLLAB_MKSTEMP", FCL_ERR_IO); close(fd); unlink(cp);
	fd = mkstemp(mp); if (fd < 0) fail("MEMORY_MKSTEMP", FUM_ERR_IO); close(fd); unlink(mp);
	COK(fcl_open(&collab, cp), "COLLAB_OPEN");
	MOK(fum_open(&memory, mp), "MEMORY_OPEN");
	printf("M109_DYNAMIC_FABRIC_OPEN_OK\n");

	COK(fcl_register_agent(&collab, "agent-alpha", 0, 1, &a), "AGENT_A");
	COK(fcl_register_agent(&collab, "agent-beta", a.agent_id, 2, &b), "AGENT_B");
	COK(fcl_register_agent(&collab, "agent-gamma", a.agent_id, 3, &c), "AGENT_C");
	COK(fcl_register_capability(&collab, a.agent_id, "semantic-graph-query", "relationship traversal", 4, &cap_a), "CAP_A");
	COK(fcl_register_capability(&collab, b.agent_id, "source-cross-check", "independent evidence", 2, &cap_b), "CAP_B");
	COK(fcl_find_capability(&collab, "source-cross-check", &found_cap), "CAP_DISCOVERY");
	if (found_cap.provider_agent_id != b.agent_id) fail("CAP_PROVIDER", FCL_ERR_STATE);
	printf("M109_DYNAMIC_CAPABILITY_DISCOVERY_OK capabilities=2\n");

	COK(fcl_create_team(&collab, a.agent_id, 108, 0, 2, &team), "TEAM_CREATE");
	COK(fcl_join_team(&collab, team.team_id, b.agent_id), "TEAM_JOIN_B");
	COK(fcl_join_team(&collab, team.team_id, c.agent_id), "TEAM_JOIN_C");
	COK(fcl_send(&collab, team.team_id, a.agent_id, b.agent_id, FCL_MSG_DELEGATE, 1, "delegate:cross-check", 10, &message), "DELEGATE");
	COK(fcl_request_evidence(&collab, team.team_id, b.agent_id, c.agent_id, "provide independent source digest", &message), "EVIDENCE_REQUEST");
	COK(fcl_challenge(&collab, team.team_id, c.agent_id, b.agent_id, subject, "claim lacks provenance", &message), "CHALLENGE");
	COK(fcl_escalate(&collab, team.team_id, b.agent_id, "risk threshold exceeded", &message), "ESCALATE");
	printf("M109_STRUCTURED_DELEGATION_EVIDENCE_CHALLENGE_ESCALATION_OK\n");
	COK(fcl_open_vote(&collab, team.team_id, 10, subject, &vote), "VOTE_OPEN");
	COK(fcl_vote(&collab, vote.vote_id, a.agent_id, 1, &vote), "VOTE_A");
	COK(fcl_vote(&collab, vote.vote_id, b.agent_id, 1, &vote), "VOTE_B");
	if (vote.state != FCL_VOTE_PASSED) fail("QUORUM_STATE", FCL_ERR_QUORUM);
	printf("M109_QUORUM_VOTE_OK approvals=%u quorum=%u\n", vote.approvals, vote.quorum_required);

	COK(fcl_recover_agent(&collab, c.agent_id, 20, &redistributed, &recovered), "AGENT_RECOVER");
	if (recovered.state != FCL_AGENT_AVAILABLE || redistributed != 0) fail("RECOVERY_STATE", FCL_ERR_STATE);
	printf("M109_AGENT_RECOVERY_REDISTRIBUTION_READY_OK generation=%llu\n", (unsigned long long)recovered.generation);

	MOK(fum_register_backend(&memory, "relational-adapter", 1, &relational), "BACKEND_RELATIONAL");
	MOK(fum_register_backend(&memory, "graph-adapter", 2, &graph), "BACKEND_GRAPH");
	MOK(fum_register_backend(&memory, "vector-adapter", 3, &vector), "BACKEND_VECTOR");
	MOK(fum_put(&memory, FUM_EPISODIC, "task:108", "caused-by", "observed source agreement", 10, 1000, 77, a.agent_id, 0xabc, 900000, 800000, relational.backend_id, &record), "MEM_EPISODIC");
	MOK(fum_put(&memory, FUM_SEMANTIC, "entity:faisal", "supports", "kernel-bound authority remains separate from model output", 11, 0, 78, a.agent_id, 0xabc, 950000, 900000, graph.backend_id, &semantic), "MEM_SEMANTIC");
	printf("M109_UNIFIED_MEMORY_CLASSES_BACKEND_NEUTRAL_OK classes=2 adapters=3\n");
	MOK(fum_get(&memory, record.record_id, a.agent_id, 0xabc, &record), "MEM_ACCESS_ALLOWED");
	CEQ(fum_get(&memory, record.record_id, b.agent_id, 0xdef, &record), FUM_ERR_ACCESS, "MEM_ACCESS_DENIED");
	memset(&q, 0, sizeof(q)); q.memory_class = FUM_EPISODIC; q.relation[0] = 'c'; strcpy(q.relation, "caused-by"); q.now_ns = 20; q.owner_agent_id = a.agent_id;
	MOK(fum_query(&memory, &q, query, 4, &found), "MEM_QUERY");
	if (found != 1) fail("MEM_QUERY_COUNT", FUM_ERR_NOT_FOUND);
	printf("M109_TEMPORAL_RELATIONSHIP_QUERY_ACCESS_CONTROL_OK found=%zu\n", found);
	CEQ(fum_put(&memory, FUM_SEMANTIC, "entity:faisal", "supports", "conflicting claim", 12, 0, 79, a.agent_id, 0xabc, 100000, 100000, vector.backend_id, &record), FUM_ERR_CONFLICT, "MEM_CONFLICT");
	MOK(fum_supersede(&memory, semantic.record_id, "updated verified claim", 13, &newer), "MEM_VERSION");
	if (newer.version != semantic.version + 1 || newer.parent_version != semantic.record_id) fail("MEM_VERSION_CHAIN", FUM_ERR_STALE);
	MOK(fum_put(&memory, FUM_FAILURE, "failure:temporary", "caused-by", "provider timeout", 14, 15, 80, a.agent_id, 0xabc, 700000, 900000, relational.backend_id, &expired), "MEM_EXPIRING");
	MOK(fum_forget_expired(&memory, 16, &forgotten), "MEM_FORGET");
	if (forgotten != 1) fail("MEM_FORGET_COUNT", FUM_ERR_STALE);
	printf("M109_CONFLICT_VERSION_FORGETTING_PROVENANCE_OK\n");

	fum_close(&memory); fcl_close(&collab);
	MOK(fum_open(&memory, mp), "MEMORY_REPLAY");
	MOK(fum_get(&memory, newer.record_id, a.agent_id, 0xabc, &record), "MEMORY_REPLAY_GET");
	printf("M109_MEMORY_REPLAY_OK version=%llu\n", (unsigned long long)record.version);
	fum_close(&memory);
	if (write(open(cp, O_WRONLY | O_APPEND), "x", 1) != 1) fail("COLLAB_CORRUPT_APPEND", FCL_ERR_IO);
	CEQ(fcl_open(&collab, cp), FCL_ERR_CORRUPT, "COLLAB_CORRUPTION");
	printf("M109_COLLAB_REPLAY_FAIL_CLOSED_OK\n");
	unlink(cp); unlink(mp);
	printf("M109_SELFTEST_EXIT=0\n");
	return 0;
}
