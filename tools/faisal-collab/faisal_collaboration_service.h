#ifndef FAISAL_COLLABORATION_SERVICE_H
#define FAISAL_COLLABORATION_SERVICE_H

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include "../faisal-task/faisal_task_service.h"

#define FCL_MAX_AGENTS 32U
#define FCL_MAX_CAPABILITIES 96U
#define FCL_MAX_TEAMS 16U
#define FCL_MAX_TEAM_MEMBERS 16U
#define FCL_MAX_MESSAGES 128U
#define FCL_MAX_VOTES 32U
#define FCL_MAX_TEXT 256U
#define FCL_MAX_CAPABILITY_NAME 64U
#define FCL_JOURNAL_MAGIC 0x46434c31U
#define FCL_JOURNAL_VERSION 1U
#define FCL_DIGEST_SIZE FTS_DIGEST_SIZE

enum fcl_agent_state {
	FCL_AGENT_REGISTERED = 1,
	FCL_AGENT_AVAILABLE = 2,
	FCL_AGENT_BUSY = 3,
	FCL_AGENT_DEGRADED = 4,
	FCL_AGENT_FAILED = 5,
	FCL_AGENT_RECOVERING = 6,
	FCL_AGENT_RETIRED = 7
};

enum fcl_message_kind {
	FCL_MSG_DELEGATE = 1,
	FCL_MSG_RESOURCE_OFFER = 2,
	FCL_MSG_STATE_SHARE = 3,
	FCL_MSG_EVIDENCE_REQUEST = 4,
	FCL_MSG_EVIDENCE_RESPONSE = 5,
	FCL_MSG_CHALLENGE = 6,
	FCL_MSG_ESCALATION = 7,
	FCL_MSG_REDISTRIBUTE = 8
};

enum fcl_vote_state {
	FCL_VOTE_OPEN = 1,
	FCL_VOTE_PASSED = 2,
	FCL_VOTE_REJECTED = 3,
	FCL_VOTE_ESCALATED = 4
};

enum fcl_status {
	FCL_OK = 0,
	FCL_ERR_ARGUMENT = -1,
	FCL_ERR_IO = -2,
	FCL_ERR_CORRUPT = -3,
	FCL_ERR_FULL = -4,
	FCL_ERR_NOT_FOUND = -5,
	FCL_ERR_CONFLICT = -6,
	FCL_ERR_POLICY = -7,
	FCL_ERR_AUTHORITY = -8,
	FCL_ERR_STATE = -9,
	FCL_ERR_QUORUM = -10
};

struct fcl_capability {
	uint64_t capability_id;
	uint64_t provider_agent_id;
	uint64_t generation;
	uint64_t resource_mask;
	uint32_t state;
	char name[FCL_MAX_CAPABILITY_NAME];
	char description[FCL_MAX_TEXT];
};

struct fcl_agent {
	uint64_t agent_id;
	uint64_t parent_agent_id;
	uint64_t identity_capability;
	uint64_t generation;
	uint64_t last_heartbeat_ns;
	uint64_t cpu_quota_ns;
	uint64_t gpu_quota_micro;
	uint64_t network_quota_bytes;
	uint32_t state;
	uint32_t trust_ppm;
	uint32_t capability_count;
	uint32_t reserved;
	uint64_t capabilities[FCL_MAX_CAPABILITIES / 8];
	char name[FCL_MAX_TEXT];
};

struct fcl_team {
	uint64_t team_id;
	uint64_t owner_agent_id;
	uint64_t generation;
	uint64_t objective_id;
	uint32_t persistent;
	uint32_t quorum_required;
	uint32_t member_count;
	uint32_t state;
	uint64_t members[FCL_MAX_TEAM_MEMBERS];
};

struct fcl_message {
	uint64_t message_id;
	uint64_t team_id;
	uint64_t sender_agent_id;
	uint64_t target_agent_id;
	uint64_t correlation;
	uint64_t sequence;
	uint32_t kind;
	uint32_t schema;
	uint32_t verified;
	uint32_t reserved;
	uint8_t payload_digest[FCL_DIGEST_SIZE];
	char payload[FCL_MAX_TEXT];
};

struct fcl_vote {
	uint64_t vote_id;
	uint64_t team_id;
	uint64_t subject_sequence;
	uint32_t approvals;
	uint32_t rejections;
	uint32_t quorum_required;
	uint32_t state;
	uint8_t subject_digest[FCL_DIGEST_SIZE];
};

struct fcl_service {
	int journal_fd;
	uint64_t next_agent_id;
	uint64_t next_capability_id;
	uint64_t next_team_id;
	uint64_t next_message_id;
	uint64_t next_vote_id;
	uint64_t next_sequence;
	char journal_path[FTS_MAX_JOURNAL_PATH];
	struct fcl_agent agents[FCL_MAX_AGENTS];
	struct fcl_capability capabilities[FCL_MAX_CAPABILITIES];
	struct fcl_team teams[FCL_MAX_TEAMS];
	struct fcl_message messages[FCL_MAX_MESSAGES];
	struct fcl_vote votes[FCL_MAX_VOTES];
	size_t agent_count;
	size_t capability_count;
	size_t team_count;
	size_t message_count;
	size_t vote_count;
	pthread_mutex_t lock;
	int lock_initialized;
};

int fcl_open(struct fcl_service *service, const char *journal_path);
void fcl_close(struct fcl_service *service);
int fcl_replay(struct fcl_service *service);
int fcl_register_agent(struct fcl_service *service, const char *name,
			       uint64_t parent_agent_id, uint64_t now_ns,
			       struct fcl_agent *out);
int fcl_heartbeat(struct fcl_service *service, uint64_t agent_id,
			 uint64_t now_ns);
int fcl_register_capability(struct fcl_service *service, uint64_t agent_id,
				   const char *name, const char *description,
				   uint64_t resource_mask,
				   struct fcl_capability *out);
int fcl_find_capability(const struct fcl_service *service, const char *name,
				       struct fcl_capability *out);
int fcl_create_team(struct fcl_service *service, uint64_t owner_agent_id,
				   uint64_t objective_id, uint32_t persistent,
				   uint32_t quorum_required, struct fcl_team *out);
int fcl_join_team(struct fcl_service *service, uint64_t team_id,
			 uint64_t agent_id);
int fcl_send(struct fcl_service *service, uint64_t team_id,
		    uint64_t sender_agent_id, uint64_t target_agent_id,
		    uint32_t kind, uint32_t schema, const char *payload,
		    uint64_t correlation, struct fcl_message *out);
int fcl_request_evidence(struct fcl_service *service, uint64_t team_id,
				 uint64_t sender_agent_id, uint64_t target_agent_id,
				 const char *request, struct fcl_message *out);
int fcl_challenge(struct fcl_service *service, uint64_t team_id,
			 uint64_t sender_agent_id, uint64_t target_agent_id,
			 const uint8_t subject_digest[FCL_DIGEST_SIZE],
			 const char *reason, struct fcl_message *out);
int fcl_open_vote(struct fcl_service *service, uint64_t team_id,
			 uint64_t subject_sequence,
			 const uint8_t subject_digest[FCL_DIGEST_SIZE],
			 struct fcl_vote *out);
int fcl_vote(struct fcl_service *service, uint64_t vote_id,
		    uint64_t agent_id, int approve, struct fcl_vote *out);
int fcl_escalate(struct fcl_service *service, uint64_t team_id,
			 uint64_t sender_agent_id, const char *reason,
			 struct fcl_message *out);
int fcl_recover_agent(struct fcl_service *service, uint64_t agent_id,
			      uint64_t now_ns, uint32_t *redistributed,
			      struct fcl_agent *out);
int fcl_query_agent(const struct fcl_service *service, uint64_t agent_id,
			   struct fcl_agent *out);

#endif
