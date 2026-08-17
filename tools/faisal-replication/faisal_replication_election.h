#ifndef FAISAL_REPLICATION_ELECTION_H
#define FAISAL_REPLICATION_ELECTION_H

#include <stdint.h>

#define FJR_MAX_REPLICAS 64U
#define FJR_OK 0
#define FJR_ERR_ARGUMENT -1
#define FJR_ERR_POLICY -2
#define FJR_ERR_STALE -3
#define FJR_ERR_CONFLICT -4
#define FJR_ERR_STATE -5
#define FJR_ERR_IO -6
#define FJR_ERR_CORRUPT -7
#define FJR_ELECTION_META_MAGIC 0x46524d31U
#define FJR_ELECTION_META_VERSION 1U

enum fjr_role {
	FJR_FOLLOWER = 0,
	FJR_CANDIDATE = 1,
	FJR_LEADER = 2,
	FJR_STOPPED = 3,
};

enum fjr_action {
	FJR_ACTION_NONE = 0,
	FJR_ACTION_START_ELECTION = 1,
	FJR_ACTION_BECOME_LEADER = 2,
	FJR_ACTION_SEND_HEARTBEAT = 3,
	FJR_ACTION_FOLLOW_LEADER = 4,
};

struct fjr_election_config {
	uint64_t replica_id;
	uint32_t replica_count;
	uint32_t quorum_size;
	uint64_t min_election_timeout_ns;
	uint64_t max_election_timeout_ns;
	uint64_t heartbeat_interval_ns;
	uint64_t random_seed;
};

struct fjr_election_metadata {
	uint32_t magic;
	uint32_t version;
	uint64_t term;
	uint64_t voted_for;
	uint64_t generation;
	uint8_t checksum[32];
};

struct fjr_election {
	uint64_t replica_id;
	uint32_t replica_count;
	uint32_t quorum_size;
	uint64_t min_election_timeout_ns;
	uint64_t max_election_timeout_ns;
	uint64_t heartbeat_interval_ns;
	uint64_t rng_state;
	uint64_t current_term;
	uint64_t voted_for;
	uint64_t leader_id;
	uint64_t metadata_generation;
	uint64_t deadline_ns;
	uint64_t votes_bitmap;
	uint32_t votes_granted;
	enum fjr_role role;
};

int fjr_validate_config(const struct fjr_election_config *config);
int fjr_election_persist(struct fjr_election *election,
			 const char *metadata_path);
int fjr_election_restore(struct fjr_election *election,
			 const char *metadata_path);
int fjr_election_init(struct fjr_election *election,
		      const struct fjr_election_config *config,
		      uint64_t now_ns);
int fjr_election_tick(struct fjr_election *election, uint64_t now_ns,
		      enum fjr_action *action);
int fjr_receive_vote_request(struct fjr_election *election,
			     uint64_t term, uint64_t candidate_id,
			     uint64_t candidate_last_sequence,
			     uint64_t local_last_sequence, uint32_t digest_valid,
			     uint32_t *granted);
int fjr_receive_vote_response(struct fjr_election *election,
			      uint64_t term, uint64_t voter_id,
			      uint32_t granted, enum fjr_action *action);
int fjr_receive_append(struct fjr_election *election, uint64_t term,
			uint64_t leader_id, enum fjr_action *action);

#endif
