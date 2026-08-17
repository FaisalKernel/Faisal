#include "faisal_replication_election.h"
#include <string.h>

static uint64_t next_random(struct fjr_election *election)
{
	uint64_t x = election->rng_state;
	if (!x)
		x = 0x9e3779b97f4a7c15ULL;
	x ^= x << 7;
	x ^= x >> 9;
	x ^= x << 8;
	election->rng_state = x;
	return x;
}

static uint64_t election_timeout(struct fjr_election *election)
{
	uint64_t span = election->max_election_timeout_ns -
		election->min_election_timeout_ns;
	if (!span)
		return election->min_election_timeout_ns;
	return election->min_election_timeout_ns + next_random(election) % (span + 1);
}

static int valid_replica(const struct fjr_election *election, uint64_t id)
{
	return id && id <= FJR_MAX_REPLICAS && id <= election->replica_count;
}

int fjr_validate_config(const struct fjr_election_config *config)
{
	if (!config || !config->replica_id || config->replica_id > FJR_MAX_REPLICAS ||
	    !config->replica_count || config->replica_count > FJR_MAX_REPLICAS ||
	    config->replica_id > config->replica_count ||
	    config->quorum_size <= config->replica_count / 2 ||
	    config->quorum_size > config->replica_count ||
	    !config->min_election_timeout_ns ||
	    config->max_election_timeout_ns < config->min_election_timeout_ns ||
	    !config->heartbeat_interval_ns ||
	    config->heartbeat_interval_ns >= config->min_election_timeout_ns)
		return FJR_ERR_POLICY;
	return FJR_OK;
}

int fjr_election_init(struct fjr_election *election,
		      const struct fjr_election_config *config,
		      uint64_t now_ns)
{
	if (!election || fjr_validate_config(config) != FJR_OK)
		return FJR_ERR_ARGUMENT;
	memset(election, 0, sizeof(*election));
	election->replica_id = config->replica_id;
	election->replica_count = config->replica_count;
	election->quorum_size = config->quorum_size;
	election->min_election_timeout_ns = config->min_election_timeout_ns;
	election->max_election_timeout_ns = config->max_election_timeout_ns;
	election->heartbeat_interval_ns = config->heartbeat_interval_ns;
	election->rng_state = config->random_seed ? config->random_seed :
		(config->replica_id * 0x9e3779b97f4a7c15ULL);
	election->role = FJR_FOLLOWER;
	election->deadline_ns = now_ns + election_timeout(election);
	return FJR_OK;
}

int fjr_election_tick(struct fjr_election *election, uint64_t now_ns,
		      enum fjr_action *action)
{
	if (!election || !action || election->role == FJR_STOPPED)
		return FJR_ERR_ARGUMENT;
	*action = FJR_ACTION_NONE;
	if (now_ns < election->deadline_ns)
		return FJR_OK;
	if (election->role == FJR_LEADER) {
		*action = FJR_ACTION_SEND_HEARTBEAT;
		election->deadline_ns = now_ns + election->heartbeat_interval_ns;
		return FJR_OK;
	}
	election->role = FJR_CANDIDATE;
	election->current_term++;
	election->voted_for = election->replica_id;
	election->leader_id = 0;
	election->votes_bitmap = 1ULL << (election->replica_id - 1);
	election->votes_granted = 1;
	election->deadline_ns = now_ns + election_timeout(election);
	*action = election->votes_granted >= election->quorum_size ?
		FJR_ACTION_BECOME_LEADER : FJR_ACTION_START_ELECTION;
	if (*action == FJR_ACTION_BECOME_LEADER)
		election->role = FJR_LEADER;
	return FJR_OK;
}

int fjr_receive_vote_request(struct fjr_election *election,
			     uint64_t term, uint64_t candidate_id,
			     uint64_t candidate_last_sequence,
			     uint64_t local_last_sequence, uint32_t digest_valid,
			     uint32_t *granted)
{
	if (!election || !granted || !valid_replica(election, candidate_id))
		return FJR_ERR_ARGUMENT;
	*granted = 0;
	if (term < election->current_term)
		return FJR_ERR_STALE;
	if (term > election->current_term) {
		election->current_term = term;
		election->voted_for = 0;
		election->leader_id = 0;
		election->role = FJR_FOLLOWER;
	}
	if (!digest_valid || candidate_last_sequence < local_last_sequence ||
	    (election->voted_for && election->voted_for != candidate_id))
		return FJR_OK;
	election->voted_for = candidate_id;
	election->deadline_ns = election->deadline_ns + election_timeout(election);
	*granted = 1;
	return FJR_OK;
}

int fjr_receive_vote_response(struct fjr_election *election,
			      uint64_t term, uint64_t voter_id,
			      uint32_t granted, enum fjr_action *action)
{
	uint64_t bit;
	if (!election || !action || !valid_replica(election, voter_id))
		return FJR_ERR_ARGUMENT;
	*action = FJR_ACTION_NONE;
	if (term != election->current_term)
		return term < election->current_term ? FJR_ERR_STALE : FJR_ERR_CONFLICT;
	if (election->role != FJR_CANDIDATE)
		return FJR_ERR_STATE;
	if (!granted)
		return FJR_OK;
	bit = 1ULL << (voter_id - 1);
	if (!(election->votes_bitmap & bit)) {
		election->votes_bitmap |= bit;
		election->votes_granted++;
	}
	if (election->votes_granted >= election->quorum_size) {
		election->role = FJR_LEADER;
		election->leader_id = election->replica_id;
		election->deadline_ns = election->heartbeat_interval_ns;
		*action = FJR_ACTION_BECOME_LEADER;
	}
	return FJR_OK;
}

int fjr_receive_append(struct fjr_election *election, uint64_t term,
			uint64_t leader_id, enum fjr_action *action)
{
	if (!election || !action || !valid_replica(election, leader_id))
		return FJR_ERR_ARGUMENT;
	*action = FJR_ACTION_NONE;
	if (term < election->current_term)
		return FJR_ERR_STALE;
	if (term > election->current_term) {
		election->current_term = term;
		election->voted_for = 0;
		election->role = FJR_FOLLOWER;
	}
	if (election->role == FJR_LEADER && leader_id != election->replica_id)
		return FJR_ERR_CONFLICT;
	election->role = FJR_FOLLOWER;
	election->leader_id = leader_id;
	election->deadline_ns = election->heartbeat_interval_ns;
	*action = FJR_ACTION_FOLLOW_LEADER;
	return FJR_OK;
}
