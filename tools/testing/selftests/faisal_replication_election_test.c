#include <stdio.h>
#include <stdlib.h>
#include "../../faisal-replication/faisal_replication_election.h"

static void check(int condition, const char *name, int rc)
{
	if (!condition) {
		printf("FJR_FAIL %s rc=%d\n", name, rc);
		exit(1);
	}
}

int main(void)
{
	struct fjr_election_config config = {
		.replica_id = 1,
		.replica_count = 3,
		.quorum_size = 2,
		.min_election_timeout_ns = 100,
		.max_election_timeout_ns = 200,
		.heartbeat_interval_ns = 25,
		.random_seed = 19,
	};
	struct fjr_election election;
	enum fjr_action action;
	uint32_t granted;
	int rc;

	rc = fjr_election_init(&election, &config, 1000);
	check(rc == FJR_OK && election.role == FJR_FOLLOWER &&
	      election.deadline_ns >= 1100 && election.deadline_ns <= 1200,
	      "INIT_BOUNDED_TIMEOUT", rc);
	check(fjr_election_tick(&election, election.deadline_ns - 1, &action) == FJR_OK &&
	      action == FJR_ACTION_NONE, "PRE_TIMEOUT_NO_ACTION", rc);
	check(fjr_election_tick(&election, election.deadline_ns, &action) == FJR_OK &&
	      action == FJR_ACTION_START_ELECTION && election.role == FJR_CANDIDATE &&
	      election.current_term == 1 && election.votes_granted == 1,
	      "TIMEOUT_STARTS_ELECTION", rc);
	check(fjr_receive_vote_response(&election, 1, 2, 1, &action) == FJR_OK &&
	      action == FJR_ACTION_BECOME_LEADER && election.role == FJR_LEADER,
	      "QUORUM_PROMOTES_LEADER", rc);
	check(fjr_receive_vote_response(&election, 1, 2, 1, &action) == FJR_ERR_STATE,
	      "LEADER_DUPLICATE_VOTE_REJECTED", rc);
	check(fjr_receive_append(&election, 0, 2, &action) == FJR_ERR_STALE,
	      "STALE_APPEND_REJECTED", rc);
	check(fjr_receive_append(&election, 1, 2, &action) == FJR_ERR_CONFLICT,
	      "LEADER_SPLIT_CONFLICT_REJECTED", rc);
	check(fjr_receive_append(&election, 2, 3, &action) == FJR_OK &&
	      action == FJR_ACTION_FOLLOW_LEADER && election.role == FJR_FOLLOWER &&
	      election.current_term == 2,
	      "HIGHER_TERM_FOLLOWS_LEADER", rc);
	check(fjr_receive_vote_request(&election, 2, 1, 1, 2, 1, &granted) == FJR_OK &&
	      granted == 0, "BEHIND_CANDIDATE_DENIED", rc);
	check(fjr_receive_vote_request(&election, 3, 1, 3, 2, 1, &granted) == FJR_OK &&
	      granted == 1 && election.current_term == 3,
	      "CURRENT_TERM_VOTE_GRANTED", rc);
	check(fjr_receive_vote_request(&election, 3, 2, 3, 2, 1, &granted) == FJR_OK &&
	      granted == 0, "SECOND_VOTE_DENIED", rc);
	printf("FJR_ELECTION_STATE_MACHINE_OK term=%llu role=%u\n",
	       (unsigned long long)election.current_term, election.role);
	printf("FJR_CONSENSUS_TIMEOUT_POLICY_OK min=%llu max=%llu heartbeat=%llu\n",
	       (unsigned long long)config.min_election_timeout_ns,
	       (unsigned long long)config.max_election_timeout_ns,
	       (unsigned long long)config.heartbeat_interval_ns);
	printf("FJR_ELECTION_SELFTEST_OK\n");
	return 0;
}
