#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
	struct fjr_election election, rebooted, durable, durable_rebooted;
	struct fjr_election_config durable_config;
	enum fjr_action action;
	char metadata_path[] = "/tmp/faisal-election-meta-XXXXXX";
	char auto_metadata_path[] = "/tmp/faisal-election-auto-meta";
	int metadata_fd;
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
	check(fjr_election_persist(&election, metadata_path) == FJR_OK &&
	      election.metadata_generation == 1, "METADATA_PERSISTED", rc);
	check(fjr_election_init(&rebooted, &config, 5000) == FJR_OK &&
	      fjr_election_restore(&rebooted, metadata_path) == FJR_OK &&
	      rebooted.current_term == election.current_term &&
	      rebooted.voted_for == election.voted_for &&
	      rebooted.metadata_generation == 1,
	      "METADATA_RESTORED_AFTER_REBOOT", rc);
	metadata_fd = open(metadata_path, O_WRONLY);
	check(metadata_fd >= 0 && write(metadata_fd, "X", 1) == 1 &&
	      close(metadata_fd) == 0 &&
	      fjr_election_restore(&rebooted, metadata_path) == FJR_ERR_CORRUPT,
	      "CORRUPTED_METADATA_REJECTED", rc);
	unlink(metadata_path);
	durable_config = config;
	durable_config.persistence_required = 1;
	snprintf(durable_config.metadata_path, sizeof(durable_config.metadata_path),
		 "%s", auto_metadata_path);
	unlink(auto_metadata_path);
	check(fjr_election_init(&durable, &durable_config, 1000) == FJR_OK &&
	      fjr_election_tick(&durable, durable.deadline_ns, &action) == FJR_OK &&
	      durable.metadata_generation == 1,
	      "AUTOMATIC_METADATA_PERSISTED", rc);
	check(fjr_election_init(&durable_rebooted, &durable_config, 2000) == FJR_OK &&
	      durable_rebooted.current_term == durable.current_term &&
	      durable_rebooted.voted_for == durable.voted_for &&
	      durable_rebooted.metadata_generation == 1,
	      "AUTOMATIC_METADATA_RESTORED", rc);
	unlink(auto_metadata_path);
	printf("FJR_ELECTION_STATE_MACHINE_OK term=%llu role=%u\n",
	       (unsigned long long)election.current_term, election.role);
	printf("FJR_AUTOMATIC_ELECTION_PERSISTENCE_OK term=%llu generation=%llu\n",
	       (unsigned long long)durable_rebooted.current_term,
	       (unsigned long long)durable_rebooted.metadata_generation);
	printf("FJR_PERSISTENT_TERM_VOTEDFOR_RESTORE_OK term=%llu voted_for=%llu generation=%llu\n",
	       (unsigned long long)election.current_term,
	       (unsigned long long)election.voted_for,
	       (unsigned long long)rebooted.metadata_generation);
	printf("FJR_CORRUPTED_ELECTION_METADATA_FAIL_CLOSED_OK\n");
	printf("FJR_CONSENSUS_TIMEOUT_POLICY_OK min=%llu max=%llu heartbeat=%llu\n",
	       (unsigned long long)config.min_election_timeout_ns,
	       (unsigned long long)config.max_election_timeout_ns,
	       (unsigned long long)config.heartbeat_interval_ns);
	printf("FJR_ELECTION_SELFTEST_OK\n");
	return 0;
}
