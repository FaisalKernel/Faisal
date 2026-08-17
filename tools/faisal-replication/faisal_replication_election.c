#include "faisal_replication_election.h"
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int valid_replica(const struct fjr_election *election, uint64_t id);

static int metadata_digest(struct fjr_election_metadata *metadata)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int length = 0;
	int rc = FJR_ERR_CORRUPT;
	memset(metadata->checksum, 0, sizeof(metadata->checksum));
	if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, metadata, offsetof(struct fjr_election_metadata,
					      checksum)) == 1 &&
	    EVP_DigestFinal_ex(ctx, metadata->checksum, &length) == 1 &&
	    length == sizeof(metadata->checksum))
		rc = FJR_OK;
	EVP_MD_CTX_free(ctx);
	return rc;
}

static int write_all(int fd, const void *data, size_t size)
{
	const uint8_t *bytes = data;
	while (size) {
		ssize_t written = write(fd, bytes, size);
		if (written <= 0)
			return FJR_ERR_IO;
		bytes += written;
		size -= (size_t)written;
	}
	return FJR_OK;
}

int fjr_election_persist(struct fjr_election *election,
			 const char *metadata_path)
{
	struct fjr_election_metadata metadata = {
		.magic = FJR_ELECTION_META_MAGIC,
		.version = FJR_ELECTION_META_VERSION,
		.term = election ? election->current_term : 0,
		.voted_for = election ? election->voted_for : 0,
		.generation = election ? election->metadata_generation + 1 : 0,
	};
	char temporary_path[512];
	int fd, rc;

	if (!election || !metadata_path || !*metadata_path ||
	    metadata.term == 0 ||
	    (metadata.voted_for && !valid_replica(election, metadata.voted_for)))
		return FJR_ERR_ARGUMENT;
	if (metadata.generation == 0 ||
	    snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.%ld",
		     metadata_path, (long)getpid()) >= (int)sizeof(temporary_path))
		return FJR_ERR_POLICY;
	if (metadata_digest(&metadata) != FJR_OK)
		return FJR_ERR_CORRUPT;
	fd = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return FJR_ERR_IO;
	rc = write_all(fd, &metadata, sizeof(metadata));
	if (rc == FJR_OK && fsync(fd) < 0)
		rc = FJR_ERR_IO;
	if (close(fd) < 0 && rc == FJR_OK)
		rc = FJR_ERR_IO;
	if (rc != FJR_OK) {
		unlink(temporary_path);
		return rc;
	}
	if (rename(temporary_path, metadata_path) < 0) {
		unlink(temporary_path);
		return FJR_ERR_IO;
	}
	election->metadata_generation = metadata.generation;
	return FJR_OK;
}

int fjr_election_restore(struct fjr_election *election,
			 const char *metadata_path)
{
	struct fjr_election_metadata metadata;
	uint8_t expected_checksum[sizeof(metadata.checksum)];
	int fd;
	ssize_t got;

	if (!election || !metadata_path || !*metadata_path)
		return FJR_ERR_ARGUMENT;
	fd = open(metadata_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? FJR_ERR_IO : FJR_ERR_IO;
	got = read(fd, &metadata, sizeof(metadata));
	close(fd);
	if (got != sizeof(metadata) || metadata.magic != FJR_ELECTION_META_MAGIC ||
	    metadata.version != FJR_ELECTION_META_VERSION || !metadata.term ||
	    metadata.generation == 0 ||
	    (metadata.voted_for && !valid_replica(election, metadata.voted_for)))
		return FJR_ERR_CORRUPT;
	memcpy(expected_checksum, metadata.checksum, sizeof(expected_checksum));
	if (metadata_digest(&metadata) != FJR_OK ||
	    memcmp(expected_checksum, metadata.checksum, sizeof(expected_checksum)) != 0)
		return FJR_ERR_CORRUPT;
	if (metadata.term < election->current_term ||
	    (metadata.term == election->current_term &&
	     metadata.generation < election->metadata_generation))
		return FJR_ERR_STALE;
	election->current_term = metadata.term;
	election->voted_for = metadata.voted_for;
	election->metadata_generation = metadata.generation;
	election->role = FJR_FOLLOWER;
	election->leader_id = 0;
	return FJR_OK;
}

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
