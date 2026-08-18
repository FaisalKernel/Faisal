#include "../../faisal-fabric/faisal_fabric.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned int cases_run;
static unsigned int mutation_rejections;

static void expect_code(const char *name, int actual, int expected)
{
	++cases_run;
	if (actual != expected) {
		fprintf(stderr, "FAIL %s actual=%d expected=%d\n", name, actual, expected);
		exit(1);
	}
}

static void expect_true(const char *name, int condition)
{
	++cases_run;
	if (!condition) {
		fprintf(stderr, "FAIL %s\n", name);
		exit(1);
	}
}

static void fill_digest(uint8_t digest[FF_DIGEST_SIZE], uint8_t value)
{
	memset(digest, value == 0U ? 1U : value, FF_DIGEST_SIZE);
}

static struct ff_policy make_policy(void)
{
	struct ff_policy policy;

	memset(&policy, 0, sizeof(policy));
	policy.current_time_ns = 100U;
	policy.observation_max_age_ns = 1000U;
	policy.default_lease_ns = 100U;
	policy.max_lease_ns = 500U;
	policy.minimum_priority = 1U;
	policy.max_queue_depth = FF_MAX_SHARDS;
	policy.require_authority = 1U;
	policy.require_verified_input = 1U;
	return policy;
}

static struct ff_node make_node(uint64_t node_id, uint8_t identity,
				uint8_t topology, uint32_t health,
				uint32_t pressure)
{
	struct ff_node node;

	memset(&node, 0, sizeof(node));
	node.node_id = node_id;
	node.generation = 1U;
	node.observed_at_ns = 100U;
	node.state = FF_NODE_HEALTHY;
	node.health_permille = health;
	node.pressure_permille = pressure;
	node.thermal_permille = 100U;
	node.forecast_permille = 100U;
	node.capacity.cpu_ns = 1000000U;
	node.capacity.memory_bytes = 1000000U;
	node.capacity.gpu_ns = 1000000U;
	node.capacity.npu_ns = 1000000U;
	node.capacity.network_bytes = 1000000U;
	node.capacity.storage_bytes = 1000000U;
	node.capacity.cost_micro = 1000000U;
	node.capacity.energy_uj = 1000000U;
	node.available = node.capacity;
	fill_digest(node.identity_digest, identity);
	fill_digest(node.topology_digest, topology);
	snprintf(node.name, sizeof(node.name), "node-%llu", (unsigned long long)node_id);
	return node;
}

static struct ff_shard make_shard(uint8_t locality, uint8_t salt)
{
	struct ff_shard shard;

	memset(&shard, 0, sizeof(shard));
	shard.objective_id = 100U + salt;
	shard.agent_id = 7U;
	shard.tenant_id = 3U;
	shard.trace_id = 500U + salt;
	shard.task_generation = 2U;
	shard.session_generation = 4U;
	shard.issued_at_ns = 100U;
	shard.deadline_ns = 10000U;
	shard.priority = 10U;
	shard.flags = FF_FLAG_AUTHORITY_GRANTED | FF_FLAG_VERIFIED_INPUT |
			      FF_FLAG_MIGRATION_ALLOWED;
	shard.demand.cpu_ns = 1000U;
	shard.demand.memory_bytes = 2000U;
	shard.demand.gpu_ns = 3000U;
	shard.demand.npu_ns = 4000U;
	shard.demand.network_bytes = 5000U;
	shard.demand.storage_bytes = 6000U;
	shard.demand.cost_micro = 7000U;
	shard.demand.energy_uj = 8000U;
	fill_digest(shard.budget_receipt_digest, salt + 1U);
	fill_digest(shard.provenance_digest, salt + 2U);
	if (locality != 0U) {
		shard.flags |= FF_FLAG_REQUIRES_LOCALITY;
		fill_digest(shard.locality_digest, locality);
	}
	snprintf(shard.name, sizeof(shard.name), "shard-%u", salt);
	return shard;
}

int main(void)
{
	char path[128];
	struct ff_service service;
	struct ff_service recovered;
	struct ff_service bad;
	struct ff_service limited;
	struct ff_policy policy = make_policy();
	struct ff_policy limited_policy = make_policy();
	struct ff_node node1 = make_node(1U, 0x11U, 0x21U, 950U, 100U);
	struct ff_node node2 = make_node(2U, 0x12U, 0x22U, 850U, 200U);
	struct ff_node registered;
	struct ff_node quarantined;
	struct ff_node node3;
	struct ff_shard request;
	struct ff_shard submitted;
	struct ff_shard placed;
	struct ff_shard released;
	struct ff_shard recovered_shard;
	struct ff_lease lease;
	struct ff_lease renewed;
	struct ff_lease migrated;
	struct ff_journal_attestation attestation;
	uint32_t recovered_count;
	uint32_t unrecoverable_count;
	int fd;
	char limited_path[128];
	unsigned char byte;
	snprintf(path, sizeof(path), "/tmp/faisal-fabric-%ld.journal", (long)getpid());
	unlink(path);
	expect_code("open", ff_open(&service, path, &policy), FF_OK);
	expect_code("register-node1", ff_register_node(&service, &node1, &registered), FF_OK);
	expect_true("node1-registered", registered.node_id == 1U &&
			 registered.state == FF_NODE_HEALTHY);
	expect_code("register-node2", ff_register_node(&service, &node2, &registered), FF_OK);
	expect_code("query-node1", ff_query_node(&service, 1U, &node1), FF_OK);
	expect_code("duplicate-node-rejected", ff_register_node(&service, &node1, &registered), FF_ERR_DUPLICATE);
	++mutation_rejections;

	request = make_shard(0x21U, 1U);
	memcpy(request.locality_digest, node1.topology_digest, FF_DIGEST_SIZE);
	expect_code("submit-locality-shard", ff_submit_shard(&service, &request, &submitted), FF_OK);
	expect_code("place-locality-shard", ff_place_shard(&service, submitted.shard_id, 110U,
							 &placed, &lease), FF_OK);
	expect_true("placed-on-local-node", placed.node_id == 1U && lease.node_id == 1U &&
			 lease.state == FF_LEASE_ACTIVE);
	expect_code("release-locality-shard", ff_release_lease(&service, lease.lease_id, 115U, &released), FF_OK);
	request = make_shard(0U, 4U);
	expect_code("submit-migration-shard", ff_submit_shard(&service, &request, &submitted), FF_OK);
	expect_code("place-migration-shard", ff_place_shard(&service, submitted.shard_id, 116U,
							 &placed, &lease), FF_OK);
	expect_code("renew-lease", ff_renew_lease(&service, lease.lease_id, 120U, 200U, &renewed), FF_OK);
	expect_true("renewed-generation", renewed.lease_generation == lease.lease_generation + 1U);
	expect_code("migrate-shard", ff_migrate_shard(&service, placed.shard_id, 130U,
							 &placed, &migrated), FF_OK);
	expect_true("migrated-to-node2", migrated.node_id == 2U && placed.node_id == 2U &&
			 migrated.previous_node_id == 1U);
	expect_code("release-lease", ff_release_lease(&service, migrated.lease_id, 140U, &released), FF_OK);
	expect_true("released-completed", released.state == FF_SHARD_COMPLETED);
	expect_code("duplicate-release-rejected", ff_release_lease(&service, migrated.lease_id, 150U, &released), FF_ERR_STATE);
	++mutation_rejections;

	request = make_shard(0U, 2U);
	expect_code("submit-expiry-shard", ff_submit_shard(&service, &request, &submitted), FF_OK);
	expect_code("place-expiry-shard", ff_place_shard(&service, submitted.shard_id, 160U,
							 &placed, &lease), FF_OK);
	expect_code("recover-expired", ff_recover_expired(&service, 300U, &recovered_count,
								&unrecoverable_count), FF_OK);
	expect_true("expired-recovery-count", recovered_count == 1U && unrecoverable_count == 0U);
	expect_code("query-recovered-shard", ff_query_shard(&service, placed.shard_id,
							 &recovered_shard), FF_OK);
	expect_true("recovery-state", recovered_shard.state == FF_SHARD_RECOVERY);

	request = make_shard(0U, 3U);
	expect_code("submit-quarantine-shard", ff_submit_shard(&service, &request, &submitted), FF_OK);
	expect_code("place-quarantine-shard", ff_place_shard(&service, submitted.shard_id, 10001U,
							 &placed, &lease), FF_ERR_DEADLINE);
	++mutation_rejections;
	policy.current_time_ns = 100U;
	request.issued_at_ns = 100U;
	request.deadline_ns = 10000U;
	expect_code("place-quarantine-shard-valid", ff_place_shard(&service, submitted.shard_id, 320U,
							 &placed, &lease), FF_OK);
	expect_code("quarantine-node", ff_quarantine_node(&service, placed.node_id, 330U,
							 &quarantined), FF_OK);
	expect_true("node-quarantined", quarantined.state == FF_NODE_QUARANTINED &&
			 quarantined.generation == 2U);
	expect_code("quarantine-repeat-rejected", ff_quarantine_node(&service, placed.node_id, 340U,
							 &quarantined), FF_ERR_QUARANTINED);
	++mutation_rejections;

	limited_policy.max_queue_depth = 1U;
	snprintf(limited_path, sizeof(limited_path), "/tmp/faisal-fabric-limited-%ld.journal", (long)getpid());
	unlink(limited_path);
	expect_code("limited-open", ff_open(&limited, limited_path, &limited_policy), FF_OK);
	expect_code("limited-submit", ff_submit_shard(&limited, &request, &submitted), FF_OK);
	request = make_shard(0U, 90U);
	expect_code("backpressure-rejected", ff_submit_shard(&limited, &request, &submitted), FF_ERR_BACKPRESSURE);
	++mutation_rejections;
	ff_close(&limited);
	unlink(limited_path);

	expect_code("journal-query", ff_query_journal(&service, &attestation), FF_OK);
	expect_true("journal-nonempty", attestation.last_sequence >= 12U &&
			 attestation.record_count == attestation.last_sequence);
	ff_close(&service);

	expect_code("replay-open", ff_open(&recovered, path, &policy), FF_OK);
	expect_code("replay-journal", ff_query_journal(&recovered, &attestation), FF_OK);
	expect_true("replay-count", attestation.last_sequence >= 12U);
	expect_code("replay-query-node", ff_query_node(&recovered, placed.node_id, &node3), FF_OK);
	expect_true("replay-node-quarantine", node3.state == FF_NODE_QUARANTINED);
	expect_code("replay-query-shard", ff_query_shard(&recovered, placed.shard_id,
							 &recovered_shard), FF_OK);
	expect_true("replay-shard-recovery", recovered_shard.state == FF_SHARD_RECOVERY);
	ff_close(&recovered);

	fd = open(path, O_RDWR);
	expect_true("tamper-open", fd >= 0);
	expect_true("tamper-seek", lseek(fd, (off_t)(sizeof(struct ff_event) - FF_DIGEST_SIZE), SEEK_SET) >= 0);
	expect_true("tamper-read", read(fd, &byte, 1) == 1);
	byte ^= 0xffU;
	expect_true("tamper-write", lseek(fd, (off_t)(sizeof(struct ff_event) - FF_DIGEST_SIZE), SEEK_SET) >= 0 && write(fd, &byte, 1) == 1);
	close(fd);
	expect_code("tampered-journal-rejected", ff_open(&bad, path, &policy), FF_ERR_REPLAY);
	++mutation_rejections;
	unlink(path);
	printf("M242_FABRIC_SELFTEST_EXIT=0 cases=%u mutation_rejections=%u\n",
	       cases_run, mutation_rejections);
	return 0;
}
