#define _GNU_SOURCE
#include "../../faisal-world/faisal_world_state_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M73_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m73-world.journal";
	struct fws_service service;
	struct agi_lc_world_sync sync;
	struct agi_lc_resource_snapshot snapshot;
	struct fws_fact fresh, conflict;
	struct fws_temporal_handle temporal;
	uint64_t newest;
	int rc;

	unlink(journal);
	unlink("/tmp/faisal-m73-world.journal.ckpt");
	memset(&service, 0, sizeof(service));
	rc = fws_open(&service, journal);
	if (rc != FMS_OK)
		return fail("open", rc);
	{
		unsigned int i;
		for (i = 0; i < 64; i++) {
			struct agi_lc_world_sync bad_world;
			struct agi_lc_temporal bad_temporal;
			struct agi_lc_resource_snapshot bad_snapshot;
			memset(&bad_world, 0, sizeof(bad_world));
			bad_world.size = 0x100U + i;
			bad_world.operation = AGI_LC_WORLD_SYNC_QUERY;
			bad_world.correlation = 73900 + i;
			if (ioctl(service.memory.kernel_fd, AGI_LC_WORLD_SYNC, &bad_world) == 0 || errno != EINVAL)
				return fail("malformed world-sync accepted", (int)i);
			memset(&bad_temporal, 0, sizeof(bad_temporal));
			bad_temporal.size = 0x200U + i;
			bad_temporal.operation = AGI_LC_TEMPORAL_RECORD;
			bad_temporal.correlation = 74000 + i;
			if (ioctl(service.memory.kernel_fd, AGI_LC_TEMPORAL, &bad_temporal) == 0 || errno != EINVAL)
				return fail("malformed temporal accepted", (int)i);
			memset(&bad_snapshot, 0, sizeof(bad_snapshot));
			bad_snapshot.size = 0x300U + i;
			bad_snapshot.correlation = 74100 + i;
			if (ioctl(service.memory.kernel_fd, AGI_LC_GET_RESOURCE_SNAPSHOT, &bad_snapshot) == 0 || errno != EINVAL)
				return fail("malformed snapshot accepted", (int)i);
		}
	}
	printf("M73_MALFORMED_UAPI_REJECT_OK iterations=64\n");
	if (fws_world_query(&service, &sync) != 0 || !sync.consumer_id || !sync.newest_sequence)
		return fail("world query", rc);
	newest = sync.newest_sequence;
	printf("M73_WORLD_QUERY_OK newest=%llu generation=%llu\n",
	       (unsigned long long)newest, (unsigned long long)sync.generation);
	if (fws_world_ack(&service, newest - 1, &sync) == 0)
		return fail("stale world ack accepted", rc);
	if (fws_world_ack(&service, newest, &sync) != 0 || sync.ack_sequence != newest)
		return fail("world ack", rc);
	printf("M73_WORLD_ACK_OK sequence=%llu\n", (unsigned long long)sync.ack_sequence);
	if (fws_test_sequence_guard(&service) != 0)
		return fail("sequence guard", rc);
	printf("M73_SEQUENCE_GUARD_OK\n");
	if (fws_add_fact(&service, "system", "mode", "online", 0, 0,
			 1000001, &fresh) == 0)
		return fail("invalid confidence accepted", rc);
	printf("M73_BOUNDED_INPUT_REJECT_OK\n");

	if (fws_add_fact(&service, "system", "mode", "online", 0, 1000000,
			 850000, &fresh) != 0 || fresh.freshness_state != AGI_LC_MEMORY_FRESH)
		return fail("fresh fact", rc);
	if (fws_get_fresh(&service, "system", "mode", &conflict) != 0)
		return fail("fresh lookup", rc);
	printf("M73_FRESH_LOOKUP_OK generation=%llu\n",
	       (unsigned long long)conflict.generation);
	usleep(5000);
	if (fws_get_fresh(&service, "system", "mode", &conflict) != 0 ||
	    conflict.freshness_state != AGI_LC_MEMORY_STALE)
		return fail("expired fact not retained as stale", rc);
	printf("M73_FRESHNESS_EXPIRY_OK\n");
	if (fws_add_fact(&service, "system", "mode", "maintenance", 0, 1000000000ULL,
			 800000, &conflict) != 0 ||
	    conflict.conflict_state != FWS_CONFLICT_DETECTED || service.fact_count != 2)
		return fail("conflict detection", rc);
	printf("M73_CONFLICT_DETECTED_OK retained=%u\n", service.fact_count);
	if (fws_resolve_conflict(&service, "system", "mode", "online", 0,
			 1000000000ULL, 900000, &conflict) != 0 ||
	    conflict.conflict_state != FWS_CONFLICT_NONE || conflict.generation < 3 ||
	    service.fact_count != 3 || fws_get_fresh(&service, "system", "mode", &fresh) != 0 ||
	    fresh.freshness_state != AGI_LC_MEMORY_FRESH)
		return fail("explicit conflict resolution", rc);
	printf("M73_CONFLICT_RESOLUTION_OK generation=%llu retained=%u\n",
	       (unsigned long long)conflict.generation, service.fact_count);

	memset(&temporal, 0, sizeof(temporal));
	if (fws_temporal_probe(&service, &temporal) != 0 ||
	    !temporal.record_id || !temporal.authority_capability || !temporal.event_sequence)
		return fail("temporal probe", rc);
	printf("M73_TEMPORAL_CHECK_OK record=%llu generation=%llu\n",
	       (unsigned long long)temporal.record_id,
	       (unsigned long long)temporal.generation);
	if (fws_test_stale_temporal(&service, &temporal) != 0)
		return fail("stale temporal capability", rc);
	printf("M73_STALE_TEMPORAL_REJECT_OK\n");
	if (fws_resource_snapshot(&service, &snapshot) != 0 ||
	    !snapshot.sampled_at_ns || !snapshot.generation)
		return fail("resource snapshot", rc);
	printf("M73_RESOURCE_SNAPSHOT_OK measured=0x%x unavailable=0x%x unsupported=0x%x\n",
	       snapshot.measured_mask, snapshot.unavailable_mask,
	       snapshot.unsupported_mask);
	if (fws_world_query(&service, &sync) != 0 ||
	    fws_world_ack(&service, sync.newest_sequence, &sync) != 0)
		return fail("final world sync", rc);
	printf("M73_WORLD_STATE_SYNC_OK\n");
	fws_close(&service);
	unlink(journal);
	unlink("/tmp/faisal-m73-world.journal.ckpt");
	printf("M73_SELFTEST_EXIT=0\n");
	return 0;
}
