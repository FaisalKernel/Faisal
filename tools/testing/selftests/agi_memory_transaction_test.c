#define _GNU_SOURCE
#include "../../faisal-memory/faisal_memory_service.h"
#include "../../faisal-memory/faisal_memory_transaction.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct concurrent_state {
	struct fms_service *left;
	struct fms_service *right;
	uint64_t baseline_id;
	pthread_rwlock_t lock;
	atomic_int failures;
	uint32_t writes;
	uint32_t reads;
};

static int fail(const char *stage, int rc)
{
	fprintf(stderr, "M83_FAIL:%s rc=%d\n", stage, rc);
	return 1;
}

static void cleanup(const char *path)
{
	char sidecar[512];
	char backup[512];
	char manifest[512];
	unlink(path);
	snprintf(sidecar, sizeof(sidecar), "%s.ckpt", path);
	snprintf(backup, sizeof(backup), "%s.m83bak", path);
	snprintf(manifest, sizeof(manifest), "%s.manifest", path);
	unlink(sidecar);
	unlink(backup);
	unlink(manifest);
}

static void *writer_main(void *arg)
{
	struct concurrent_state *state = arg;
	unsigned int i;
	for (i = 0; i < 16; i++) {
		char left[128];
		char right[128];
		struct fms_entry entry;
		snprintf(left, sizeof(left), "m83-concurrent-left-%u", i);
		snprintf(right, sizeof(right), "m83-concurrent-right-%u", i);
		pthread_rwlock_wrlock(&state->lock);
		if (fms_reactivate(state->left) != FMS_OK ||
		    fms_put(state->left, left, AGI_LC_MEMORY_TIER_EPISODIC,
				700000 + i, 500000 + i, 83000 + i, &entry) != FMS_OK ||
		    fms_reactivate(state->right) != FMS_OK ||
		    fms_put(state->right, right, AGI_LC_MEMORY_TIER_SEMANTIC,
				700000 + i, 500000 + i, 83000 + i, &entry) != FMS_OK)
			atomic_fetch_add_explicit(&state->failures, 1, memory_order_relaxed);
		else
			state->writes++;
		pthread_rwlock_unlock(&state->lock);
	}
	return NULL;
}

static void *reader_main(void *arg)
{
	struct concurrent_state *state = arg;
	unsigned int i;
	for (i = 0; i < 2000; i++) {
		struct fms_entry entry;
		pthread_rwlock_rdlock(&state->lock);
		if (fms_get(state->left, state->baseline_id, &entry) != FMS_OK ||
		    strcmp(entry.content, "m83-baseline-left"))
			atomic_fetch_add_explicit(&state->failures, 1, memory_order_relaxed);
		else
			state->reads++;
		pthread_rwlock_unlock(&state->lock);
	}
	return NULL;
}

int main(void)
{
	const char *left_path = "/tmp/faisal-m83-left.journal";
	const char *right_path = "/tmp/faisal-m83-right.journal";
	const char *coordinator = "/tmp/faisal-m83-coordinator";
	struct fms_service left, right;
	struct fms_entry entry;
	struct m83_transaction transaction;
	struct concurrent_state concurrent;
	pthread_t writer, reader;
	uint32_t state;
	uint64_t transaction_id;
	int rc;

	cleanup(left_path);
	cleanup(right_path);
	cleanup(coordinator);
	memset(&left, 0, sizeof(left));
	memset(&right, 0, sizeof(right));
	if (m83_begin(&transaction, coordinator, 83001) != M83_OK ||
	    m83_add_operation(&transaction, 0, left_path, "invalid-left",
			      AGI_LC_MEMORY_TIER_EPISODIC, 800000, 600000, 83001) != M83_OK ||
	    m83_add_operation(&transaction, 1, left_path, "duplicate-left",
			      AGI_LC_MEMORY_TIER_SEMANTIC, 800000, 600000, 83002) != M83_OK ||
	    m83_commit(&transaction, 0) != M83_ERR_ARGUMENT)
		return fail("transaction input validation", M83_ERR_ARGUMENT);
	printf("M83_TRANSACTION_INPUT_VALIDATION_OK\n");
	if (fms_open(&left, left_path) != FMS_OK ||
	    fms_open(&right, right_path) != FMS_OK)
		return fail("open baseline", FMS_ERR_IO);
	if (fms_reactivate(&left) != FMS_OK)
		return fail("activate baseline left", FMS_ERR_KERNEL);
	rc = fms_put(&left, "m83-baseline-left", AGI_LC_MEMORY_TIER_EPISODIC,
		      900000, 800000, 83001, &entry);
	if (rc != FMS_OK) {
		fprintf(stderr, "M83_BASELINE_LEFT_ERR rc=%d errno=%d\n", rc, errno);
		return fail("baseline left", rc);
	}
	if (fms_reactivate(&right) != FMS_OK)
		return fail("activate baseline right", FMS_ERR_KERNEL);
	rc = fms_put(&right, "m83-baseline-right", AGI_LC_MEMORY_TIER_SEMANTIC,
		      900000, 800000, 83002, &entry);
	if (rc != FMS_OK) {
		fprintf(stderr, "M83_BASELINE_RIGHT_ERR rc=%d errno=%d\n", rc, errno);
		return fail("baseline right", rc);
	}
	fms_close(&left);
	fms_close(&right);

	if (m83_begin(&transaction, coordinator, 83010) != M83_OK ||
	    m83_add_operation(&transaction, 0, left_path, "m83-crash-left",
			      AGI_LC_MEMORY_TIER_EPISODIC, 800000, 600000, 83010) != M83_OK ||
	    m83_add_operation(&transaction, 1, right_path, "m83-crash-right",
			      AGI_LC_MEMORY_TIER_SEMANTIC, 800000, 600000, 83011) != M83_OK)
		return fail("begin crash transaction", M83_ERR_ARGUMENT);
	if (m83_commit(&transaction, 2) != M83_ERR_INJECTED_CRASH)
		return fail("crash injection", M83_ERR_INJECTED_CRASH);
	if (m83_read_manifest(coordinator, &state, &transaction_id) != M83_OK ||
	    state != M83_STATE_PREPARED || transaction_id != 83010)
		return fail("prepared manifest", M83_ERR_CORRUPT);
	printf("M83_PREPARED_CRASH_STATE_OK transaction=%llu\n",
	       (unsigned long long)transaction_id);
	if (m83_recover(coordinator) != M83_OK ||
	    m83_read_manifest(coordinator, &state, &transaction_id) != M83_OK ||
	    state != M83_STATE_ABORTED)
		return fail("rollback recovery", M83_ERR_CORRUPT);
	printf("M83_CRASH_ROLLBACK_OK state=%u\n", state);

	memset(&left, 0, sizeof(left));
	memset(&right, 0, sizeof(right));
	if (fms_open(&left, left_path) != FMS_OK ||
	    fms_open(&right, right_path) != FMS_OK ||
	    left.entry_count != 1 || right.entry_count != 1 ||
	    strcmp(left.entries[0].content, "m83-baseline-left") ||
	    strcmp(right.entries[0].content, "m83-baseline-right"))
		return fail("rollback journal state", FMS_ERR_CORRUPT);
	printf("M83_CROSS_JOURNAL_ATOMICITY_OK entries=%zu,%zu\n",
	       left.entry_count, right.entry_count);
	fms_close(&left);
	fms_close(&right);

	if (m83_begin(&transaction, coordinator, 83020) != M83_OK ||
	    m83_add_operation(&transaction, 0, left_path, "m83-commit-left",
			      AGI_LC_MEMORY_TIER_EPISODIC, 800000, 600000, 83020) != M83_OK ||
	    m83_add_operation(&transaction, 1, right_path, "m83-commit-right",
			      AGI_LC_MEMORY_TIER_SEMANTIC, 800000, 600000, 83021) != M83_OK ||
	    m83_commit(&transaction, 0) != M83_OK)
		return fail("successful transaction", M83_ERR_IO);
	if (m83_read_manifest(coordinator, &state, &transaction_id) != M83_OK ||
	    state != M83_STATE_COMMITTED || transaction_id != 83020)
		return fail("committed manifest", M83_ERR_CORRUPT);
	printf("M83_ATOMIC_COMMIT_OK transaction=%llu\n",
	       (unsigned long long)transaction_id);

	if (fms_open(&left, left_path) != FMS_OK || fms_open(&right, right_path) != FMS_OK ||
	    left.entry_count != 2 || right.entry_count != 2 ||
	    strcmp(left.entries[1].content, "m83-commit-left") ||
	    strcmp(right.entries[1].content, "m83-commit-right"))
		return fail("committed journal replay", FMS_ERR_CORRUPT);
	if (fms_reactivate(&left) != FMS_OK ||
	    fms_test_stale_capability(&left, left.entries[0].record_id) != FMS_OK)
		return fail("capability isolation", FMS_ERR_CAPABILITY);
	printf("M83_CAPABILITY_ISOLATION_OK\n");

	memset(&concurrent, 0, sizeof(concurrent));
	concurrent.left = &left;
	concurrent.right = &right;
	concurrent.baseline_id = left.entries[0].record_id;
	atomic_init(&concurrent.failures, 0);
	if (pthread_rwlock_init(&concurrent.lock, NULL) != 0 ||
	    pthread_create(&writer, NULL, writer_main, &concurrent) != 0 ||
	    pthread_create(&reader, NULL, reader_main, &concurrent) != 0)
		return fail("concurrency setup", M83_ERR_IO);
	pthread_join(writer, NULL);
	pthread_join(reader, NULL);
	pthread_rwlock_destroy(&concurrent.lock);
	if (atomic_load_explicit(&concurrent.failures, memory_order_relaxed) != 0 ||
	    concurrent.writes != 16 || concurrent.reads != 2000)
		return fail("concurrent read write", M83_ERR_CORRUPT);
	printf("M83_CONCURRENT_READ_WRITE_OK writes=%u reads=%u\n",
	       concurrent.writes, concurrent.reads);
	fms_close(&left);
	fms_close(&right);
	cleanup(left_path);
	cleanup(right_path);
	cleanup(coordinator);
	printf("M83_SELFTEST_EXIT=0\n");
	return 0;
}
