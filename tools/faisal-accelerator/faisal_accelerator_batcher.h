#ifndef FAISAL_ACCELERATOR_BATCHER_H
#define FAISAL_ACCELERATOR_BATCHER_H

#include <stdint.h>
#include <linux/agi_lifecycle.h>

#define FAISAL_ACCEL_BATCHER_MIN_BATCH 1U
#define FAISAL_ACCEL_BATCHER_DEFAULT_BATCH 8U
#define FAISAL_ACCEL_BATCHER_MAX_BATCH AGI_LC_ACCEL_ACCOUNT_BATCH_MAX
#define FAISAL_ACCEL_BATCHER_DEFAULT_RETRY_NS 1000000ULL
#define FAISAL_ACCEL_BATCHER_MAX_RETRY_NS 100000000ULL
#define FAISAL_ACCEL_BATCHER_DEFAULT_PRESSURE_CACHE_NS 1000000ULL
#define FAISAL_ACCEL_BATCHER_MAX_PRESSURE_CACHE_NS 100000000ULL
#define FAISAL_ACCEL_BATCHER_MAX_MANY_ENTRIES 4096U

typedef int (*faisal_accel_ioctl_fn)(int fd, unsigned long request,
					 void *arg);
typedef int (*faisal_accel_resync_fn)(void *context,
					 const struct agi_lc_event_backpressure *state);

struct faisal_accel_batcher {
	int fd;
	faisal_accel_ioctl_fn ioctl_fn;
	faisal_accel_resync_fn resync_fn;
	void *resync_context;
	uint64_t device_id;
	uint32_t target_batch;
	uint32_t max_batch;
	uint32_t pending;
	uint32_t healthy_queries;
	uint32_t loss_acknowledged;
	uint64_t observed_dropped_records;
	uint64_t submitted_entries;
	uint64_t flushes;
	uint64_t backpressure_queries;
	uint64_t telemetry_losses;
	uint64_t resync_attempts;
	uint64_t resync_failures;
	uint64_t retry_until_ns;
	uint64_t retry_backoff_ns;
	uint64_t retry_max_ns;
	uint64_t fast_rejects;
	uint64_t pressure_cache_hits;
	uint64_t pressure_cache_ns;
	uint64_t pressure_cache_timestamp_ns;
	struct agi_lc_event_backpressure cached_pressure;
	uint32_t pressure_cache_valid;
	struct agi_lc_accel_device_account entries[FAISAL_ACCEL_BATCHER_MAX_BATCH];
};

int faisal_accel_batcher_init(struct faisal_accel_batcher *batcher,
			      int fd, uint64_t device_id,
			      uint32_t initial_batch, uint32_t max_batch);
int faisal_accel_batcher_set_ioctl(struct faisal_accel_batcher *batcher,
				   faisal_accel_ioctl_fn ioctl_fn);
int faisal_accel_batcher_set_resync(struct faisal_accel_batcher *batcher,
				    faisal_accel_resync_fn resync_fn,
				    void *context);
int faisal_accel_batcher_set_retry_backoff(struct faisal_accel_batcher *batcher,
					      uint64_t initial_ns,
					      uint64_t max_ns);
int faisal_accel_batcher_set_pressure_cache(struct faisal_accel_batcher *batcher,
						   uint64_t cache_ns);
int faisal_accel_batcher_submit(struct faisal_accel_batcher *batcher,
				const struct agi_lc_accel_device_account *entry);
int faisal_accel_batcher_submit_many(struct faisal_accel_batcher *batcher,
				     const struct agi_lc_accel_device_account *entries,
				     uint32_t count, int flush_after,
				     uint32_t *accepted_count);
int faisal_accel_batcher_flush(struct faisal_accel_batcher *batcher);
int faisal_accel_batcher_query(struct faisal_accel_batcher *batcher,
			       struct agi_lc_event_backpressure *out);
int faisal_accel_batcher_acknowledge_loss(struct faisal_accel_batcher *batcher);
uint32_t faisal_accel_batcher_pending(const struct faisal_accel_batcher *batcher);

#endif
