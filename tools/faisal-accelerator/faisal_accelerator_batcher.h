#ifndef FAISAL_ACCELERATOR_BATCHER_H
#define FAISAL_ACCELERATOR_BATCHER_H

#include <stdint.h>
#include <linux/agi_lifecycle.h>

#define FAISAL_ACCEL_BATCHER_MIN_BATCH 1U
#define FAISAL_ACCEL_BATCHER_DEFAULT_BATCH 8U
#define FAISAL_ACCEL_BATCHER_MAX_BATCH AGI_LC_ACCEL_ACCOUNT_BATCH_MAX

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
int faisal_accel_batcher_submit(struct faisal_accel_batcher *batcher,
				const struct agi_lc_accel_device_account *entry);
int faisal_accel_batcher_flush(struct faisal_accel_batcher *batcher);
int faisal_accel_batcher_query(struct faisal_accel_batcher *batcher,
			       struct agi_lc_event_backpressure *out);
int faisal_accel_batcher_acknowledge_loss(struct faisal_accel_batcher *batcher);
uint32_t faisal_accel_batcher_pending(const struct faisal_accel_batcher *batcher);

#endif
