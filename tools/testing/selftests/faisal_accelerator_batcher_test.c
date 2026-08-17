#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "faisal_accelerator_batcher.h"

struct fake_kernel {
	struct agi_lc_event_backpressure pressure;
	uint32_t batch_calls;
	uint32_t last_entry_count;
	uint32_t complete_count;
	int batch_result;
	int resync_result;
	uint32_t resync_calls;
};

static struct fake_kernel fake;

static int fake_resync(void *context,
			const struct agi_lc_event_backpressure *state)
{
	struct fake_kernel *kernel = context;
	(void)state;
	kernel->resync_calls++;
	if (kernel->resync_result == 0) {
		kernel->pressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL;
		kernel->pressure.queued = 0;
	}
	return kernel->resync_result;
}

static int fake_ioctl(int fd, unsigned long request, void *arg)
{
	struct agi_lc_accel_device_account_batch *batch;
	(void)fd;
	if (request == AGI_LC_EVENT_BACKPRESSURE) {
		*(struct agi_lc_event_backpressure *)arg = fake.pressure;
		return 0;
	}
	if (request != AGI_LC_ACCEL_DEVICE_ACCOUNT_BATCH) {
		errno = EINVAL;
		return -1;
	}
	batch = arg;
	fake.batch_calls++;
	fake.last_entry_count = batch->entry_count;
	batch->completed = fake.complete_count ? fake.complete_count : batch->entry_count;
	batch->status = AGI_LC_ACCEL_ACCOUNT_STATUS_ACCEPTED;
	return fake.batch_result;
}

static struct agi_lc_accel_device_account entry(uint64_t device_id,
						 uint64_t correlation)
{
	struct agi_lc_accel_device_account account = {
		.size = sizeof(account),
		.flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
		.device_id = device_id,
		.correlation = correlation,
	};
	return account;
}

int main(void)
{
	struct faisal_accel_batcher batcher;
	struct agi_lc_event_backpressure state;
	struct agi_lc_accel_device_account account;
	uint64_t queries_before;
	uint64_t flushes_before;

	assert(faisal_accel_batcher_init(&batcher, 3, 7, 4, 0) < 0);
	assert(faisal_accel_batcher_init(&batcher, 3, 7, 4, 4) == 0);
	assert(faisal_accel_batcher_set_ioctl(&batcher, fake_ioctl) == 0);
	assert(faisal_accel_batcher_set_resync(&batcher, fake_resync, &fake) == 0);
	assert(faisal_accel_batcher_set_retry_backoff(&batcher, 1000, 8000) == 0);
	memset(&fake, 0, sizeof(fake));
	fake.resync_result = 0;
	fake.pressure.size = sizeof(fake.pressure);
	fake.pressure.capacity = 64;
	fake.pressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL;
	assert(faisal_accel_batcher_query(&batcher, &state) == 0);
	account = entry(7, 1);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	account = entry(7, 2);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	assert(faisal_accel_batcher_pending(&batcher) == 2);
	assert(faisal_accel_batcher_flush(&batcher) == 0);
	assert(faisal_accel_batcher_pending(&batcher) == 0);
	assert(fake.batch_calls == 1 && fake.last_entry_count == 2);

	fake.pressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS;
	fake.pressure.queued = 64;
	fake.pressure.dropped_records = 1;
	account = entry(7, 3);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	assert(faisal_accel_batcher_flush(&batcher) == 0);
	assert(faisal_accel_batcher_pending(&batcher) == 0);
	assert(fake.resync_calls == 1 && batcher.resync_attempts == 1);
	assert(batcher.target_batch == 2);

	fake.resync_result = -1;
	fake.pressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS;
	fake.pressure.queued = 64;
	fake.pressure.dropped_records = 2;
	account = entry(7, 4);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	errno = 0;
	assert(faisal_accel_batcher_flush(&batcher) < 0 && errno == EAGAIN);
	assert(faisal_accel_batcher_pending(&batcher) == 1);
	assert(batcher.resync_failures == 1);
	queries_before = batcher.backpressure_queries;
	flushes_before = batcher.flushes;
	errno = 0;
	assert(faisal_accel_batcher_flush(&batcher) < 0 && errno == EAGAIN);
	assert(batcher.fast_rejects == 1);
	assert(batcher.backpressure_queries == queries_before);
	assert(batcher.flushes == flushes_before);
	fake.pressure.state = AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL;
	fake.pressure.queued = 0;
	assert(faisal_accel_batcher_acknowledge_loss(&batcher) == 0);
	assert(faisal_accel_batcher_flush(&batcher) == 0);
	assert(faisal_accel_batcher_pending(&batcher) == 0);
	for (int i = 0; i < 8; i++)
		assert(faisal_accel_batcher_query(&batcher, &state) == 0);
	assert(batcher.target_batch == 4);

	fake.pressure.dropped_records = 3;
	fake.complete_count = 1;
	fake.batch_result = -EAGAIN;
	account = entry(7, 5);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	account = entry(7, 6);
	assert(faisal_accel_batcher_submit(&batcher, &account) == 0);
	assert(faisal_accel_batcher_flush(&batcher) < 0);
	assert(faisal_accel_batcher_pending(&batcher) == 1);
	assert(batcher.telemetry_losses >= 2);
	fake.pressure.dropped_records = 3;
	fake.complete_count = 0;
	fake.batch_result = 0;
	assert(faisal_accel_batcher_acknowledge_loss(&batcher) == 0);
	assert(faisal_accel_batcher_flush(&batcher) == 0);
	assert(faisal_accel_batcher_pending(&batcher) == 0);
	assert(batcher.submitted_entries >= 5);
	printf("M159_ADAPTIVE_BATCHER_BACKOFF_OK flushes=%llu queries=%llu losses=%llu resync=%llu failures=%llu fast=%llu target=%u\n",
	       (unsigned long long)batcher.flushes,
	       (unsigned long long)batcher.backpressure_queries,
	       (unsigned long long)batcher.telemetry_losses,
	       (unsigned long long)batcher.resync_attempts,
	       (unsigned long long)batcher.resync_failures,
	       (unsigned long long)batcher.fast_rejects,
	       batcher.target_batch);
	return 0;
}
