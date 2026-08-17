#include "faisal_accelerator_batcher.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

static int default_ioctl(int fd, unsigned long request, void *arg)
{
	return ioctl(fd, request, arg);
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	if ((uint64_t)ts.tv_sec > UINT64_MAX / 1000000000ULL)
		return UINT64_MAX;
	return (uint64_t)ts.tv_sec * 1000000000ULL +
		(uint64_t)ts.tv_nsec;
}

static void reset_retry_backoff(struct faisal_accel_batcher *batcher)
{
	batcher->retry_until_ns = 0;
	batcher->retry_backoff_ns = FAISAL_ACCEL_BATCHER_DEFAULT_RETRY_NS;
}

static void invalidate_pressure_cache(struct faisal_accel_batcher *batcher)
{
	batcher->pressure_cache_valid = 0;
	batcher->pressure_cache_timestamp_ns = 0;
}

static int pressure_cache_fresh(struct faisal_accel_batcher *batcher,
				struct agi_lc_event_backpressure *out)
{
	uint64_t now;

	if (!batcher->pressure_cache_valid || !batcher->pressure_cache_ns)
		return 0;
	now = monotonic_ns();
	if (!now || now < batcher->pressure_cache_timestamp_ns ||
	    now - batcher->pressure_cache_timestamp_ns >
		batcher->pressure_cache_ns) {
		invalidate_pressure_cache(batcher);
		return 0;
	}
	*out = batcher->cached_pressure;
	batcher->pressure_cache_hits++;
	return 1;
}

static int pressure_for_flush(struct faisal_accel_batcher *batcher,
			       struct agi_lc_event_backpressure *out)
{
	if (pressure_cache_fresh(batcher, out))
		return 0;
	return faisal_accel_batcher_query(batcher, out);
}

static void arm_retry_backoff(struct faisal_accel_batcher *batcher)
{
	uint64_t now = monotonic_ns();
	uint64_t delay = batcher->retry_backoff_ns;

	if (!delay)
		delay = FAISAL_ACCEL_BATCHER_DEFAULT_RETRY_NS;
	if (now > UINT64_MAX - delay)
		batcher->retry_until_ns = UINT64_MAX;
	else
		batcher->retry_until_ns = now + delay;
	if (delay >= batcher->retry_max_ns / 2)
		batcher->retry_backoff_ns = batcher->retry_max_ns;
	else
		batcher->retry_backoff_ns = delay * 2;
}

static uint32_t clamp_batch(uint32_t value, uint32_t max_batch)
{
	if (value < FAISAL_ACCEL_BATCHER_MIN_BATCH)
		return FAISAL_ACCEL_BATCHER_MIN_BATCH;
	if (value > max_batch)
		return max_batch;
	return value;
}

static void shrink_batch(struct faisal_accel_batcher *batcher)
{
	uint32_t next = batcher->target_batch / 2;

	batcher->target_batch = clamp_batch(next, batcher->max_batch);
	batcher->healthy_queries = 0;
}

static void grow_batch(struct faisal_accel_batcher *batcher)
{
	uint32_t next;

	if (batcher->target_batch >= batcher->max_batch)
		return;
	next = batcher->target_batch > batcher->max_batch / 2 ?
		batcher->max_batch : batcher->target_batch * 2;
	batcher->target_batch = clamp_batch(next, batcher->max_batch);
	batcher->healthy_queries = 0;
}

int faisal_accel_batcher_init(struct faisal_accel_batcher *batcher,
			      int fd, uint64_t device_id,
			      uint32_t initial_batch, uint32_t max_batch)
{
	if (!batcher || fd < 0 || !device_id ||
	    max_batch < FAISAL_ACCEL_BATCHER_MIN_BATCH ||
	    max_batch > FAISAL_ACCEL_BATCHER_MAX_BATCH)
		return -1;
	memset(batcher, 0, sizeof(*batcher));
	batcher->fd = fd;
	batcher->device_id = device_id;
	batcher->max_batch = max_batch;
	batcher->target_batch = clamp_batch(initial_batch, max_batch);
	batcher->retry_max_ns = FAISAL_ACCEL_BATCHER_MAX_RETRY_NS;
	batcher->pressure_cache_ns =
		FAISAL_ACCEL_BATCHER_DEFAULT_PRESSURE_CACHE_NS;
	reset_retry_backoff(batcher);
	batcher->ioctl_fn = default_ioctl;
	return 0;
}

int faisal_accel_batcher_set_ioctl(struct faisal_accel_batcher *batcher,
				   faisal_accel_ioctl_fn ioctl_fn)
{
	if (!batcher || !ioctl_fn)
		return -1;
	batcher->ioctl_fn = ioctl_fn;
	return 0;
}

int faisal_accel_batcher_set_retry_backoff(struct faisal_accel_batcher *batcher,
					      uint64_t initial_ns,
					      uint64_t max_ns)
{
	if (!batcher || !initial_ns || initial_ns > max_ns ||
	    max_ns > FAISAL_ACCEL_BATCHER_MAX_RETRY_NS)
		return -1;
	batcher->retry_backoff_ns = initial_ns;
	batcher->retry_max_ns = max_ns;
	batcher->retry_until_ns = 0;
	return 0;
}

int faisal_accel_batcher_set_pressure_cache(struct faisal_accel_batcher *batcher,
						   uint64_t cache_ns)
{
	if (!batcher || cache_ns > FAISAL_ACCEL_BATCHER_MAX_PRESSURE_CACHE_NS)
		return -1;
	batcher->pressure_cache_ns = cache_ns;
	invalidate_pressure_cache(batcher);
	return 0;
}

int faisal_accel_batcher_set_resync(struct faisal_accel_batcher *batcher,
				    faisal_accel_resync_fn resync_fn,
				    void *context)
{
	if (!batcher)
		return -1;
	batcher->resync_fn = resync_fn;
	batcher->resync_context = context;
	return 0;
}

int faisal_accel_batcher_query(struct faisal_accel_batcher *batcher,
			       struct agi_lc_event_backpressure *out)
{
	struct agi_lc_event_backpressure state = {
		.size = sizeof(state),
	};
	bool pressured = false;

	if (!batcher || !batcher->ioctl_fn)
		return -1;
	if (batcher->ioctl_fn(batcher->fd, AGI_LC_EVENT_BACKPRESSURE,
			      &state) < 0)
		return -1;
	batcher->backpressure_queries++;
	if (state.dropped_records > batcher->observed_dropped_records) {
		batcher->observed_dropped_records = state.dropped_records;
		batcher->telemetry_losses++;
		batcher->loss_acknowledged = 0;
		pressured = true;
	}
	if (state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_NEAR_FULL ||
	    state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_FULL ||
	    (state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS &&
	     !batcher->loss_acknowledged))
		pressured = true;
	if (pressured) {
		if (state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS &&
		    !batcher->loss_acknowledged && batcher->resync_fn) {
			batcher->resync_attempts++;
			if (batcher->resync_fn(batcher->resync_context, &state) == 0)
				batcher->loss_acknowledged = 1;
			else
				batcher->resync_failures++;
		}
		shrink_batch(batcher);
	} else if (state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL &&
		 state.queued < state.capacity / 2) {
		if (++batcher->healthy_queries >= 4)
			grow_batch(batcher);
	} else {
		batcher->healthy_queries = 0;
		if (batcher->loss_acknowledged)
			reset_retry_backoff(batcher);
	}
	if (!pressured && state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_NORMAL &&
	    state.queued < state.capacity / 2 && batcher->pressure_cache_ns) {
		batcher->cached_pressure = state;
		batcher->pressure_cache_timestamp_ns = monotonic_ns();
		batcher->pressure_cache_valid =
			batcher->pressure_cache_timestamp_ns != 0;
	} else {
		invalidate_pressure_cache(batcher);
	}
	if (out)
		*out = state;
	return 0;
}

static int flush_entries(struct faisal_accel_batcher *batcher,
			  const struct agi_lc_accel_device_account *entries,
			  uint32_t count, int direct, uint32_t *completed_out)
{
	struct agi_lc_event_backpressure state;
	struct agi_lc_accel_device_account_batch batch;
	uint32_t completed;
	int ret;

	if (completed_out)
		*completed_out = 0;
	if (!batcher || !entries || !count)
		return -1;
	{
		uint64_t now = monotonic_ns();
		if (now && batcher->retry_until_ns > now) {
			batcher->fast_rejects++;
			errno = EAGAIN;
			return -1;
		}
	}
	if (pressure_for_flush(batcher, &state) < 0)
		return -1;
	if (state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS &&
	    batcher->loss_acknowledged) {
		invalidate_pressure_cache(batcher);
		if (faisal_accel_batcher_query(batcher, &state) < 0)
			return -1;
	}
	if ((state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_LOSS &&
	     !batcher->loss_acknowledged) ||
	    state.state == AGI_LC_EVENT_BACKPRESSURE_STATE_FULL ||
	    state.queued + count > state.capacity) {
		errno = EAGAIN;
		invalidate_pressure_cache(batcher);
		arm_retry_backoff(batcher);
		return -1;
	}

	memset(&batch, 0, sizeof(batch));
	batch.size = sizeof(batch);
	batch.entries_ptr = (uint64_t)(uintptr_t)(direct ? entries : batcher->entries);
	batch.entry_count = count;
	ret = batcher->ioctl_fn(batcher->fd,
				AGI_LC_ACCEL_DEVICE_ACCOUNT_BATCH, &batch);
	batcher->flushes++;
	if (direct)
		batcher->direct_submissions++;
	completed = batch.completed;
	if (completed > count)
		completed = count;
	if (completed_out)
		*completed_out = completed;
	if (completed) {
		batcher->submitted_entries += completed;
		if (direct) {
			batcher->pending = count - completed;
			if (batcher->pending)
				memcpy(batcher->entries, entries + completed,
				       batcher->pending * sizeof(batcher->entries[0]));
		} else {
			batcher->pending -= completed;
			if (batcher->pending)
				memmove(batcher->entries, batcher->entries + completed,
					batcher->pending * sizeof(batcher->entries[0]));
		}
	}
	if (ret < 0) {
		if (ret == -EAGAIN || errno == EAGAIN) {
			batcher->telemetry_losses++;
			invalidate_pressure_cache(batcher);
			shrink_batch(batcher);
			arm_retry_backoff(batcher);
		}
		return -1;
	}
	if (batcher->pending)
		return -1;
	invalidate_pressure_cache(batcher);
	reset_retry_backoff(batcher);
	return 0;
}

int faisal_accel_batcher_flush(struct faisal_accel_batcher *batcher)
{
	if (!batcher || !batcher->pending)
		return 0;
	return flush_entries(batcher, batcher->entries, batcher->pending,
				     0, NULL);
}

int faisal_accel_batcher_acknowledge_loss(struct faisal_accel_batcher *batcher)
{
	if (!batcher)
		return -1;
	batcher->loss_acknowledged = 1;
	batcher->healthy_queries = 0;
	invalidate_pressure_cache(batcher);
	reset_retry_backoff(batcher);
	return 0;
}

int faisal_accel_batcher_submit(struct faisal_accel_batcher *batcher,
				const struct agi_lc_accel_device_account *entry)
{
	if (!batcher || !entry || entry->size != sizeof(*entry) ||
	    entry->device_id != batcher->device_id ||
	    batcher->pending >= batcher->max_batch)
		return -1;
	if (batcher->pending >= batcher->target_batch &&
	    faisal_accel_batcher_flush(batcher) < 0)
		return -1;
	batcher->entries[batcher->pending++] = *entry;
	if (batcher->pending >= batcher->target_batch)
		return faisal_accel_batcher_flush(batcher);
	return 0;
}

int faisal_accel_batcher_submit_many(struct faisal_accel_batcher *batcher,
				     const struct agi_lc_accel_device_account *entries,
				     uint32_t count, int flush_after,
				     uint32_t *accepted_count)
{
	uint32_t i;
	uint32_t position = 0;

	if (accepted_count)
		*accepted_count = 0;
	if (!batcher || !entries || !count ||
	    count > FAISAL_ACCEL_BATCHER_MAX_MANY_ENTRIES)
		return -1;
	for (i = 0; i < count; i++) {
		if (entries[i].size != sizeof(entries[i]) ||
		    entries[i].device_id != batcher->device_id)
			return -1;
	}
	while (position < count) {
		uint32_t room;
		uint32_t chunk;
		uint32_t completed = 0;
		int ret;

		if (batcher->pending == batcher->max_batch &&
		    faisal_accel_batcher_flush(batcher) < 0)
			return -1;
		room = batcher->max_batch - batcher->pending;
		chunk = count - position < room ? count - position : room;
		if (!batcher->pending && chunk == batcher->max_batch) {
			ret = flush_entries(batcher, entries + position, chunk, 1,
					    &completed);
			if (accepted_count)
				*accepted_count += chunk;
			position += chunk;
			if (ret < 0)
				return -1;
			continue;
		}
		memcpy(batcher->entries + batcher->pending,
		       entries + position,
		       chunk * sizeof(batcher->entries[0]));
		batcher->pending += chunk;
		position += chunk;
		if (accepted_count)
			*accepted_count += chunk;
		if (batcher->pending == batcher->max_batch &&
		    position < count && faisal_accel_batcher_flush(batcher) < 0)
			return -1;
	}
	if (flush_after && batcher->pending &&
	    faisal_accel_batcher_flush(batcher) < 0)
		return -1;
	return 0;
}

uint32_t faisal_accel_batcher_pending(const struct faisal_accel_batcher *batcher)
{
	return batcher ? batcher->pending : 0;
}
