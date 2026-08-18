#define _GNU_SOURCE
#include "../../faisal-world/faisal_world_state_service.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M198_FAIL:%s rc=%d errno=%d\n", what, rc, errno);
	return 1;
}

static int expect_subscription_reject(struct fws_service *service,
					  struct agi_lc_world_subscription *subscription,
					  const char *what)
{
	errno = 0;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SET_WORLD_SUBSCRIPTION,
		  subscription) == 0 || errno != EINVAL)
		return fail(what, 0);
	return 0;
}

static int expect_sync_reject(struct fws_service *service,
				       struct agi_lc_world_sync *sync,
				       int expected_errno, const char *what)
{
	errno = 0;
	if (ioctl(service->memory.kernel_fd, AGI_LC_WORLD_SYNC, sync) == 0 ||
	    errno != expected_errno)
		return fail(what, 0);
	return 0;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m198-world-sync.journal";
	struct fws_service service;
	struct agi_lc_world_subscription subscription, current;
	struct agi_lc_world_sync sync;
	uint64_t newest;
	unsigned int i;
	int rc;

	unlink(journal);
	unlink("/tmp/faisal-m198-world-sync.journal.ckpt");
	memset(&service, 0, sizeof(service));
	rc = fws_open(&service, journal);
	if (rc != FMS_OK)
		return fail("open", rc);

	for (i = 0; i < 7; i++) {
		memset(&subscription, 0, sizeof(subscription));
		subscription.size = sizeof(subscription);
		subscription.class_mask = 1ULL << (AGI_LC_WORLD_EVENT_SECURITY - 1);
		subscription.min_priority = AGI_LC_WORLD_PRIORITY_LOW;
		subscription.queue_policy = AGI_LC_WORLD_QUEUE_DROP_LOW;
		switch (i) {
		case 0: subscription.size--; break;
		case 1: subscription.flags = 1; break;
		case 2: subscription.class_mask |= 1ULL << AGI_LC_WORLD_EVENT_MAX; break;
		case 3: subscription.min_priority = AGI_LC_WORLD_PRIORITY_CRITICAL + 1; break;
		case 4: subscription.queue_policy = AGI_LC_WORLD_QUEUE_DROP_LOW + 1; break;
		case 5: subscription.delivered = 1; break;
		default: subscription.reserved[0] = 1; break;
		}
		if (expect_subscription_reject(&service, &subscription,
					       "malformed subscription accepted")) {
			fws_close(&service);
			return 1;
		}
	}
	printf("M198_SUBSCRIPTION_REJECT_OK cases=7\n");

	memset(&subscription, 0, sizeof(subscription));
	subscription.size = sizeof(subscription);
	subscription.class_mask = (1ULL << (AGI_LC_WORLD_EVENT_SECURITY - 1)) |
		(1ULL << (AGI_LC_WORLD_EVENT_TASK_STATE - 1));
	subscription.min_priority = AGI_LC_WORLD_PRIORITY_LOW;
	subscription.queue_policy = AGI_LC_WORLD_QUEUE_DROP_LOW;
	subscription.correlation = 198001;
	if (ioctl(service.memory.kernel_fd, AGI_LC_SET_WORLD_SUBSCRIPTION,
		  &subscription) != 0)
		return fail("valid subscription update", rc);
	memset(&current, 0, sizeof(current));
	current.size = sizeof(current);
	if (ioctl(service.memory.kernel_fd, AGI_LC_GET_WORLD_SUBSCRIPTION,
		  &current) != 0 || current.class_mask != subscription.class_mask ||
	    current.min_priority != subscription.min_priority ||
	    current.queue_policy != subscription.queue_policy || current.delivered ||
	    current.filtered || current.dropped || current.last_loss_sequence)
		return fail("subscription readback", rc);
	printf("M198_SUBSCRIPTION_UPDATE_OK mask=0x%llx policy=%u\n",
	       (unsigned long long)current.class_mask, current.queue_policy);

	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_QUERY;
	sync.flags = 1;
	sync.correlation = 198002;
	if (expect_sync_reject(&service, &sync, EINVAL,
			       "world query flags accepted"))
		return 1;
	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_QUERY;
	sync.correlation = 198003;
	if (ioctl(service.memory.kernel_fd, AGI_LC_WORLD_SYNC, &sync) != 0 ||
	    !sync.consumer_id || !sync.newest_sequence)
		return fail("world query", rc);
	newest = sync.newest_sequence;
	printf("M198_WORLD_QUERY_OK newest=%llu generation=%llu\n",
	       (unsigned long long)newest, (unsigned long long)sync.generation);

	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_ACK;
	sync.consumer_id = service.memory.session_id;
	sync.ack_sequence = newest + 1;
	sync.correlation = 198004;
	if (expect_sync_reject(&service, &sync, ERANGE,
			       "future world ack accepted"))
		return 1;
	if (fws_world_ack(&service, newest, &sync) != 0 ||
	    sync.ack_sequence != newest)
		return fail("valid world ack", rc);
	if (fws_world_ack(&service, newest - 1, &sync) == 0)
		return fail("ack rollback accepted", rc);
	printf("M198_SYNC_WRITE_GUARD_OK sequence=%llu\n",
	       (unsigned long long)newest);

	memset(&sync, 0, sizeof(sync));
	sync.size = sizeof(sync);
	sync.operation = AGI_LC_WORLD_SYNC_RESYNC;
	sync.consumer_id = service.memory.session_id;
	sync.ack_sequence = newest;
	sync.resync_sequence = newest;
	sync.correlation = 198005;
	if (expect_sync_reject(&service, &sync, EAGAIN,
			       "unrequired resync accepted"))
		return 1;
	printf("M198_RESYNC_GUARD_OK\n");

	fws_close(&service);
	unlink(journal);
	unlink("/tmp/faisal-m198-world-sync.journal.ckpt");
	printf("M198_SELFTEST_EXIT=0\n");
	return 0;
}
