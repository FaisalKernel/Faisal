// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/agi_lifecycle.h>

#define M89_WORKERS 8
#define M89_ITERATIONS 8
#define M89_MIN_RECORDS 8

static const uint64_t verify_mask = 1ULL << (AGI_LC_EVENT_VERIFY - 1);
static pthread_barrier_t start_barrier;
static int worker_failures;
static pthread_mutex_t failure_lock = PTHREAD_MUTEX_INITIALIZER;

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M89_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void note_worker_failure(void)
{
	pthread_mutex_lock(&failure_lock);
	worker_failures++;
	pthread_mutex_unlock(&failure_lock);
}

static int setup_session(int fd, uint64_t event_mask)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_subscribe subscribe = {
		.size = sizeof(subscribe),
		.event_mask = event_mask,
	};

	if (ioctl(fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(fd, AGI_LC_SUBSCRIBE, &subscribe) < 0)
		return -errno;
	return 0;
}

static void *worker_main(void *arg)
{
	int i;

	(void)arg;
	{
		int barrier_rc = pthread_barrier_wait(&start_barrier);

		if (barrier_rc != 0 && barrier_rc != PTHREAD_BARRIER_SERIAL_THREAD) {
			note_worker_failure();
			return NULL;
		}
	}
	for (i = 0; i < M89_ITERATIONS; i++) {
		int fd = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC | O_NONBLOCK);

		if (fd < 0 || setup_session(fd, verify_mask) != 0) {
			if (fd >= 0)
				close(fd);
			note_worker_failure();
			continue;
		}
		close(fd);
	}
	return NULL;
}

static int read_records(int fd, int *records)
{
	struct agi_lc_record record;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int rounds = 60;

	while (rounds-- && *records < M89_MIN_RECORDS) {
		int rc = poll(&pfd, 1, 1000);

		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0 || !(pfd.revents & POLLIN))
			continue;
		for (;;) {
			ssize_t n = read(fd, &record, sizeof(record));

			if (n < 0 && (errno == EAGAIN || errno == EINTR))
				break;
			if (n != (ssize_t)sizeof(record))
				return -EINVAL;
			if (record.type == AGI_LC_EVENT_VERIFY &&
			    (record.flags & AGI_LC_VERIFY_FLAG_RV_OBSERVATION) &&
			    (record.metadata & AGI_LC_RV_METADATA_TAG_MASK) ==
				AGI_LC_RV_METADATA_TAG && record.status < 0 &&
			    record.session_id && record.correlation)
				(*records)++;
		}
	}
	return 0;
}

int main(void)
{
	pthread_t workers[M89_WORKERS];
	int subscribed;
	int isolated;
	int ready_fd;
	int records = 0;
	int i;

	subscribed = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	isolated = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (subscribed < 0 || isolated < 0)
		return fail("open", -errno);
	if (setup_session(subscribed, verify_mask) != 0 ||
	    setup_session(isolated, 0) != 0)
		return fail("session setup", -errno);
	if (pthread_barrier_init(&start_barrier, NULL, M89_WORKERS + 1) != 0)
		return fail("barrier init", -errno);
	for (i = 0; i < M89_WORKERS; i++) {
		if (pthread_create(&workers[i], NULL, worker_main, NULL) != 0)
			return fail("pthread create", -errno);
	}
	printf("M89_CONCURRENT_SETUP_OK workers=%d iterations=%d\n",
	       M89_WORKERS, M89_ITERATIONS);
	fflush(stdout);
	ready_fd = open("/tmp/m89-subscribed", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (ready_fd < 0)
		return fail("readiness marker", -errno);
	close(ready_fd);
	{
		int barrier_rc = pthread_barrier_wait(&start_barrier);

		if (barrier_rc != 0 && barrier_rc != PTHREAD_BARRIER_SERIAL_THREAD)
			return fail("barrier release", barrier_rc);
	}
	printf("M89_RECORD_POLL_BEGIN\n");
	fflush(stdout);
	if (read_records(subscribed, &records) != 0)
		return fail("record read", -EINVAL);
	printf("M89_RECORD_POLL_END records=%d\n", records);
	fflush(stdout);
	printf("M89_WORKER_JOIN_BEGIN\n");
	fflush(stdout);
	for (i = 0; i < M89_WORKERS; i++)
		pthread_join(workers[i], NULL);
	printf("M89_WORKER_JOIN_END\n");
	fflush(stdout);
	if (worker_failures)
		return fail("worker lifecycle", -EIO);
	if (records < M89_MIN_RECORDS)
		return fail("record count", records);
	printf("M89_CONCURRENT_PROVENANCE_OK records=%d\n", records);
	if (poll(&(struct pollfd){ .fd = isolated, .events = POLLIN }, 1, 100) > 0)
		return fail("unsubscribed delivery", -EACCES);
	printf("M89_CAPABILITY_FILTER_OK unsubscribed=1\n");
	close(isolated);
	close(subscribed);
	pthread_barrier_destroy(&start_barrier);
	printf("M89_SELFTEST_EXIT=0\n");
	return 0;
}
