#include <linux/agi_lifecycle.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M88_FAIL:%s rc=%d\n", what, rc);
	return 1;
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

static uint32_t monitor_hash(const char *name)
{
	uint32_t hash = 2166136261U;
	const unsigned char *p = (const unsigned char *)name;

	for (; *p; p++)
		hash = (hash ^ *p) * 16777619U;
	return hash;
}

int main(void)
{
	const uint64_t verify_mask = 1ULL << (AGI_LC_EVENT_VERIFY - 1);
	struct agi_lc_record record;
	struct pollfd pollfd;
	uint64_t deadline;
	int subscribed;
	int isolated;
	int seen = 0;
	int rc;
	int ready_fd;

	subscribed = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	isolated = open("/dev/agi_lifecycle", O_RDWR | O_CLOEXEC | O_NONBLOCK);
	if (subscribed < 0 || isolated < 0)
		return fail("open", -errno);
	if (setup_session(subscribed, verify_mask) != 0 ||
	    setup_session(isolated, 0) != 0)
		return fail("session setup", -errno);
	printf("M88_SUBSCRIPTION_SETUP_OK verify_mask=0x%llx\n",
	       (unsigned long long)verify_mask);
	ready_fd = open("/tmp/m88-subscribed", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (ready_fd < 0)
		return fail("readiness marker", -errno);
	close(ready_fd);

	pollfd.fd = subscribed;
	pollfd.events = POLLIN;
	deadline = 8;
	while (deadline--) {
		rc = poll(&pollfd, 1, 1000);
		if (rc < 0 && errno == EINTR)
			continue;
		if (rc <= 0)
			continue;
		if (!(pollfd.revents & POLLIN))
			continue;
		for (;;) {
			ssize_t n = read(subscribed, &record, sizeof(record));
			if (n < 0 && (errno == EAGAIN || errno == EINTR))
				break;
			if (n != (ssize_t)sizeof(record))
				return fail("record size", n < 0 ? -errno : -EINVAL);
			if (record.type != AGI_LC_EVENT_VERIFY)
				continue;
			if (!(record.flags & AGI_LC_VERIFY_FLAG_RV_OBSERVATION) ||
			    (record.metadata & AGI_LC_RV_METADATA_TAG_MASK) !=
				AGI_LC_RV_METADATA_TAG || record.status >= 0 ||
			    !record.session_id || !record.correlation ||
			    (record.metadata & AGI_LC_RV_METADATA_SEQUENCE_MASK) !=
				(record.correlation & AGI_LC_RV_METADATA_SEQUENCE_MASK)) {
				fprintf(stderr, "M88_PROVENANCE_FIELDS flags=0x%x metadata=0x%llx status=%d seq=%llu corr=%llu expected_tag=0x%llx\n",
					record.flags, (unsigned long long)record.metadata,
					record.status, (unsigned long long)record.sequence,
					(unsigned long long)record.correlation,
					(unsigned long long)AGI_LC_RV_METADATA_TAG);
				return fail("rv provenance", -EINVAL);
			}
			if (((record.metadata & AGI_LC_RV_METADATA_MONITOR_MASK) >>
			     AGI_LC_RV_METADATA_MONITOR_SHIFT) !=
			    (monitor_hash("stall") & 0xffffU)) {
				fprintf(stderr, "M88_MONITOR_FIELDS got=0x%llx expected=0x%x\n",
					(unsigned long long)((record.metadata & AGI_LC_RV_METADATA_MONITOR_MASK) >>
					AGI_LC_RV_METADATA_MONITOR_SHIFT), monitor_hash("stall") & 0xffffU);
				return fail("monitor provenance", -EINVAL);
			}
			seen++;
		}
		if (seen)
			break;
	}
	if (!seen)
		return fail("rv observation timeout", -ETIMEDOUT);
	printf("M88_RV_PROVENANCE_OK records=%d monitor_hash=0x%x\n", seen,
	       monitor_hash("stall") & 0xffffU);
	pollfd.fd = isolated;
	pollfd.events = POLLIN;
	rc = poll(&pollfd, 1, 100);
	if (rc > 0 && (pollfd.revents & POLLIN))
		return fail("unsubscribed delivery", -EACCES);
	printf("M88_CAPABILITY_FILTER_OK unsubscribed=1\n");
	close(isolated);
	close(subscribed);
	printf("M88_SELFTEST_EXIT=0\n");
	return 0;
}
