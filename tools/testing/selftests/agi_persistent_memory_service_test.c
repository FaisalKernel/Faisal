#define _GNU_SOURCE
#include "../../faisal-memory/faisal_memory_service.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M71_FAIL:%s rc=%d errno=%s\n", what, rc, strerror(errno));
	return 1;
}

static int copy_file(const char *src, const char *dst)
{
	char buf[4096];
	ssize_t n;
	int in = open(src, O_RDONLY | O_CLOEXEC);
	int out;
	if (in < 0)
		return -1;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		char *p = buf;
		ssize_t left = n;
		while (left) {
			ssize_t w = write(out, p, (size_t)left);
			if (w <= 0) {
				close(in); close(out); return -1;
			}
			p += w; left -= w;
		}
	}
	close(in);
	close(out);
	return n < 0 ? -1 : 0;
}

int main(void)
{
	const char *journal = "/tmp/faisal-m71-memory.journal";
	const char *corrupt = "/tmp/faisal-m71-memory.corrupt";
	struct fms_service service, restarted, bad;
	struct fms_entry first, loaded;
	int fd, rc;
	unsigned char byte;

	unlink(journal);
	unlink("/tmp/faisal-m71-memory.journal.ckpt");
	unlink(corrupt);
	memset(&service, 0, sizeof(service));
	rc = fms_open(&service, journal);
	if (rc != FMS_OK)
		return fail("open initial service", rc);
	rc = fms_put(&service, "experience: verified durable observation", AGI_LC_MEMORY_TIER_EPISODIC,
		     850000, 700000, 0, &first);
	if (rc != FMS_OK || !first.record_id || !first.authority_capability)
		return fail("durable put", rc);
	printf("M71_PUT_OK record=%llu generation=%llu\n",
	       (unsigned long long)first.record_id,
	       (unsigned long long)first.kernel_generation);
	if (fms_get(&service, first.record_id, &loaded) != FMS_OK ||
	    strcmp(loaded.content, first.content) ||
	    memcmp(loaded.digest, first.digest, FMS_DIGEST_SIZE))
		return fail("get after put", FMS_ERR_CORRUPT);
	printf("M71_GET_DIGEST_OK\n");
	if (fms_test_stale_capability(&service, first.record_id) != FMS_OK)
		return fail("stale capability", FMS_ERR_CAPABILITY);
	printf("M71_STALE_CAPABILITY_REJECT_OK\n");
	if (fms_checkpoint(&service) != FMS_OK)
		return fail("checkpoint", FMS_ERR_KERNEL);
	printf("M71_CHECKPOINT_OK id=%llu sequence=%llu\n",
	       (unsigned long long)service.checkpoint.checkpoint_id,
	       (unsigned long long)service.checkpoint.checkpoint_sequence);
	if (fms_mark_crash(&service) != FMS_OK)
		return fail("mark crash", FMS_ERR_KERNEL);
	printf("M71_CRASH_MARK_OK\n");
	fms_close(&service);

	memset(&restarted, 0, sizeof(restarted));
	rc = fms_open(&restarted, journal);
	if (rc != FMS_OK)
		return fail("restart replay", rc);
	if (restarted.entry_count != 1 ||
	    fms_get(&restarted, restarted.entries[0].record_id, &loaded) != FMS_OK ||
	    strcmp(loaded.content, "experience: verified durable observation"))
		return fail("restart content", FMS_ERR_CORRUPT);
	printf("M71_RESTART_REPLAY_OK record=%llu\n",
	       (unsigned long long)loaded.record_id);
	if (fms_restore(&restarted) != FMS_OK)
		return fail("verified restore", FMS_ERR_KERNEL);
	printf("M71_VERIFIED_RESTORE_OK\n");
	fms_close(&restarted);

	fd = open(journal, O_WRONLY | O_APPEND | O_CLOEXEC);
	if (fd < 0 || write(fd, "tail", 4) != 4) {
		if (fd >= 0) close(fd);
		return fail("append crash tail", FMS_ERR_IO);
	}
	close(fd);
	memset(&restarted, 0, sizeof(restarted));
	if (fms_open(&restarted, journal) != FMS_OK)
		return fail("truncate incomplete tail", FMS_ERR_CORRUPT);
	printf("M71_INCOMPLETE_TAIL_RECOVERED_OK\n");
	fms_close(&restarted);

	if (copy_file(journal, corrupt) < 0)
		return fail("copy corrupt fixture", FMS_ERR_IO);
	fd = open(corrupt, O_RDWR | O_CLOEXEC);
	if (fd < 0 || lseek(fd, 80, SEEK_SET) < 0 || read(fd, &byte, 1) != 1 ||
	    lseek(fd, 80, SEEK_SET) < 0 || write(fd, "X", 1) != 1) {
		if (fd >= 0) close(fd);
		return fail("corrupt fixture", FMS_ERR_IO);
	}
	close(fd);
	memset(&bad, 0, sizeof(bad));
	if (fms_open(&bad, corrupt) != FMS_ERR_CORRUPT)
		return fail("corrupt digest accepted", FMS_ERR_CORRUPT);
	printf("M71_CORRUPT_DIGEST_REJECT_OK\n");

	unlink(journal);
	unlink("/tmp/faisal-m71-memory.journal.ckpt");
	unlink(corrupt);
	printf("M71_SELFTEST_EXIT=0\n");
	return 0;
}
