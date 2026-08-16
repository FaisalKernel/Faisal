// SPDX-License-Identifier: GPL-2.0
/*
 * FAISAL lifecycle UAPI fuzz smoke.
 *
 * This is deliberately bounded and non-authoritative: random model data never
 * grants capability, changes policy, or represents a valid production request.
 * It exercises read-only/query ABI paths and malformed ioctl encodings. QEMU
 * validates kernel survival and the harness separately scans the serial log for
 * sanitizer, Oops, warning, and panic diagnostics.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define FUZZ_BUFFER_SIZE 4096U
#define FUZZ_DEFAULT_ITERATIONS 4096U
#define FUZZ_QUERY_COUNT 8U

struct fuzz_result {
	unsigned long calls;
	unsigned long accepted;
	unsigned long rejected;
	unsigned long unexpected_signal_safe_errors;
};

static uint64_t fuzz_next(uint64_t *state)
{
	uint64_t x = *state;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	*state = x;
	return x;
}

static void fuzz_fill(unsigned char *buffer, size_t length, uint64_t *state)
{
	size_t index;

	for (index = 0; index < length; ++index)
		buffer[index] = (unsigned char)fuzz_next(state);
}

static int fuzz_call(int fd, unsigned long command, unsigned char *buffer,
			     struct fuzz_result *result)
{
	int rc;

	errno = 0;
	rc = ioctl(fd, command, buffer);
	result->calls++;
	if (rc == 0) {
		result->accepted++;
		return 0;
	}

	/* Query fuzzing is expected to reject malformed state with a normal errno. */
	switch (errno) {
	case EAGAIN:
	case EBADF:
	case EFAULT:
	case EINVAL:
	case ENOTTY:
	case EPERM:
	case EPIPE:
	case EOVERFLOW:
	case EBUSY:
		result->rejected++;
		return 0;
	default:
		result->unexpected_signal_safe_errors++;
		return 0;
	}
}

static unsigned long parse_iterations(const char *value)
{
	char *end;
	unsigned long iterations;

	errno = 0;
	iterations = strtoul(value, &end, 10);
	if (errno || !value[0] || *end || iterations == 0 || iterations > 1000000UL)
		return 0;
	return iterations;
}

int main(int argc, char **argv)
{
	static const unsigned long queries[FUZZ_QUERY_COUNT] = {
		AGI_LC_GET_STATS,
		AGI_LC_ACCEL_GET,
		AGI_LC_GET_BUDGET,
		AGI_LC_GET_MEMORY_BUDGET,
		AGI_LC_GET_WORLD_SUBSCRIPTION,
		AGI_LC_GET_RESOURCE_SNAPSHOT,
		AGI_LC_GET_IDENTITY,
		AGI_LC_GET_ATTRIBUTION,
	};
	unsigned char buffer[FUZZ_BUFFER_SIZE];
	struct fuzz_result result = { 0 };
	const char *device = "/dev/agi_lifecycle";
	unsigned long iterations = FUZZ_DEFAULT_ITERATIONS;
	uint64_t state = UINT64_C(0x46414953414c4655);
	int fd;
	unsigned long index;

	if (argc > 1)
		device = argv[1];
	if (argc > 2) {
		iterations = parse_iterations(argv[2]);
		if (!iterations) {
			fprintf(stderr, "invalid iteration count\n");
			return 2;
		}
	}

	fd = open(device, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		perror("open lifecycle device");
		return 2;
	}

	for (index = 0; index < iterations; ++index) {
		unsigned long query = queries[index % FUZZ_QUERY_COUNT];
		unsigned long malformed;

		fuzz_fill(buffer, sizeof(buffer), &state);
		fuzz_call(fd, query, buffer, &result);

		/* Unknown command numbers and sizes must fail without corrupting state. */
		malformed = _IOC(_IOC_READ | _IOC_WRITE, AGI_LC_IOC_MAGIC,
				 0x80U + (unsigned int)(fuzz_next(&state) & 0x3fU),
				 1U + (unsigned int)(fuzz_next(&state) & 0x3ffU));
		fuzz_fill(buffer, sizeof(buffer), &state);
		fuzz_call(fd, malformed, buffer, &result);
	}

	if (close(fd) < 0) {
		perror("close lifecycle device");
		return 2;
	}

	printf("FAISAL_UAPI_FUZZ_OK calls=%lu accepted=%lu rejected=%lu unexpected_errno=%lu iterations=%lu\n",
	       result.calls, result.accepted, result.rejected,
	       result.unexpected_signal_safe_errors, iterations);
	return 0;
}
