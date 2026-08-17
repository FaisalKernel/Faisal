#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/agi_lifecycle.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FAISAL_MT_MAX_TENANTS 8U
#define FAISAL_MT_BATCH_SIZE 4U
#define FAISAL_MT_DEFAULT_ITERATIONS 256U
#define FAISAL_MT_WARMUP_ITERATIONS 8U
#define FAISAL_MT_MEMORY_BYTES (64ULL * 1024 * 1024)

struct faisal_mt_context {
	int fd;
	int cgroup_fd;
	char cgroup_path[128];
	struct agi_lc_tenant_cgroup tenant_cgroup;
	struct agi_lc_accel_device accel;
	struct agi_lc_accel_device_account entries[FAISAL_MT_BATCH_SIZE];
	struct agi_lc_accel_device_account_batch batch;
};

struct faisal_mt_result {
	uint32_t tenant;
	uint32_t iterations;
	uint32_t failures;
	uint32_t reserved;
	uint64_t total_ns;
	uint64_t elapsed_ns;
	uint64_t min_ns;
	uint64_t max_ns;
	uint64_t p50_ns;
	uint64_t p95_ns;
	uint64_t p99_ns;
};

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL +
		(uint64_t)ts.tv_nsec;
}

static int read_all(int fd, void *buffer, size_t size)
{
	char *cursor = buffer;

	while (size) {
		ssize_t count = read(fd, cursor, size);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

static int write_all(int fd, const void *buffer, size_t size)
{
	const char *cursor = buffer;

	while (size) {
		ssize_t count = write(fd, cursor, size);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		cursor += count;
		size -= (size_t)count;
	}
	return 0;
}

static int drain_records(int fd)
{
	struct agi_lc_record record;
	int original_flags = fcntl(fd, F_GETFL, 0);

	if (original_flags < 0 ||
	    fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) < 0)
		return -1;
	for (;;) {
		ssize_t count = read(fd, &record, sizeof(record));

		if (count == (ssize_t)sizeof(record))
			continue;
		if (count < 0 && (errno == EAGAIN || errno == EINTR)) {
			if (errno == EINTR)
				continue;
			break;
		}
		(void)fcntl(fd, F_SETFL, original_flags);
		return -1;
	}
	return fcntl(fd, F_SETFL, original_flags);
}

static int move_pid_to(const char *path)
{
	int fd;
	char pid[32];
	int length;
	int ret;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	length = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
	ret = length > 0 && write_all(fd, pid, (size_t)length) == 0 ? 0 : -1;
	close(fd);
	return ret;
}

static void cleanup_context(struct faisal_mt_context *context)
{
	struct agi_lc_accel_device accel_remove = {
		.size = sizeof(accel_remove),
		.device_id = context->accel.device_id,
	};
	struct agi_lc_tenant_cgroup release = {
		.size = sizeof(release),
		.operation = AGI_LC_TENANT_CGROUP_RELEASE,
		.cgroup_fd = -1,
	};

	if (context->fd < 0)
		return;
	(void)move_pid_to("/sys/fs/cgroup/cgroup.procs");
	if (context->accel.device_id)
		(void)ioctl(context->fd, AGI_LC_ACCEL_UNREGISTER, &accel_remove);
	if (context->tenant_cgroup.cgroup_id)
		(void)ioctl(context->fd, AGI_LC_TENANT_CGROUP, &release);
	if (context->cgroup_fd >= 0)
		close(context->cgroup_fd);
	if (context->cgroup_path[0])
		(void)rmdir(context->cgroup_path);
	close(context->fd);
	context->fd = -1;
}

static int setup_context(struct faisal_mt_context *context, uint32_t tenant)
{
	struct agi_lc_create create = { .size = sizeof(create) };
	struct agi_lc_sandbox_binding sandbox = {
		.size = sizeof(sandbox),
		.operation = AGI_LC_SANDBOX_BIND,
	};
	struct agi_lc_light_agent light = {
		.size = sizeof(light),
		.role = AGI_LC_LIGHT_AGENT_ROLE_INFRASTRUCTURE,
		.workload = AGI_LC_WORKLOAD_VERIFICATION,
		.correlation = 164000 + tenant,
	};
	struct agi_lc_agent agent = {
		.size = sizeof(agent),
		.correlation = 164050 + tenant,
	};
	struct agi_lc_accel_device accel = {
		.size = sizeof(accel),
		.type = AGI_LC_ACCEL_TYPE_GPU,
		.capabilities = AGI_LC_ACCEL_CAP_DEVICE_MEMORY,
		.accounting_flags = AGI_LC_ACCEL_ACCOUNT_MEMORY,
		.isolation_flags = AGI_LC_ACCEL_ISOLATION_TENANT_MEMORY,
		.total_memory_bytes = FAISAL_MT_MEMORY_BYTES,
		.available_memory_bytes = FAISAL_MT_MEMORY_BYTES,
		.name = "qemu-multi-tenant-gpu",
		.driver = "faisal-multi-tenant-benchmark",
		.correlation = 164200 + tenant,
	};
	struct agi_lc_subscribe telemetry_disable = {
		.size = sizeof(telemetry_disable),
		.event_mask = 0,
		.correlation = 164150 + tenant,
	};
	struct agi_lc_tenant_cgroup bind = {
		.size = sizeof(bind),
		.flags = AGI_LC_TENANT_CGROUP_FLAG_REQUIRE_SANDBOX,
		.operation = AGI_LC_TENANT_CGROUP_BIND,
		.cgroup_fd = -1,
		.correlation = 164100 + tenant,
	};

	memset(context, 0, sizeof(*context));
	context->fd = -1;
	context->cgroup_fd = -1;
	context->fd = open("/dev/agi_lifecycle", O_RDWR);
	if (context->fd < 0)
		return -1;
	if (ioctl(context->fd, AGI_LC_CREATE, &create) < 0 ||
	    ioctl(context->fd, AGI_LC_ATTACH_TASK) < 0 ||
	    ioctl(context->fd, AGI_LC_SANDBOX, &sandbox) < 0 ||
	    sandbox.state != AGI_LC_SANDBOX_STATE_BOUND ||
	    !sandbox.binding_id ||
	    ioctl(context->fd, AGI_LC_LIGHT_AGENT_REGISTER, &light) < 0 ||
	    !light.agent_id || !light.capability)
		goto fail;
	agent.agent_id = light.agent_id;
	if (ioctl(context->fd, AGI_LC_SET_AGENT, &agent) < 0)
		goto fail;
	if (snprintf(context->cgroup_path, sizeof(context->cgroup_path),
			     "/sys/fs/cgroup/faisal-mt-%ld-%u",
			     (long)getpid(), tenant) <= 0)
		goto fail;
	if (mkdir(context->cgroup_path, 0755) < 0)
		goto fail;
	context->cgroup_fd = open(context->cgroup_path, O_RDONLY | O_DIRECTORY);
	if (context->cgroup_fd < 0)
		goto fail;
	bind.cgroup_fd = context->cgroup_fd;
	if (ioctl(context->fd, AGI_LC_TENANT_CGROUP, &bind) < 0 ||
	    bind.status != AGI_LC_TENANT_CGROUP_STATUS_BOUND ||
	    bind.hierarchy_owner_id != create.session_id)
		goto fail;
	context->tenant_cgroup = bind;
	{
		char cgroup_procs_path[sizeof(context->cgroup_path) + 16];

		if (snprintf(cgroup_procs_path, sizeof(cgroup_procs_path),
			     "%s/cgroup.procs", context->cgroup_path) <= 0 ||
		    move_pid_to(cgroup_procs_path) < 0)
			goto fail;
	}
	if (ioctl(context->fd, AGI_LC_ACCEL_REGISTER, &accel) < 0 ||
	    !accel.device_id || accel.owner_session_id != create.session_id ||
	    accel.owner_cgroup_id != bind.cgroup_id)
		goto fail;
	context->accel = accel;
	if (ioctl(context->fd, AGI_LC_SUBSCRIBE, &telemetry_disable) < 0 ||
	    drain_records(context->fd) < 0)
		goto fail;
	context->batch.size = sizeof(context->batch);
	context->batch.entries_ptr = (uint64_t)(uintptr_t)context->entries;
	context->batch.entry_count = FAISAL_MT_BATCH_SIZE;
	return 0;

fail:
	cleanup_context(context);
	return -1;
}

static void reset_batch_entries(struct faisal_mt_context *context,
				uint32_t tenant, uint32_t iteration)
{
	for (uint32_t i = 0; i < FAISAL_MT_BATCH_SIZE; i++) {
		memset(&context->entries[i], 0, sizeof(context->entries[i]));
		context->entries[i].size = sizeof(context->entries[i]);
		context->entries[i].flags = AGI_LC_ACCEL_ACCOUNT_MEMORY;
		context->entries[i].device_id = context->accel.device_id;
		context->entries[i].correlation = 164300 +
			(uint64_t)tenant * 4096ULL +
			(uint64_t)iteration * FAISAL_MT_BATCH_SIZE + i;
	}
}

static int compare_u64(const void *left, const void *right)
{
	uint64_t a = *(const uint64_t *)left;
	uint64_t b = *(const uint64_t *)right;

	return a > b ? 1 : a < b ? -1 : 0;
}

static uint64_t percentile(const uint64_t *samples, uint32_t count,
			   uint32_t percentile_value)
{
	uint32_t index = (count * percentile_value + 99U) / 100U;

	if (!index)
		index = 1;
	if (index > count)
		index = count;
	return samples[index - 1];
}

static int report_result(int result_fd, struct faisal_mt_result *result)
{
	return write_all(result_fd, result, sizeof(*result));
}

static int benchmark_worker(uint32_t tenant, uint32_t iterations,
			    int ready_fd, int start_fd, int result_fd)
{
	struct faisal_mt_context context;
	struct faisal_mt_result result = {
		.tenant = tenant,
		.iterations = iterations,
	};
	uint64_t *samples;
	uint64_t measure_start_ns;
	char ready = 'R';
	char start;

	if (setup_context(&context, tenant) < 0) {
		ready = 'F';
		(void)write_all(ready_fd, &ready, 1);
		return 2;
	}
	if (write_all(ready_fd, &ready, 1) < 0 ||
	    read_all(start_fd, &start, 1) < 0) {
		cleanup_context(&context);
		return 2;
	}
	samples = calloc(iterations, sizeof(*samples));
	if (!samples) {
		cleanup_context(&context);
		return 2;
	}
	for (uint32_t i = 0; i < FAISAL_MT_WARMUP_ITERATIONS; i++) {
		reset_batch_entries(&context, tenant, i);
		context.batch.completed = 0;
		context.batch.status = 0;
		if (ioctl(context.fd, AGI_LC_ACCEL_DEVICE_ACCOUNT_BATCH,
			  &context.batch) < 0)
			result.failures++;
	}
	measure_start_ns = monotonic_ns();
	for (uint32_t i = 0; i < iterations; i++) {
		uint64_t start_ns = monotonic_ns();
		uint64_t end_ns;

		reset_batch_entries(&context, tenant,
				    FAISAL_MT_WARMUP_ITERATIONS + i);
		context.batch.completed = 0;
		context.batch.status = 0;
		if (ioctl(context.fd, AGI_LC_ACCEL_DEVICE_ACCOUNT_BATCH,
			  &context.batch) < 0) {
			result.failures++;
			continue;
		}
		end_ns = monotonic_ns();
		if (!start_ns || !end_ns || end_ns < start_ns) {
			result.failures++;
			continue;
		}
		samples[i] = end_ns - start_ns;
		result.total_ns += samples[i];
		if (!result.min_ns || samples[i] < result.min_ns)
			result.min_ns = samples[i];
		if (samples[i] > result.max_ns)
			result.max_ns = samples[i];
	}
	result.elapsed_ns = monotonic_ns() - measure_start_ns;
	if (result.failures || result.total_ns == 0 || !result.elapsed_ns) {
		free(samples);
		cleanup_context(&context);
		(void)report_result(result_fd, &result);
		return 2;
	}
	qsort(samples, iterations, sizeof(*samples), compare_u64);
	result.p50_ns = percentile(samples, iterations, 50);
	result.p95_ns = percentile(samples, iterations, 95);
	result.p99_ns = percentile(samples, iterations, 99);
	free(samples);
	if (report_result(result_fd, &result) < 0) {
		cleanup_context(&context);
		return 2;
	}
	cleanup_context(&context);
	return 0;
}

static int run_level(uint32_t tenants, uint32_t iterations)
{
	int ready_pipe[2];
	int start_pipe[2];
	int result_pipe[2];
	pid_t children[FAISAL_MT_MAX_TENANTS] = { 0 };
	struct faisal_mt_result results[FAISAL_MT_MAX_TENANTS];
	uint64_t aggregate_ops;
	uint64_t wall_elapsed_ns = 0;
	uint64_t median_sum = 0;
	uint64_t max_p95 = 0;
	uint64_t max_p99 = 0;
	uint64_t max_max = 0;
	uint32_t ready_count = 0;
	uint32_t result_count = 0;
	uint32_t failures = 0;
	char ready;
	char starts[FAISAL_MT_MAX_TENANTS];

	memset(starts, 'S', sizeof(starts));
	if (pipe(ready_pipe) < 0 || pipe(start_pipe) < 0 ||
	    pipe(result_pipe) < 0)
		return -1;
	for (uint32_t i = 0; i < tenants; i++) {
		children[i] = fork();
		if (children[i] < 0)
			goto kill_children;
		if (children[i] == 0) {
			int rc;

			close(ready_pipe[0]);
			close(start_pipe[1]);
			close(result_pipe[0]);
			rc = benchmark_worker(i + 1, iterations, ready_pipe[1],
					      start_pipe[0], result_pipe[1]);
			close(ready_pipe[1]);
			close(start_pipe[0]);
			close(result_pipe[1]);
			_exit(rc);
		}
	}
	close(ready_pipe[1]);
	close(start_pipe[0]);
	close(result_pipe[1]);
	while (ready_count < tenants) {
		if (read_all(ready_pipe[0], &ready, 1) < 0 || ready != 'R')
			goto kill_parent_children;
		ready_count++;
	}
	close(ready_pipe[0]);
	if (write_all(start_pipe[1], starts, tenants) < 0)
		goto kill_parent_children;
	close(start_pipe[1]);
	while (result_count < tenants) {
		if (read_all(result_pipe[0], &results[result_count],
			     sizeof(results[result_count])) < 0)
			goto kill_parent_children;
		result_count++;
	}
	close(result_pipe[0]);
	for (uint32_t i = 0; i < tenants; i++) {
		int status;

		if (waitpid(children[i], &status, 0) != children[i] ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			failures++;
		if (results[i].elapsed_ns > wall_elapsed_ns)
			wall_elapsed_ns = results[i].elapsed_ns;
	}
	aggregate_ops = (uint64_t)tenants * iterations * FAISAL_MT_BATCH_SIZE;
	for (uint32_t i = 0; i < tenants; i++) {
		median_sum += results[i].p50_ns;
		if (results[i].p95_ns > max_p95)
			max_p95 = results[i].p95_ns;
		if (results[i].p99_ns > max_p99)
			max_p99 = results[i].p99_ns;
		if (results[i].max_ns > max_max)
			max_max = results[i].max_ns;
		failures += results[i].failures;
		printf("FAISAL_MT_TENANT_LATENCY tenant=%u iterations=%u elapsed_ns=%llu min_ns=%llu p50_ns=%llu p95_ns=%llu p99_ns=%llu max_ns=%llu failures=%u\n",
		       results[i].tenant, results[i].iterations,
		       (unsigned long long)results[i].elapsed_ns,
		       (unsigned long long)results[i].min_ns,
		       (unsigned long long)results[i].p50_ns,
		       (unsigned long long)results[i].p95_ns,
		       (unsigned long long)results[i].p99_ns,
		       (unsigned long long)results[i].max_ns, results[i].failures);
	}
	printf("FAISAL_MT_LEVEL_OK tenants=%u iterations=%u batch=%u aggregate_ops=%llu wall_ns=%llu aggregate_ops_s_x100=%llu avg_p50_ns=%llu max_p95_ns=%llu max_p99_ns=%llu max_ns=%llu failures=%u\n",
	       tenants, iterations, FAISAL_MT_BATCH_SIZE,
	       (unsigned long long)aggregate_ops,
	       (unsigned long long)wall_elapsed_ns,
	       (unsigned long long)(wall_elapsed_ns ?
					aggregate_ops * 100000000000ULL / wall_elapsed_ns : 0),
	       (unsigned long long)(median_sum / tenants),
	       (unsigned long long)max_p95,
	       (unsigned long long)max_p99,
	       (unsigned long long)max_max, failures);
	return failures ? -1 : 0;

kill_parent_children:
	close(ready_pipe[0]);
	close(start_pipe[1]);
	close(result_pipe[0]);
kill_children:
	for (uint32_t i = 0; i < tenants; i++)
		if (children[i] > 0)
			(void)kill(children[i], SIGKILL);
	for (uint32_t i = 0; i < tenants; i++)
		if (children[i] > 0)
			(void)waitpid(children[i], NULL, 0);
	return -1;
}

int main(int argc, char **argv)
{
	uint32_t tenants = argc > 1 ? (uint32_t)strtoul(argv[1], NULL, 10) : 1;
	uint32_t iterations = argc > 2 ? (uint32_t)strtoul(argv[2], NULL, 10) :
		FAISAL_MT_DEFAULT_ITERATIONS;

	if (!tenants || tenants > FAISAL_MT_MAX_TENANTS || !iterations ||
	    iterations > 4096)
		return 2;
	printf("FAISAL_MT_BENCH_START tenants=%u iterations=%u batch=%u\n",
	       tenants, iterations, FAISAL_MT_BATCH_SIZE);
	if (run_level(tenants, iterations) < 0)
		return 1;
	printf("FAISAL_MT_BENCH_DONE tenants=%u iterations=%u\n",
	       tenants, iterations);
	return 0;
}
