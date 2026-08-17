// SPDX-License-Identifier: GPL-2.0
/* Controlled host benchmark for tenant budget-check synchronization overhead. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdatomic.h>

struct worker_args {
	uint64_t iterations;
	uint64_t bytes_per_op;
	uint64_t memory_limit;
	pthread_mutex_t *budget_lock;
	atomic_uint_fast64_t *baseline_ops;
	uint64_t *checked_ops;
	uint64_t *checked_bytes;
};

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void *baseline_worker(void *opaque)
{
	struct worker_args *args = opaque;
	for (uint64_t i = 0; i < args->iterations; i++)
		atomic_fetch_add_explicit(args->baseline_ops, 1, memory_order_relaxed);
	return NULL;
}

static void *checked_worker(void *opaque)
{
	struct worker_args *args = opaque;
	for (uint64_t i = 0; i < args->iterations; i++) {
		pthread_mutex_lock(args->budget_lock);
		if (args->bytes_per_op <= args->memory_limit - *args->checked_bytes) {
			*args->checked_bytes += args->bytes_per_op;
			(*args->checked_ops)++;
		}
		pthread_mutex_unlock(args->budget_lock);
	}
	return NULL;
}

static int run_threads(unsigned threads, uint64_t iterations,
			       uint64_t bytes_per_op, int checked,
			       uint64_t *elapsed_ns, uint64_t *accepted)
{
	pthread_t *ids = calloc(threads, sizeof(*ids));
	struct worker_args *args = calloc(threads, sizeof(*args));
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	atomic_uint_fast64_t baseline_ops = 0;
	uint64_t checked_ops = 0, checked_bytes = 0, start, end;
	int ret = 0;
	if (!ids || !args)
		return ENOMEM;
	start = now_ns();
	for (unsigned i = 0; i < threads; i++) {
		args[i] = (struct worker_args){
			.iterations = iterations,
			.bytes_per_op = bytes_per_op,
			.memory_limit = UINT64_MAX / 2,
			.budget_lock = &lock,
			.baseline_ops = &baseline_ops,
			.checked_ops = &checked_ops,
			.checked_bytes = &checked_bytes,
		};
		ret = pthread_create(&ids[i], NULL,
				     checked ? checked_worker : baseline_worker,
				     &args[i]);
		if (ret)
			break;
	}
	for (unsigned i = 0; i < threads && !ret; i++)
		ret = pthread_join(ids[i], NULL);
	end = now_ns();
	*elapsed_ns = end - start;
	*accepted = checked ? checked_ops : atomic_load(&baseline_ops);
	free(args);
	free(ids);
	return ret;
}

int main(int argc, char **argv)
{
	unsigned threads = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 8;
	uint64_t iterations = argc > 2 ? strtoull(argv[2], NULL, 10) : 250000;
	uint64_t bytes = argc > 3 ? strtoull(argv[3], NULL, 10) : 4096;
	uint64_t baseline_ns, checked_ns, baseline_ops, checked_ops;
	if (threads < 2 || threads > 128 || iterations < 1000 || iterations > 10000000 ||
	    bytes == 0 || bytes > (1ULL << 20)) {
		fprintf(stderr, "invalid bounded benchmark arguments\n");
		return 2;
	}
	if (run_threads(threads, iterations, bytes, 0, &baseline_ns, &baseline_ops) ||
	    run_threads(threads, iterations, bytes, 1, &checked_ns, &checked_ops))
		return 1;
	printf("{\n");
	printf("  \"benchmark\": \"faisal-tenant-budget-check-overhead\",\n");
	printf("  \"threads\": %u,\n  \"iterations_per_thread\": %" PRIu64 ",\n", threads, iterations);
	printf("  \"bytes_per_operation\": %" PRIu64 ",\n", bytes);
	printf("  \"baseline_ops\": %" PRIu64 ",\n  \"checked_ops\": %" PRIu64 ",\n", baseline_ops, checked_ops);
	printf("  \"baseline_ns\": %" PRIu64 ",\n  \"checked_ns\": %" PRIu64 ",\n", baseline_ns, checked_ns);
	printf("  \"baseline_ops_per_second\": %.3f,\n", (double)baseline_ops * 1e9 / baseline_ns);
	printf("  \"checked_ops_per_second\": %.3f,\n", (double)checked_ops * 1e9 / checked_ns);
	printf("  \"overhead_percent\": %.3f,\n", ((double)checked_ns / baseline_ns - 1.0) * 100.0);
	printf("  \"interpretation\": \"Controlled host synchronization model; not a kernel syscall, QEMU, cgroup, GPU, NPU, or production-cluster benchmark.\"\n");
	printf("}\n");
	return 0;
}
