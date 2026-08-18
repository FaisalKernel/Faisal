#define _POSIX_C_SOURCE 200809L
#include "../../faisal-platform/faisal_platform.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ITERATIONS 10000U

static void digest(uint8_t out[FPL_DIGEST_SIZE], uint8_t value)
{
	memset(out, value == 0U ? 1U : value, FPL_DIGEST_SIZE);
}

static struct fpl_policy policy(void)
{
	struct fpl_policy value;

	memset(&value, 0, sizeof(value));
	value.current_time_ns = 1000U;
	value.max_intent_age_ns = 10000U;
	value.flags = FPL_REQUIRE_AUTHORITY | FPL_REQUIRE_LINEAGE |
		FPL_REQUIRE_TOPOLOGY | FPL_FAIL_CLOSED;
	value.max_workloads = FPL_MAX_WORKLOADS;
	value.max_recovery_attempts = 3U;
	digest(value.authority_digest, 0xA1U);
	return value;
}

static struct fpl_node node(void)
{
	struct fpl_node value;

	memset(&value, 0, sizeof(value));
	value.node_id = 1U;
	value.generation = 1U;
	value.total_cpu_millis = 10000U;
	value.free_cpu_millis = value.total_cpu_millis;
	value.total_memory_bytes = 1ULL << 30;
	value.free_memory_bytes = value.total_memory_bytes;
	value.total_network_mbps = 10000U;
	value.free_network_mbps = value.total_network_mbps;
	value.total_storage_bytes = 1ULL << 40;
	value.free_storage_bytes = value.total_storage_bytes;
	value.accelerator_mask = 1U;
	value.accelerator_count = 1U;
	value.capability_mask = FLE_CAP_INFERENCE;
	value.provider_mask = 1U;
	value.health_ppm = 1000000U;
	value.state = FPL_NODE_READY;
	snprintf(value.provider, sizeof(value.provider), "fuzz");
	snprintf(value.zone, sizeof(value.zone), "zone");
	snprintf(value.rack, sizeof(value.rack), "rack");
	snprintf(value.fabric, sizeof(value.fabric), "fabric");
	digest(value.attestation_digest, 0xB1U);
	return value;
}

static int copy_file(const char *source, const char *destination)
{
	int source_fd;
	int destination_fd;
	uint8_t buffer[4096];
	ssize_t count;

	source_fd = open(source, O_RDONLY);
	if (source_fd < 0)
		return 1;
	destination_fd = open(destination, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (destination_fd < 0) {
		close(source_fd);
		return 1;
	}
	while ((count = read(source_fd, buffer, sizeof(buffer))) > 0) {
		ssize_t written = 0;
		while (written < count) {
			ssize_t step = write(destination_fd, buffer + written,
					     (size_t)(count - written));
			if (step <= 0) {
				close(source_fd);
				close(destination_fd);
				return 1;
			}
			written += step;
		}
	}
	close(source_fd);
	if (close(destination_fd) != 0 || count < 0)
		return 1;
	return 0;
}

int main(void)
{
	char base_path[128];
	char mutated_path[128];
	struct fpl_service service;
	struct fpl_service mutated;
	struct fpl_policy configured = policy();
	struct fpl_node worker = node();
	struct fpl_workload workload;
	struct fpl_intent request;
	struct stat info;
	unsigned int rejected = 0U;
	unsigned int accepted = 0U;
	unsigned int i;

	snprintf(base_path, sizeof(base_path), "/tmp/faisal-platform-fuzz-base-%ld.journal", (long)getpid());
	snprintf(mutated_path, sizeof(mutated_path), "/tmp/faisal-platform-fuzz-mutated-%ld.journal", (long)getpid());
	unlink(base_path);
	unlink(mutated_path);
	if (fpl_open(&service, base_path, &configured) != FPL_OK ||
	    fpl_add_node(&service, &worker) != FPL_OK)
		return 1;
	memset(&request, 0, sizeof(request));
	request.abi_version = FPL_ABI_VERSION;
	request.provider_kind = FPL_PROVIDER_KUBERNETES_DRA;
	request.workload_id = 1U;
	request.tenant_id = 1U;
	request.agent_id = 1U;
	request.objective_id = 1U;
	request.created_at_ns = 900U;
	request.deadline_ns = 9000U;
	request.required_cpu_millis = 1U;
	request.required_memory_bytes = 1U;
	request.required_network_mbps = 1U;
	request.required_storage_bytes = 1U;
	request.required_accelerator_mask = 1U;
	request.required_accelerator_count = 1U;
	request.required_capability_mask = FLE_CAP_INFERENCE;
	request.replicas = 1U;
	request.gang_size = 1U;
	request.authorized = 1U;
	request.allow_recovery = 1U;
	snprintf(request.tenant, sizeof(request.tenant), "tenant");
	snprintf(request.model_id, sizeof(request.model_id), "model");
	snprintf(request.objective, sizeof(request.objective), "objective");
	snprintf(request.zone, sizeof(request.zone), "zone");
	snprintf(request.rack, sizeof(request.rack), "rack");
	snprintf(request.fabric, sizeof(request.fabric), "fabric");
	digest(request.lineage_digest, 0xC1U);
	digest(request.policy_digest, 0xC2U);
	digest(request.provider_claim_digest, 0xC3U);
	if (fpl_submit(&service, &request, &workload) != FPL_OK ||
	    fpl_place(&service, request.workload_id, &workload) != FPL_OK) {
		fpl_close(&service);
		return 1;
	}
	fpl_close(&service);
	if (stat(base_path, &info) != 0 || info.st_size <= 0)
		return 1;
	for (i = 0U; i < ITERATIONS; ++i) {
		int fd;
		off_t offset;
		if (copy_file(base_path, mutated_path) != 0)
			return 1;
		fd = open(mutated_path, O_RDWR);
		if (fd < 0)
			return 1;
		offset = (off_t)(i % (sizeof(struct fpl_event)));
		{
			uint8_t byte;
			if (pread(fd, &byte, sizeof(byte), offset) != (ssize_t)sizeof(byte)) {
				close(fd);
				return 1;
			}
			byte ^= (uint8_t)(1U + (i % 251U));
			if (pwrite(fd, &byte, sizeof(byte), offset) != (ssize_t)sizeof(byte)) {
				close(fd);
				return 1;
			}
		}
		if (fdatasync(fd) != 0) {
			close(fd);
			return 1;
		}
		close(fd);
		if (fpl_open(&mutated, mutated_path, &configured) == FPL_OK) {
			++accepted;
			fpl_close(&mutated);
		} else {
			++rejected;
		}
		unlink(mutated_path);
	}
	unlink(base_path);
	if (accepted != 0U || rejected != ITERATIONS)
		return 1;
	printf("M245_PLATFORM_FUZZ_EXIT=0 iterations=%u rejected=%u accepted=%u base_size=%lld\n",
	       ITERATIONS, rejected, accepted, (long long)info.st_size);
	return 0;
}
