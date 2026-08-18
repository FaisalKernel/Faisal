#define _POSIX_C_SOURCE 200809L
#include "../../faisal-safety/faisal_safety.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ITERATIONS 10000U

static void digest(uint8_t output[FSA_DIGEST_SIZE], uint8_t value)
{
	memset(output, value == 0U ? 1U : value, FSA_DIGEST_SIZE);
}

static struct fsa_policy policy(void)
{
	struct fsa_policy value;

	memset(&value, 0, sizeof(value));
	value.abi_version = FSA_ABI_VERSION;
	value.flags = FSA_FLAG_FAIL_CLOSED;
	value.max_risk_ppm = 200000U;
	value.max_anomaly_ppm = 100000U;
	value.max_decision_age_ns = 1000U;
	value.max_token_ttl_ns = 1000U;
	value.generation = 1U;
	digest(value.policy_digest, 0xA1U);
	snprintf(value.name, sizeof(value.name), "fuzz-policy");
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
	struct fsa_service service;
	struct fsa_service mutated;
	struct fsa_policy configured = policy();
	struct fsa_decision decision;
	struct fsa_request request;
	struct stat info;
	unsigned int rejected = 0U;
	unsigned int accepted = 0U;
	unsigned int i;

	memset(&request, 0, sizeof(request));
	request.abi_version = FSA_ABI_VERSION;
	request.attestation_state = FSA_ATTESTATION_TRUSTED;
	request.workload_id = 1U;
	request.tenant_id = 1U;
	request.agent_id = 1U;
	request.generation = 1U;
	request.policy_generation = 1U;
	request.submitted_at_ns = 900U;
	request.deadline_ns = 5000U;
	request.requested_capabilities = FSA_CAP_EXECUTE;
	request.granted_capabilities = request.requested_capabilities;
	request.cpu_budget_ns = 1U;
	request.memory_limit_bytes = 1U;
	request.network_limit_bytes = 1U;
	request.storage_limit_bytes = 1U;
	request.risk_ppm = 1U;
	request.anomaly_ppm = 1U;
	request.provenance_verified = 1U;
	request.artifact_verified = 1U;
	digest(request.identity_digest, 0xB1U);
	digest(request.provenance_digest, 0xB2U);
	digest(request.artifact_digest, 0xB3U);
	digest(request.attestation_digest, 0xB4U);
	snprintf(base_path, sizeof(base_path), "/tmp/faisal-safety-fuzz-base-%ld.journal", (long)getpid());
	snprintf(mutated_path, sizeof(mutated_path), "/tmp/faisal-safety-fuzz-mutated-%ld.journal", (long)getpid());
	unlink(base_path);
	unlink(mutated_path);
	if (fsa_open(&service, base_path, &configured) != FSA_OK ||
	    fsa_evaluate(&service, &request, &decision) != FSA_OK) {
		fsa_close(&service);
		return 1;
	}
	fsa_close(&service);
	if (stat(base_path, &info) != 0 || info.st_size <= 0)
		return 1;
	for (i = 0U; i < ITERATIONS; ++i) {
		int fd;
		off_t offset;
		uint8_t byte;
		if (copy_file(base_path, mutated_path) != 0)
			return 1;
		fd = open(mutated_path, O_RDWR);
		if (fd < 0)
			return 1;
		offset = (off_t)(i % sizeof(struct fsa_event));
		if (pread(fd, &byte, sizeof(byte), offset) != (ssize_t)sizeof(byte)) {
			close(fd);
			return 1;
		}
		byte ^= (uint8_t)(1U + (i % 251U));
		if (pwrite(fd, &byte, sizeof(byte), offset) != (ssize_t)sizeof(byte) ||
		    fdatasync(fd) != 0) {
			close(fd);
			return 1;
		}
		close(fd);
		if (fsa_open(&mutated, mutated_path, &configured) == FSA_OK) {
			++accepted;
			fsa_close(&mutated);
		} else {
			++rejected;
		}
		unlink(mutated_path);
	}
	unlink(base_path);
	if (accepted != 0U || rejected != ITERATIONS)
		return 1;
	printf("M246_SAFETY_FUZZ_EXIT=0 iterations=%u rejected=%u accepted=%u base_size=%lld\n",
	       ITERATIONS, rejected, accepted, (long long)info.st_size);
	return 0;
}
