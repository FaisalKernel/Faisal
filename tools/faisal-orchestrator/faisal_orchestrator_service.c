#define _GNU_SOURCE
#include "faisal_orchestrator_service.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int digest_bytes(const void *data, size_t len,
			unsigned char digest[FMO_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 0;
	int ret = -1;
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, len) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &out_len) == 1 &&
	    out_len == FMO_DIGEST_SIZE)
		ret = 0;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int nonzero_digest(const uint8_t digest[FMO_DIGEST_SIZE])
{
	uint32_t i;
	for (i = 0; i < FMO_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

static int request_digest(const struct fmo_request *request,
			  uint8_t digest[FMO_DIGEST_SIZE])
{
	return digest_bytes(request, sizeof(*request), digest);
}

void fmo_policy_default(struct fmo_policy *policy)
{
	if (!policy)
		return;
	memset(policy, 0, sizeof(*policy));
	policy->max_cpu_time_ns = 2000000000ULL;
	policy->max_memory_pages = 65536ULL;
	policy->policy_generation = 1;
	policy->require_supervisor = 1;
	policy->require_operator = 1;
}

int fmo_open(struct fmo_service *service, const char *journal_path)
{
	int ret;
	if (!service)
		return -1;
	memset(service, 0, sizeof(*service));
	fmo_policy_default(&service->policy);
	ret = fms_open(&service->memory, journal_path);
	return ret == FMS_OK ? 0 : ret;
}

void fmo_close(struct fmo_service *service)
{
	if (service)
		fms_close(&service->memory);
}

static int validate_request(const struct fmo_service *service,
			    const struct fmo_request *request)
{
	if (!service || !request || !*request->model_id ||
	    strlen(request->model_id) >= FMO_MAX_MODEL_ID ||
	    !nonzero_digest(request->model_digest) || !request->cpu_time_ns ||
	    !request->memory_pages || request->workload < FMO_WORKLOAD_INFERENCE ||
	    request->workload > FMO_WORKLOAD_MAX || request->reserved ||
	    request->cpu_time_ns > service->policy.max_cpu_time_ns ||
	    request->memory_pages > service->policy.max_memory_pages ||
	    (service->policy.require_supervisor && request->supervisor_approved != 1) ||
	    (service->policy.require_operator && request->operator_approved != 1) ||
	    !request->supervisor_nonce || !request->operator_nonce ||
	    request->supervisor_nonce == request->operator_nonce)
		return -1;
	return 0;
}

static int kernel_budget(struct fmo_service *service,
			 const struct fmo_request *request)
{
	struct agi_lc_budget budget;
	struct agi_lc_memory_budget memory;
	struct agi_lc_gate gate;
	memset(&budget, 0, sizeof(budget));
	budget.size = sizeof(budget);
	budget.cpu_time_ns = request->cpu_time_ns;
	budget.correlation = 74001;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SET_BUDGET, &budget) < 0)
		return -1;
	memset(&memory, 0, sizeof(memory));
	memory.size = sizeof(memory);
	memory.limit_pages = request->memory_pages;
	memory.correlation = 74002;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SET_MEMORY_BUDGET, &memory) < 0)
		return -1;
	memset(&gate, 0, sizeof(gate));
	gate.size = sizeof(gate);
	gate.open = 0;
	gate.correlation = 74003;
	if (ioctl(service->memory.kernel_fd, AGI_LC_SET_GATE, &gate) < 0)
		return -1;
	return 0;
}

static int kernel_checkpoint(struct fmo_service *service,
			     const struct fmo_request *request,
			     const uint8_t state_digest[FMO_DIGEST_SIZE],
			     struct fmo_run *run)
{
	struct agi_lc_checkpoint checkpoint;
	struct agi_lc_checkpoint_manifest manifest;
	struct agi_lc_verify verify;
	struct agi_lc_handoff handoff;
	if (kernel_budget(service, request) < 0)
		return -1;
	memset(&checkpoint, 0, sizeof(checkpoint));
	checkpoint.size = sizeof(checkpoint);
	checkpoint.checkpoint_id = 74000ULL + service->run_count + 1;
	memcpy(checkpoint.state_digest, state_digest, FMO_DIGEST_SIZE);
	checkpoint.correlation = 74004;
	if (ioctl(service->memory.kernel_fd, AGI_LC_CHECKPOINT, &checkpoint) < 0)
		return -1;
	memset(&manifest, 0, sizeof(manifest));
	manifest.size = sizeof(manifest);
	manifest.checkpoint_id = checkpoint.checkpoint_id;
	manifest.scope_flags = AGI_LC_CHECKPOINT_SCOPE_TASK |
		AGI_LC_CHECKPOINT_SCOPE_RESOURCES |
		AGI_LC_CHECKPOINT_SCOPE_USER_STATE;
	manifest.resource_policy = AGI_LC_CHECKPOINT_RESOURCE_USERSPACE;
	memcpy(manifest.user_state_digest, state_digest, FMO_DIGEST_SIZE);
	manifest.correlation = 74005;
	if (ioctl(service->memory.kernel_fd, AGI_LC_CHECKPOINT_MANIFEST,
		  &manifest) < 0)
		return -1;
	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.state = AGI_LC_VERIFY_UNVERIFIED;
	verify.checkpoint_id = checkpoint.checkpoint_id;
	verify.checkpoint_sequence = checkpoint.checkpoint_sequence;
	verify.parent_sequence = checkpoint.parent_sequence;
	memcpy(verify.state_digest, state_digest, FMO_DIGEST_SIZE);
	verify.correlation = 74006;
	if (ioctl(service->memory.kernel_fd, AGI_LC_VERIFY_CHECKPOINT, &verify) < 0 ||
	    verify.status || verify.state != AGI_LC_VERIFY_MATCHED)
		return -1;
	memset(&handoff, 0, sizeof(handoff));
	handoff.size = sizeof(handoff);
	handoff.correlation = 74007;
	if (ioctl(service->memory.kernel_fd, AGI_LC_EXPORT_CHECKPOINT, &handoff) < 0 ||
	    !handoff.validated)
		return -1;
	run->checkpoint_id = checkpoint.checkpoint_id;
	run->checkpoint_sequence = checkpoint.checkpoint_sequence;
	run->parent_sequence = checkpoint.parent_sequence;
	memcpy(run->state_digest, state_digest, FMO_DIGEST_SIZE);
	memcpy(run->manifest_digest, manifest.manifest_digest, FMO_DIGEST_SIZE);
	run->handoff = handoff;
	run->state = FMO_CHECKPOINTED;
	return 0;
}

int fmo_admit(struct fmo_service *service, const struct fmo_request *request,
		      struct fmo_run *out)
{
	struct fmo_run run;
	struct fms_entry memory;
	uint8_t state_digest[FMO_DIGEST_SIZE];
	char content[256];
	if (validate_request(service, request) < 0 || !out ||
	    service->run_count >= FMO_MAX_RUNS)
		return -1;
	if (request_digest(request, state_digest) < 0)
		return -1;
	memset(&run, 0, sizeof(run));
	run.run_id = service->run_count + 1;
	run.policy_generation = service->policy.policy_generation;
	run.proposed_action_mask = request->proposed_action_mask;
	memcpy(run.model_digest, request->model_digest, FMO_DIGEST_SIZE);
	if (kernel_checkpoint(service, request, state_digest, &run) < 0)
		return -2;
	snprintf(content, sizeof(content), "admission:model=%s:run=%llu:checkpoint=%llu",
		 request->model_id, (unsigned long long)run.run_id,
		 (unsigned long long)run.checkpoint_id);
	if (fms_put(&service->memory, content, AGI_LC_MEMORY_TIER_EPISODIC,
			900000, 900000, run.checkpoint_sequence, &memory) != FMS_OK)
		return -3;
	run.memory_record_id = memory.record_id;
	run.memory_capability = memory.authority_capability;
	run.state = FMO_ADMITTED;
	service->runs[service->run_count++] = run;
	*out = run;
	return 0;
}

int fmo_record_output(struct fmo_service *service, struct fmo_run *run,
		      const char *output, uint32_t policy_accepts_format)
{
	struct fms_entry memory;
	char content[FMO_MAX_OUTPUT + 32];
	if (!service || !run || !output || !*output ||
	    strlen(output) >= FMO_MAX_OUTPUT || run->state < FMO_ADMITTED)
		return -1;
	if (digest_bytes(output, strlen(output), run->output_digest) < 0)
		return -1;
	snprintf(content, sizeof(content), "model-output:run=%llu:%s",
		 (unsigned long long)run->run_id, output);
	if (fms_put(&service->memory, content, AGI_LC_MEMORY_TIER_EPISODIC,
			policy_accepts_format ? 500000 : 200000,
			policy_accepts_format ? 500000 : 200000,
			run->checkpoint_sequence, &memory) != FMS_OK)
		return -2;
	run->memory_record_id = memory.record_id;
	run->memory_capability = memory.authority_capability;
	run->state = policy_accepts_format ? FMO_OUTPUT_PROPOSED : FMO_DENIED;
	return policy_accepts_format ? 0 : -3;
}

int fmo_rollback(struct fmo_service *service, struct fmo_run *run)
{
	struct agi_lc_recovery recovery;
	struct agi_lc_handoff handoff;
	if (!service || !run || run->state < FMO_CHECKPOINTED ||
	    !run->checkpoint_id || !run->checkpoint_sequence ||
	    !nonzero_digest(run->manifest_digest))
		return -1;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_MARK_CRASH;
	recovery.checkpoint_id = run->checkpoint_id;
	recovery.checkpoint_sequence = run->checkpoint_sequence;
	recovery.parent_sequence = run->parent_sequence;
	memcpy(recovery.user_state_digest, run->state_digest, FMO_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, run->manifest_digest, FMO_DIGEST_SIZE);
	recovery.correlation = 74008;
	if (ioctl(service->memory.kernel_fd, AGI_LC_RECOVERY, &recovery) < 0)
		return -2;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_RESTORE_BEGIN;
	recovery.checkpoint_id = run->checkpoint_id;
	recovery.checkpoint_sequence = run->checkpoint_sequence;
	recovery.parent_sequence = run->parent_sequence;
	memcpy(recovery.user_state_digest, run->state_digest, FMO_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, run->manifest_digest, FMO_DIGEST_SIZE);
	recovery.correlation = 74009;
	if (ioctl(service->memory.kernel_fd, AGI_LC_RECOVERY, &recovery) < 0)
		return -3;
	handoff = run->handoff;
	handoff.validated = 0;
	handoff.correlation = 74010;
	if (ioctl(service->memory.kernel_fd, AGI_LC_IMPORT_CHECKPOINT, &handoff) < 0 ||
	    !handoff.validated)
		return -4;
	memset(&recovery, 0, sizeof(recovery));
	recovery.size = sizeof(recovery);
	recovery.action = AGI_LC_RECOVERY_CONTINUE;
	recovery.checkpoint_id = run->checkpoint_id;
	recovery.checkpoint_sequence = run->checkpoint_sequence;
	recovery.parent_sequence = run->parent_sequence;
	memcpy(recovery.user_state_digest, run->state_digest, FMO_DIGEST_SIZE);
	memcpy(recovery.manifest_digest, run->manifest_digest, FMO_DIGEST_SIZE);
	recovery.correlation = 74011;
	if (ioctl(service->memory.kernel_fd, AGI_LC_RECOVERY, &recovery) < 0 ||
	    recovery.state != AGI_LC_RECOVERY_CONTINUED)
		return -5;
	run->recovery_sequence = recovery.recovery_sequence;
	run->recovery_state = recovery.state;
	run->state = FMO_ROLLED_BACK;
	return 0;
}

int fmo_test_policy_denials(struct fmo_service *service,
			     const struct fmo_request *valid_request)
{
	struct fmo_request request;
	struct fmo_run run;
	if (!service || !valid_request)
		return -1;
	request = *valid_request;
	request.operator_approved = 0;
	if (fmo_admit(service, &request, &run) == 0)
		return -2;
	request = *valid_request;
	request.cpu_time_ns = service->policy.max_cpu_time_ns + 1;
	if (fmo_admit(service, &request, &run) == 0)
		return -3;
	request = *valid_request;
	request.operator_nonce = request.supervisor_nonce;
	if (fmo_admit(service, &request, &run) == 0)
		return -4;
	request = *valid_request;
	request.workload = FMO_WORKLOAD_MAX + 1;
	if (fmo_admit(service, &request, &run) == 0)
		return -5;
	return 0;
}

int fmo_test_output_is_untrusted(const struct fmo_run *run)
{
	if (!run || run->state != FMO_OUTPUT_PROPOSED || !run->output_digest[0])
		return -1;
	if (!run->proposed_action_mask)
		return -2;
	return run->memory_capability ? 0 : -3;
}
