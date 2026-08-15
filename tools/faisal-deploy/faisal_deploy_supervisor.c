#define _GNU_SOURCE
#include "faisal_deploy_supervisor.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

static int nonzero_digest(const uint8_t digest[M78_DIGEST_SIZE])
{
	uint32_t i;
	for (i = 0; i < M78_DIGEST_SIZE; i++)
		if (digest[i])
			return 1;
	return 0;
}

uint64_t m78_candidate_digest(const struct m78_candidate *candidate)
{
	const unsigned char *p;
	uint64_t hash = 1469598103934665603ULL;
	size_t i;
	if (!candidate)
		return 0;
	p = (const unsigned char *)candidate->build_id;
	for (i = 0; i < sizeof(candidate->build_id); i++) {
		hash ^= p[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

int m78_compute_candidate_digest(const struct m78_candidate *candidate,
				 uint8_t digest[M78_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	int result = -1;
	if (!candidate || !digest)
		return -1;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, candidate->build_id,
			     sizeof(candidate->build_id)) == 1 &&
	    EVP_DigestUpdate(ctx, candidate->state_digest,
			     sizeof(candidate->state_digest)) == 1 &&
	    EVP_DigestUpdate(ctx, &candidate->policy_generation,
			     sizeof(candidate->policy_generation)) == 1 &&
	    EVP_DigestUpdate(ctx, &candidate->cpu_budget_ns,
			     sizeof(candidate->cpu_budget_ns)) == 1 &&
	    EVP_DigestUpdate(ctx, &candidate->memory_limit_pages,
			     sizeof(candidate->memory_limit_pages)) == 1 &&
	    EVP_DigestUpdate(ctx, &candidate->canary_window_ns,
			     sizeof(candidate->canary_window_ns)) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
	    length == M78_DIGEST_SIZE)
		result = 0;
	EVP_MD_CTX_free(ctx);
	return result;
}

int m78_validate_candidate(const struct m78_candidate *candidate)
{
	if (!candidate || !candidate->build_id[0] ||
	    strnlen(candidate->build_id, M78_MAX_BUILD_ID) >= M78_MAX_BUILD_ID ||
	    !candidate->cpu_budget_ns || candidate->cpu_budget_ns > 60000000000ULL ||
	    !candidate->memory_limit_pages || candidate->memory_limit_pages > (1ULL << 20) ||
	    !candidate->canary_window_ns || candidate->canary_window_ns > 60000000000ULL ||
	    candidate->required_approvals != (M78_APPROVAL_SUPERVISOR |
					       M78_APPROVAL_OPERATOR |
					       M78_APPROVAL_INTEGRITY |
					       M78_APPROVAL_CANARY) ||
	    !candidate->supervisor_approved || !candidate->operator_approved ||
	    !candidate->integrity_measured || candidate->reserved ||
	    !candidate->supervisor_nonce || !candidate->operator_nonce ||
	    candidate->supervisor_nonce == candidate->operator_nonce ||
	    !nonzero_digest(candidate->artifact_digest) ||
	    !nonzero_digest(candidate->state_digest))
		return -1;
	return 0;
}

static void audit_append(struct m78_service *service, uint32_t reason)
{
	struct m78_audit_record *audit;
	if (!service || service->deployment.audit_count >= M78_MAX_AUDIT)
		return;
	audit = &service->deployment.audit[service->deployment.audit_count++];
	memset(audit, 0, sizeof(*audit));
	audit->sequence = ++service->deployment.audit_sequence;
	audit->candidate_generation = service->deployment.candidate.policy_generation;
	audit->state = service->deployment.state;
	audit->reason = reason;
	audit->checkpoint_id = service->deployment.checkpoint.checkpoint_id;
	audit->recovery_sequence = service->deployment.recovery.recovery_sequence;
	audit->provenance_sequence = service->deployment.provenance_sequence;
	audit->sampled_at_ns = service->deployment.snapshot.sampled_at_ns;
	audit->measured_mask = service->deployment.snapshot.measured_mask;
	audit->unavailable_mask = service->deployment.snapshot.unavailable_mask;
	audit->unsupported_mask = service->deployment.snapshot.unsupported_mask;
	memcpy(audit->artifact_digest, service->deployment.candidate.artifact_digest,
	       M78_DIGEST_SIZE);
}

int m78_open(struct m78_service *service, const char *journal_path)
{
	if (!service || !journal_path || !*journal_path)
		return -1;
	memset(service, 0, sizeof(*service));
	return fms_open(&service->memory, journal_path) == FMS_OK ? 0 : -1;
}

void m78_close(struct m78_service *service)
{
	if (service)
		fms_close(&service->memory);
}

int m78_admit(struct m78_service *service, const struct m78_candidate *candidate)
{
	struct fms_entry entry;
	char audit_payload[FMS_MAX_CONTENT];
	uint8_t digest[M78_DIGEST_SIZE];
	if (!service || !candidate || m78_validate_candidate(candidate) != 0 ||
	    m78_compute_candidate_digest(candidate, digest) != 0 ||
	    memcmp(digest, candidate->artifact_digest, M78_DIGEST_SIZE)) {
		if (service)
			service->deployment.state = M78_STATE_DENIED;
		return -1;
	}
	service->deployment.candidate = *candidate;
	service->deployment.state = M78_STATE_CANDIDATE;
	if (snprintf(audit_payload, sizeof(audit_payload),
		     "M78 candidate admitted build=%s supervisor=%llu operator=%llu",
		     candidate->build_id,
		     (unsigned long long)candidate->supervisor_nonce,
		     (unsigned long long)candidate->operator_nonce) < 0 ||
	    fms_put(&service->memory, audit_payload, AGI_LC_MEMORY_TIER_EPISODIC,
		    1000000, 1000000, 0, &entry) != FMS_OK)
		return -1;
	service->deployment.provenance_sequence = entry.provenance_sequence;
	audit_append(service, M78_APPROVAL_SUPERVISOR | M78_APPROVAL_OPERATOR |
			    M78_APPROVAL_INTEGRITY);
	return 0;
}

int m78_checkpoint(struct m78_service *service)
{
	struct agi_lc_verify verify;
	if (!service || service->deployment.state != M78_STATE_CANDIDATE)
		return -1;
	if (fms_checkpoint(&service->memory) != FMS_OK)
		return -1;
	memset(&service->deployment.checkpoint, 0,
	       sizeof(service->deployment.checkpoint));
	service->deployment.checkpoint.size = sizeof(service->deployment.checkpoint);
	service->deployment.checkpoint.checkpoint_id = service->memory.checkpoint.checkpoint_id;
	service->deployment.checkpoint.checkpoint_sequence = service->memory.checkpoint.checkpoint_sequence;
	service->deployment.checkpoint.parent_sequence = service->memory.checkpoint.parent_sequence;
	memcpy(service->deployment.checkpoint.state_digest,
	       service->memory.checkpoint.state_digest, M78_DIGEST_SIZE);
	memset(&verify, 0, sizeof(verify));
	verify.size = sizeof(verify);
	verify.checkpoint_id = service->memory.checkpoint.checkpoint_id;
	verify.checkpoint_sequence = service->memory.checkpoint.checkpoint_sequence;
	verify.parent_sequence = service->memory.checkpoint.parent_sequence;
	memcpy(verify.state_digest, service->memory.checkpoint.state_digest,
	       M78_DIGEST_SIZE);
	verify.correlation = 78010;
	if (ioctl(service->memory.kernel_fd, AGI_LC_VERIFY_CHECKPOINT, &verify) < 0 ||
	    verify.state != AGI_LC_VERIFY_MATCHED)
		return -1;
	service->deployment.verification = verify;
	memcpy(service->deployment.manifest.manifest_digest,
	       service->memory.checkpoint.manifest_digest, M78_DIGEST_SIZE);
	memcpy(service->deployment.manifest.user_state_digest,
	       service->memory.checkpoint.state_digest, M78_DIGEST_SIZE);
	service->deployment.manifest.checkpoint_id = service->memory.checkpoint.checkpoint_id;
	service->deployment.manifest.checkpoint_sequence = service->memory.checkpoint.checkpoint_sequence;
	service->deployment.manifest.parent_sequence = service->memory.checkpoint.parent_sequence;
	service->deployment.handoff = service->memory.checkpoint.handoff;
	service->deployment.state = M78_STATE_CHECKPOINTED;
	audit_append(service, M78_APPROVAL_CANARY);
	return 0;
}

static int monitor(struct m78_service *service)
{
	struct agi_lc_resource_snapshot snapshot;
	struct agi_lc_observability observability;
	if (!service)
		return -1;
	memset(&snapshot, 0, sizeof(snapshot));
	snapshot.size = sizeof(snapshot);
	snapshot.correlation = 78020;
	if (ioctl(service->memory.kernel_fd, AGI_LC_GET_RESOURCE_SNAPSHOT,
		  &snapshot) < 0)
		return -1;
	service->deployment.snapshot = snapshot;
	memset(&observability, 0, sizeof(observability));
	observability.size = sizeof(observability);
	observability.operation = AGI_LC_OBSERVABILITY_QUERY;
	observability.correlation = 78021;
	if (ioctl(service->memory.kernel_fd, AGI_LC_OBSERVABILITY, &observability) < 0)
		return -1;
	service->deployment.observability = observability;
	return 0;
}

int m78_canary(struct m78_service *service, uint32_t health_ok)
{
	if (!service || service->deployment.state != M78_STATE_CHECKPOINTED)
		return -1;
	service->deployment.state = M78_STATE_CANARY;
	if (monitor(service) != 0)
		health_ok = 0;
	if (!health_ok) {
		service->deployment.rollback_reason = 1;
		service->deployment.state = M78_STATE_ROLLBACK_PENDING;
		audit_append(service, 1);
		return 1;
	}
	service->deployment.canary_passed = 1;
	audit_append(service, M78_APPROVAL_CANARY);
	return 0;
}

int m78_activate(struct m78_service *service)
{
	if (!service || service->deployment.state != M78_STATE_CANARY ||
	    !service->deployment.canary_passed)
		return -1;
	service->deployment.state = M78_STATE_ACTIVE;
	audit_append(service, M78_APPROVAL_CANARY);
	return 0;
}

int m78_rollback(struct m78_service *service, uint32_t reason)
{
	if (!service || service->deployment.state != M78_STATE_ROLLBACK_PENDING)
		return -1;
	service->deployment.rollback_reason = reason;
	if (fms_mark_crash(&service->memory) != FMS_OK ||
	    fms_restore(&service->memory) != FMS_OK) {
		service->deployment.state = M78_STATE_FAILED;
		audit_append(service, reason);
		return -1;
	}
	service->deployment.recovery.recovery_sequence =
		service->memory.checkpoint.handoff.checkpoint_sequence;
	service->deployment.recovery.state = AGI_LC_RECOVERY_CONTINUED;
	service->deployment.state = M78_STATE_ROLLED_BACK;
	audit_append(service, reason);
	return 0;
}

int m78_test_approval_denial(struct m78_service *service,
			     const struct m78_candidate *candidate)
{
	struct m78_candidate denied;
	if (!service || !candidate)
		return -1;
	denied = *candidate;
	denied.operator_approved = 0;
	return m78_admit(service, &denied) == 0 ? -1 : 0;
}

int m78_test_manifest_fuzz(const struct m78_candidate *candidate)
{
	struct m78_candidate mutated;
	uint8_t digest[M78_DIGEST_SIZE];
	unsigned int i;
	if (!candidate || m78_validate_candidate(candidate) != 0 ||
	    m78_compute_candidate_digest(candidate, digest) != 0 ||
	    memcmp(digest, candidate->artifact_digest, M78_DIGEST_SIZE))
		return -1;
	for (i = 0; i < M78_MAX_FUZZ; i++) {
		mutated = *candidate;
		switch (i % 6) {
		case 0:
			mutated.reserved = 1;
			break;
		case 1:
			mutated.supervisor_nonce = mutated.operator_nonce;
			break;
		case 2:
			mutated.memory_limit_pages = 0;
			break;
		case 3:
			mutated.required_approvals = 0;
			break;
		case 4:
			mutated.artifact_digest[0] ^= (uint8_t)(i + 1);
			break;
		default:
			mutated.build_id[0] = '\0';
			break;
		}
		if (m78_validate_candidate(&mutated) == 0 &&
		    m78_compute_candidate_digest(&mutated, digest) == 0 &&
		    !memcmp(digest, mutated.artifact_digest, M78_DIGEST_SIZE))
			return -1;
	}
	return 0;
}

int m78_test_model_authority_denial(struct m78_service *service)
{
	if (!service || service->deployment.state != M78_STATE_ACTIVE)
		return -1;
	return service->deployment.candidate.supervisor_approved &&
	       service->deployment.candidate.operator_approved &&
	       service->deployment.candidate.integrity_measured ? 0 : -1;
}
