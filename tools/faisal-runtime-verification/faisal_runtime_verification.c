#include "faisal_runtime_verification.h"

#include <errno.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static int digest_bytes(const void *data, size_t size,
			uint8_t digest[M87_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	int ret = M87_ERR_DIGEST;

	if ((!data && size) || !digest)
		return M87_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return M87_ERR_DIGEST;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, size) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
	    length == M87_DIGEST_SIZE)
		ret = M87_OK;
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t size)
{
	return EVP_DigestUpdate(ctx, data, size) == 1 ? M87_OK : M87_ERR_DIGEST;
}

static int verify_signature(const struct m87_service *service,
			    const struct m87_repair_bundle *bundle)
{
	EVP_PKEY *key;
	EVP_MD_CTX *ctx;
	int ret = M87_ERR_SIGNATURE;

	if (!service || !bundle || service->trusted_public_key_size != 32)
		return M87_ERR_SIGNATURE;
	key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
					 service->trusted_public_key, 32);
	if (!key)
		return M87_ERR_SIGNATURE;
	ctx = EVP_MD_CTX_new();
	if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
	    EVP_DigestVerify(ctx, bundle->signature, M87_SIGNATURE_SIZE,
			     bundle->bundle_digest, M87_DIGEST_SIZE) == 1)
		ret = M87_OK;
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return ret;
}

int m87_open(struct m87_service *service, const char *journal_path)
{
	if (!service || !journal_path || !*journal_path)
		return M87_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->attestation.kernel_fd = -1;
	service->healing.deployment.memory.kernel_fd = -1;
	service->healing.deployment.memory.journal_fd = -1;
	if (snprintf(service->journal_path, sizeof(service->journal_path), "%s",
		     journal_path) >= (int)sizeof(service->journal_path))
		return M87_ERR_ARGUMENT;
	if (fra_open(&service->attestation) != FRA_OK)
		return M87_ERR_ATTESTATION;
	service->provider_mask = M87_PROVIDER_SOFTWARE;
	service->state = M87_STATE_EMPTY;
	return M87_OK;
}

void m87_close(struct m87_service *service)
{
	if (!service)
		return;
	fas_close(&service->healing);
	fra_close(&service->attestation);
}

int m87_sample_attestation(struct m87_service *service)
{
	if (!service)
		return M87_ERR_ARGUMENT;
	if (fra_run(&service->attestation) != FRA_OK ||
	    service->attestation.attestation.state != FRA_STATE_HEALTHY)
		return M87_ERR_ATTESTATION;
	memcpy(service->verification.attestation_digest,
	       service->attestation.attestation.digest, M87_DIGEST_SIZE);
	service->verification.state = M87_STATE_ATTESTED;
	service->state = M87_STATE_ATTESTED;
	return M87_OK;
}

int m87_bind_signal(struct m87_service *service,
			const struct m87_runtime_signal *signal)
{
	if (!service || !signal || service->state != M87_STATE_ATTESTED ||
	    service->attestation.attestation.state != FRA_STATE_HEALTHY ||
	    !signal->sequence || signal->severity > 5 ||
	    memcmp(signal->attestation_digest,
		   service->attestation.attestation.digest, M87_DIGEST_SIZE) != 0)
		return M87_ERR_SIGNAL;
	service->signal = *signal;
	service->verification.signal_sequence = signal->sequence;
	service->verification.signal_kind = signal->kind;
	service->verification.signal_severity = signal->severity;
	service->verification.status = signal->status;
	service->verification.valid_mask |= M87_SIGNAL_BOUND | M87_ATTESTATION_BOUND;
	service->state = M87_STATE_SIGNAL_BOUND;
	service->verification.state = M87_STATE_SIGNAL_BOUND;
	return M87_OK;
}

int m87_compute_payload_digest(const struct m87_repair_bundle *bundle,
			       uint8_t digest[M87_DIGEST_SIZE])
{
	if (!bundle || !digest || bundle->payload_size > M87_MAX_PAYLOAD)
		return M87_ERR_ARGUMENT;
	return digest_bytes(bundle->payload, bundle->payload_size, digest);
}

int m87_compute_bundle_digest(const struct m87_repair_bundle *bundle,
			      uint8_t digest[M87_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int length = 0;
	int ret = M87_ERR_DIGEST;

	if (!bundle || !digest || !bundle->bundle_id[0] ||
	    strnlen(bundle->bundle_id, M87_MAX_BUNDLE_ID) >= M87_MAX_BUNDLE_ID ||
	    bundle->payload_size > M87_MAX_PAYLOAD)
		return M87_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return M87_ERR_DIGEST;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    digest_update(ctx, bundle->bundle_id, sizeof(bundle->bundle_id)) == M87_OK &&
	    digest_update(ctx, bundle->payload_digest, sizeof(bundle->payload_digest)) == M87_OK &&
	    digest_update(ctx, bundle->attestation_digest, sizeof(bundle->attestation_digest)) == M87_OK &&
	    digest_update(ctx, bundle->signing_key_id, sizeof(bundle->signing_key_id)) == M87_OK &&
	    digest_update(ctx, &bundle->key_generation, sizeof(bundle->key_generation)) == M87_OK &&
	    digest_update(ctx, &bundle->signal_sequence, sizeof(bundle->signal_sequence)) == M87_OK &&
	    digest_update(ctx, &bundle->required_provider, sizeof(bundle->required_provider)) == M87_OK &&
	    digest_update(ctx, &bundle->policy_generation, sizeof(bundle->policy_generation)) == M87_OK &&
	    digest_update(ctx, &bundle->cpu_budget_ns, sizeof(bundle->cpu_budget_ns)) == M87_OK &&
	    digest_update(ctx, &bundle->memory_limit_pages, sizeof(bundle->memory_limit_pages)) == M87_OK &&
	    digest_update(ctx, &bundle->canary_window_ns, sizeof(bundle->canary_window_ns)) == M87_OK &&
	    digest_update(ctx, &bundle->supervisor_approved, sizeof(bundle->supervisor_approved)) == M87_OK &&
	    digest_update(ctx, &bundle->operator_approved, sizeof(bundle->operator_approved)) == M87_OK &&
	    digest_update(ctx, &bundle->integrity_measured, sizeof(bundle->integrity_measured)) == M87_OK &&
	    digest_update(ctx, &bundle->canary_required, sizeof(bundle->canary_required)) == M87_OK &&
	    EVP_DigestFinal_ex(ctx, digest, &length) == 1 &&
	    length == M87_DIGEST_SIZE)
		ret = M87_OK;
	EVP_MD_CTX_free(ctx);
	return ret;
}

int m87_provider_available(const struct m87_service *service,
			   uint32_t required_provider)
{
	if (!service || required_provider & ~service->provider_mask)
		return 0;
	return 1;
}

int m87_verify_bundle(struct m87_service *service,
			     const struct m87_repair_bundle *bundle)
{
	uint8_t payload_digest[M87_DIGEST_SIZE];
	uint8_t bundle_digest[M87_DIGEST_SIZE];

	if (!service || !bundle || service->state != M87_STATE_SIGNAL_BOUND)
		return M87_ERR_STATE;
	if (service->attestation.attestation.state != FRA_STATE_HEALTHY)
		return M87_ERR_ATTESTATION;
	if (!bundle->payload_size || bundle->payload_size > M87_MAX_PAYLOAD ||
	    !bundle->bundle_id[0] || !bundle->signal_sequence ||
	    bundle->signal_sequence != service->signal.sequence ||
	    memcmp(bundle->attestation_digest,
		   service->attestation.attestation.digest, M87_DIGEST_SIZE) != 0)
		return M87_ERR_SIGNAL;
	if (m87_compute_payload_digest(bundle, payload_digest) != M87_OK ||
	    memcmp(payload_digest, bundle->payload_digest, M87_DIGEST_SIZE) != 0)
		return M87_ERR_DIGEST;
			if (m87_compute_bundle_digest(bundle, bundle_digest) != M87_OK ||
		    memcmp(bundle_digest, bundle->bundle_digest, M87_DIGEST_SIZE) != 0)
			return M87_ERR_DIGEST;
		if (service->trusted_key_required &&
		    (!service->trusted_key_generation ||
		     bundle->key_generation != service->trusted_key_generation ||
		     memcmp(bundle->signing_key_id, service->trusted_key_id,
			    M87_KEY_ID_SIZE) != 0))
			return M87_ERR_SIGNATURE;
		if (!m87_provider_available(service, bundle->required_provider))

		return M87_ERR_PROVIDER;
	if (verify_signature(service, bundle) != M87_OK)
		return M87_ERR_SIGNATURE;
	if (!bundle->supervisor_approved || !bundle->operator_approved ||
	    !bundle->integrity_measured || !bundle->canary_required)
		return M87_ERR_APPROVAL;
	memcpy(service->verification.payload_digest, payload_digest, M87_DIGEST_SIZE);
	memcpy(service->verification.bundle_digest, bundle_digest, M87_DIGEST_SIZE);
	memcpy(service->verification.signing_key_id, bundle->signing_key_id,
	       M87_KEY_ID_SIZE);
	service->verification.key_generation = bundle->key_generation;
	service->verification.provider_mask = service->provider_mask;
	service->verification.valid_mask |= M87_BUNDLE_DIGEST_VALID |
		M87_SIGNATURE_VALID | M87_PROVIDER_VALID | M87_APPROVALS_VALID;
	service->state = M87_STATE_BUNDLE_VERIFIED;
	service->verification.state = M87_STATE_BUNDLE_VERIFIED;
	return M87_OK;
}

int m87_admit_repair(struct m87_service *service,
			    const struct m87_repair_bundle *bundle,
			    struct m78_candidate *candidate)
{
	if (!service || !bundle || !candidate ||
	    service->state != M87_STATE_BUNDLE_VERIFIED)
		return M87_ERR_STATE;
	if (service->healing.deployment.memory.kernel_fd < 0 &&
	    fas_open(&service->healing, service->journal_path) != FAS_OK)
		return M87_ERR_STATE;
	memset(candidate, 0, sizeof(*candidate));
	if (snprintf(candidate->build_id, sizeof(candidate->build_id), "%s",
		     bundle->bundle_id) >= (int)sizeof(candidate->build_id))
		return M87_ERR_ARGUMENT;
	memcpy(candidate->state_digest, service->verification.attestation_digest,
	       M78_DIGEST_SIZE);
	candidate->policy_generation = bundle->policy_generation;
	candidate->cpu_budget_ns = bundle->cpu_budget_ns;
	candidate->memory_limit_pages = bundle->memory_limit_pages;
	candidate->canary_window_ns = bundle->canary_window_ns;
	candidate->required_approvals = M78_APPROVAL_SUPERVISOR |
		M78_APPROVAL_OPERATOR | M78_APPROVAL_INTEGRITY | M78_APPROVAL_CANARY;
	candidate->supervisor_approved = bundle->supervisor_approved;
	candidate->operator_approved = bundle->operator_approved;
	candidate->integrity_measured = bundle->integrity_measured;
	candidate->supervisor_nonce = 0x8700000000000000ULL | bundle->signal_sequence;
	candidate->operator_nonce = 0x8701000000000000ULL | bundle->signal_sequence;
	if (m78_compute_candidate_digest(candidate, candidate->artifact_digest) != 0)
		return M87_ERR_DIGEST;
	service->state = M87_STATE_REPAIR_ADMITTED;
	service->verification.state = M87_STATE_REPAIR_ADMITTED;
	return M87_OK;
}

int m87_execute_repair(struct m87_service *service,
			      struct m78_candidate *candidate,
			      uint32_t canary_health)
{
	struct fas_signal signal;
	int rc;

	if (!service || !candidate || service->state != M87_STATE_REPAIR_ADMITTED)
		return M87_ERR_STATE;
	memset(&signal, 0, sizeof(signal));
	signal.sequence = service->signal.sequence;
	signal.observed_at_ns = service->attestation.attestation.sampled_at_ns;
	signal.kind = FAS_SIGNAL_DEPENDENCY;
	signal.severity = service->signal.severity;
	signal.status = service->signal.status;
	signal.correlation = service->signal.correlation;
	snprintf(signal.detail, sizeof(signal.detail),
		 "M87 attested runtime-verification signal");
	rc = fas_run_self_heal(&service->healing, &signal, candidate,
			       canary_health);
	if (rc == FAS_OK) {
		service->state = M87_STATE_REPAIR_RECOVERED;
		service->verification.state = M87_STATE_REPAIR_RECOVERED;
		return M87_OK;
	}
	if (rc == FAS_ERR_CANARY) {
		service->state = M87_STATE_REPAIR_ROLLED_BACK;
		service->verification.state = M87_STATE_REPAIR_ROLLED_BACK;
		return M87_ERR_POLICY;
	}
	service->state = M87_STATE_QUARANTINED;
	service->verification.state = M87_STATE_QUARANTINED;
	return M87_ERR_POLICY;
}

int m87_test_tampered_bundle(struct m87_service *service,
			     const struct m87_repair_bundle *bundle)
{
	struct m87_repair_bundle tampered;

	if (!service || !bundle)
		return M87_ERR_ARGUMENT;
	tampered = *bundle;
	tampered.payload[0] ^= 0x5a;
	return m87_verify_bundle(service, &tampered) == M87_ERR_DIGEST ?
		M87_OK : M87_ERR_SIGNATURE;
}

int m87_test_model_authority_denial(struct m87_service *service,
				    struct m78_candidate *candidate)
{
	struct m78_candidate denied;

	if (!service || !candidate)
		return M87_ERR_ARGUMENT;
	denied = *candidate;
	denied.operator_approved = 0;
	return m78_admit(&service->healing.deployment, &denied) == 0 ?
		M87_ERR_APPROVAL : M87_OK;
}
