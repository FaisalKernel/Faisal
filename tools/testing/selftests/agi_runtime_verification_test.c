#include "../../faisal-runtime-verification/faisal_runtime_verification.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M87_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void cleanup(const char *path)
{
	char sidecar[256];
	char tx_manifest[256];
	unsigned int i;

	unlink(path);
	snprintf(sidecar, sizeof(sidecar), "%s.ckpt", path);
	unlink(sidecar);
	snprintf(tx_manifest, sizeof(tx_manifest), "%s.m83.manifest", path);
	unlink(tx_manifest);
	for (i = 0; i < 2; i++) {
		char backup[256];
		snprintf(backup, sizeof(backup), "%s.m83.backup.%u", path, i);
		unlink(backup);
	}
}

static int make_key(EVP_PKEY **key, uint8_t public_key[32])
{
	EVP_PKEY_CTX *ctx;
	size_t public_size = 32;
	int rc = -1;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (!ctx || EVP_PKEY_keygen_init(ctx) != 1 ||
	    EVP_PKEY_keygen(ctx, key) != 1 ||
	    EVP_PKEY_get_raw_public_key(*key, public_key, &public_size) != 1 ||
	    public_size != 32)
		goto out;
	rc = 0;
out:
	EVP_PKEY_CTX_free(ctx);
	return rc;
}

static int sign_bundle(EVP_PKEY *key, struct m87_repair_bundle *bundle)
{
	EVP_MD_CTX *ctx;
	size_t signature_size = M87_SIGNATURE_SIZE;
	int rc = -1;

	ctx = EVP_MD_CTX_new();
	if (!ctx || EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) != 1 ||
	    EVP_DigestSign(ctx, bundle->signature, &signature_size,
			   bundle->bundle_digest, M87_DIGEST_SIZE) != 1 ||
	    signature_size != M87_SIGNATURE_SIZE)
		goto out;
	rc = 0;
out:
	EVP_MD_CTX_free(ctx);
	return rc;
}

static int make_bundle(struct m87_service *service,
			       struct m87_repair_bundle *bundle,
			       EVP_PKEY *key)
{
	static const char payload[] = "M87 pre-approved repair payload; no kernel self-modification";

	memset(bundle, 0, sizeof(*bundle));
	snprintf(bundle->bundle_id, sizeof(bundle->bundle_id),
		 "m87-signed-repair-%llu",
		 (unsigned long long)service->signal.sequence);
	memcpy(bundle->payload, payload, sizeof(payload) - 1);
	bundle->payload_size = sizeof(payload) - 1;
	bundle->required_provider = M87_PROVIDER_SOFTWARE;
	bundle->policy_generation = service->signal.sequence;
	bundle->cpu_budget_ns = 5000000000ULL;
	bundle->memory_limit_pages = 16384;
	bundle->canary_window_ns = 1000000000ULL;
	memcpy(bundle->attestation_digest,
	       service->attestation.attestation.digest, M87_DIGEST_SIZE);
	bundle->signal_sequence = service->signal.sequence;
	bundle->supervisor_approved = 1;
	bundle->operator_approved = 1;
	bundle->integrity_measured = 1;
	bundle->canary_required = 1;
	if (m87_compute_payload_digest(bundle, bundle->payload_digest) != M87_OK ||
	    m87_compute_bundle_digest(bundle, bundle->bundle_digest) != M87_OK ||
	    sign_bundle(key, bundle) != 0)
		return -1;
	return 0;
}

static int bind_health_signal(struct m87_service *service, uint64_t sequence)
{
	struct m87_runtime_signal signal;

	memset(&signal, 0, sizeof(signal));
	signal.sequence = sequence;
	signal.observed_at_ns = service->attestation.attestation.sampled_at_ns;
	signal.kind = FAS_SIGNAL_DEPENDENCY;
	signal.severity = 3;
	signal.status = -11;
	signal.correlation = 87000 + sequence;
	memcpy(signal.attestation_digest,
	       service->attestation.attestation.digest, M87_DIGEST_SIZE);
	service->signal = signal;
	return m87_bind_signal(service, &signal);
}

int main(void)
{
	const char *path = "/tmp/faisal-m87-runtime-verification";
	struct m87_service service;
	struct m87_repair_bundle bundle;
	struct m87_repair_bundle tampered;
	struct m87_service degraded;
	struct m78_candidate candidate;
	EVP_PKEY *key = NULL;
	uint8_t public_key[32];
	int rc;

	cleanup(path);
	memset(&service, 0, sizeof(service));
	if (make_key(&key, public_key) != 0)
		return fail("test-key", M87_ERR_SIGNATURE);
	if (m87_open(&service, path) != M87_OK)
		return fail("open", M87_ERR_STATE);
	memcpy(service.trusted_public_key, public_key, sizeof(public_key));
	service.trusted_public_key_size = sizeof(public_key);
	if (m87_sample_attestation(&service) != M87_OK ||
	    service.attestation.attestation.state != FRA_STATE_HEALTHY)
		return fail("attestation", M87_ERR_ATTESTATION);
	printf("M87_ATTESTATION_BOUND_OK digest_valid=1 state=%u\n",
	       service.attestation.attestation.state);

	memset(&service.signal, 0, sizeof(service.signal));
	service.signal.sequence = 1;
	service.signal.severity = 3;
	if (m87_bind_signal(&service, &service.signal) != M87_ERR_SIGNAL)
		return fail("signal mismatch denial", M87_ERR_SIGNAL);
	printf("M87_SIGNAL_MISMATCH_DENIAL_OK\n");
	if (bind_health_signal(&service, 1) != M87_OK)
		return fail("signal bind", M87_ERR_SIGNAL);
	printf("M87_RUNTIME_SIGNAL_BIND_OK sequence=%llu\n",
	       (unsigned long long)service.signal.sequence);
	if (make_bundle(&service, &bundle, key) != 0)
		return fail("bundle fixture", M87_ERR_DIGEST);
	degraded = service;
	degraded.attestation.attestation.state = FRA_STATE_DEGRADED;
	if (m87_verify_bundle(&degraded, &bundle) != M87_ERR_ATTESTATION)
		return fail("degraded attestation denial", M87_ERR_ATTESTATION);
	printf("M87_DEGRADED_ATTESTATION_DENIAL_OK\n");

	tampered = bundle;
	tampered.required_provider = M87_PROVIDER_HARDWARE_ATTESTATION;
	if (m87_compute_bundle_digest(&tampered, tampered.bundle_digest) != M87_OK ||
	    sign_bundle(key, &tampered) != 0 ||
	    m87_verify_bundle(&service, &tampered) != M87_ERR_PROVIDER)
		return fail("provider gate", M87_ERR_PROVIDER);
	printf("M87_PROVIDER_GATE_DENIAL_OK\n");
	if (m87_test_tampered_bundle(&service, &bundle) != M87_OK)
		return fail("payload tamper denial", M87_ERR_DIGEST);
	printf("M87_PAYLOAD_DIGEST_DENIAL_OK\n");
	tampered = bundle;
	tampered.signature[0] ^= 0x80;
	if (m87_verify_bundle(&service, &tampered) != M87_ERR_SIGNATURE)
		return fail("signature denial", M87_ERR_SIGNATURE);
	printf("M87_SIGNATURE_DENIAL_OK\n");
	if (m87_verify_bundle(&service, &bundle) != M87_OK)
		return fail("bundle verify", M87_ERR_SIGNATURE);
	printf("M87_SIGNED_BUNDLE_VERIFY_OK\n");
	if (m87_admit_repair(&service, &bundle, &candidate) != M87_OK)
		return fail("repair admission", M87_ERR_APPROVAL);
	if (m87_test_model_authority_denial(&service, &candidate) != M87_OK)
		return fail("model authority denial", M87_ERR_APPROVAL);
	printf("M87_MODEL_AUTHORITY_DENIAL_OK\n");
	if (m87_execute_repair(&service, &candidate, 1) != M87_OK ||
	    service.state != M87_STATE_REPAIR_RECOVERED ||
	    service.healing.deployment.deployment.state != M78_STATE_ACTIVE)
		return fail("attested repair", M87_ERR_POLICY);
	printf("M87_ATTESTED_REPAIR_CANARY_OK state=%u\n", service.state);
	m87_close(&service);
	cleanup(path);

	memset(&service, 0, sizeof(service));
	if (m87_open(&service, path) != M87_OK)
		return fail("rollback reopen", M87_ERR_STATE);
	memcpy(service.trusted_public_key, public_key, sizeof(public_key));
	service.trusted_public_key_size = sizeof(public_key);
	if (m87_sample_attestation(&service) != M87_OK ||
	    bind_health_signal(&service, 2) != M87_OK ||
	    make_bundle(&service, &bundle, key) != 0 ||
	    m87_verify_bundle(&service, &bundle) != M87_OK ||
	    m87_admit_repair(&service, &bundle, &candidate) != M87_OK)
		return fail("rollback setup", M87_ERR_STATE);
	rc = m87_execute_repair(&service, &candidate, 0);
	if (rc != M87_ERR_POLICY || service.state != M87_STATE_REPAIR_ROLLED_BACK ||
	    service.healing.deployment.deployment.state != M78_STATE_ROLLED_BACK)
		return fail("canary rollback", rc);
	printf("M87_CANARY_ROLLBACK_OK state=%u\n", service.state);
	m87_close(&service);
	cleanup(path);
	EVP_PKEY_free(key);
	printf("M87_SELFTEST_EXIT=0\n");
	return 0;
}
