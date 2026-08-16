// SPDX-License-Identifier: GPL-2.0-only
#include "../../faisal-key-provider/faisal_key_provider.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M90_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static int make_key(EVP_PKEY **key)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	int rc = -1;

	if (ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
	    EVP_PKEY_keygen(ctx, key) == 1)
		rc = 0;
	EVP_PKEY_CTX_free(ctx);
	return rc;
}

static int bind_signal(struct m87_service *service, uint64_t sequence)
{
	struct m87_runtime_signal signal;

	memset(&signal, 0, sizeof(signal));
	signal.sequence = sequence;
	signal.observed_at_ns = service->attestation.attestation.sampled_at_ns;
	signal.kind = FAS_SIGNAL_DEPENDENCY;
	signal.severity = 3;
	signal.status = -11;
	signal.correlation = 90000 + sequence;
	memcpy(signal.attestation_digest,
	       service->attestation.attestation.digest, M87_DIGEST_SIZE);
	service->signal = signal;
	return m87_bind_signal(service, &signal);
}

static int make_bundle(struct m87_service *service,
		       struct m87_repair_bundle *bundle,
		       const uint8_t key_id[M90_KEY_ID_SIZE],
		       uint64_t generation)
{
	static const char payload[] = "M90 provider-bound signed repair payload";

	memset(bundle, 0, sizeof(*bundle));
	snprintf(bundle->bundle_id, sizeof(bundle->bundle_id),
		 "m90-key-contract-%llu", (unsigned long long)generation);
	memcpy(bundle->payload, payload, sizeof(payload) - 1);
	bundle->payload_size = sizeof(payload) - 1;
	bundle->required_provider = M87_PROVIDER_SOFTWARE;
	bundle->policy_generation = generation;
	bundle->cpu_budget_ns = 5000000000ULL;
	bundle->memory_limit_pages = 16384;
	bundle->canary_window_ns = 1000000000ULL;
	memcpy(bundle->attestation_digest,
	       service->attestation.attestation.digest, M87_DIGEST_SIZE);
	memcpy(bundle->signing_key_id, key_id, M90_KEY_ID_SIZE);
	bundle->key_generation = generation;
	bundle->signal_sequence = service->signal.sequence;
	bundle->supervisor_approved = 1;
	bundle->operator_approved = 1;
	bundle->integrity_measured = 1;
	bundle->canary_required = 1;
	return m87_compute_payload_digest(bundle, bundle->payload_digest) == M87_OK &&
	       m87_compute_bundle_digest(bundle, bundle->bundle_digest) == M87_OK;
}

static int sign_bundle(struct m90_key_provider *provider,
		       struct m87_repair_bundle *bundle)
{
	return m90_provider_sign_active(provider, bundle->bundle_digest,
					M87_DIGEST_SIZE, bundle->signature);
}

int main(void)
{
	const char *path = "/tmp/faisal-m90-key-provider";
	struct m90_key_provider provider;
	struct m87_service service;
	struct m87_repair_bundle old_bundle;
	struct m87_repair_bundle new_bundle;
	struct m87_repair_bundle approval_bundle;
	EVP_PKEY *old_key = NULL;
	EVP_PKEY *new_key = NULL;
	uint8_t old_id[M90_KEY_ID_SIZE];
	uint8_t new_id[M90_KEY_ID_SIZE];
	uint8_t duplicate_id[M90_KEY_ID_SIZE];
	uint64_t old_generation;
	uint64_t new_generation;
	uint64_t duplicate_generation;
	int rc;

	unlink(path);
	if (make_key(&old_key) != 0 || make_key(&new_key) != 0)
		return fail("key generation", M90_ERR_KEY);
	if (m90_provider_init(&provider) != M90_OK)
		return fail("provider init", M90_ERR_STATE);
	if (m90_provider_provision(&provider, old_key, old_id,
				   &old_generation) != M90_OK || old_generation == 0)
		return fail("provision", M90_ERR_KEY);
	if (m90_provider_provision(&provider, old_key, duplicate_id,
				   &duplicate_generation) != M90_ERR_STATE)
		return fail("duplicate provision denial", M90_ERR_STATE);
	printf("M90_KEY_PROVISION_OK generation=%llu\n",
	       (unsigned long long)old_generation);
	if (m87_open(&service, path) != M87_OK ||
	    m87_sample_attestation(&service) != M87_OK ||
	    bind_signal(&service, 1) != M87_OK ||
	    m90_provider_bind_service(&provider, &service) != M90_OK)
		return fail("service bind", M90_ERR_STATE);
	if (!service.trusted_key_required ||
	    memcmp(service.trusted_key_id, old_id, M90_KEY_ID_SIZE) != 0 ||
	    service.trusted_key_generation != old_generation)
		return fail("service key binding", M90_ERR_STATE);
	if (!make_bundle(&service, &old_bundle, old_id, old_generation) ||
	    sign_bundle(&provider, &old_bundle) != M90_OK ||
	    m87_verify_bundle(&service, &old_bundle) != M87_OK)
		return fail("old bundle verify", M87_ERR_SIGNATURE);
	printf("M90_PROVISIONED_BUNDLE_VERIFY_OK generation=%llu\n",
	       (unsigned long long)old_generation);

	if (m90_provider_rotate(&provider, new_key, new_id, &new_generation) != M90_OK ||
	    new_generation <= old_generation ||
	    m90_provider_bind_service(&provider, &service) != M90_OK)
		return fail("rotation", M90_ERR_STATE);
	if (m87_verify_bundle(&service, &old_bundle) != M87_ERR_SIGNATURE)
		return fail("old-key isolation", M87_ERR_SIGNATURE);
	printf("M90_OLD_KEY_ISOLATION_OK\n");
	if (!make_bundle(&service, &new_bundle, new_id, new_generation) ||
	    sign_bundle(&provider, &new_bundle) != M90_OK ||
	    m87_verify_bundle(&service, &new_bundle) != M87_OK)
		return fail("rotated bundle verify", M87_ERR_SIGNATURE);
	printf("M90_KEY_ROTATION_OK old_generation=%llu new_generation=%llu\n",
	       (unsigned long long)old_generation,
	       (unsigned long long)new_generation);

	if (m90_provider_bind_service(&provider, &service) != M90_OK)
		return fail("approval rebind", M90_ERR_STATE);
	approval_bundle = new_bundle;
	approval_bundle.operator_approved = 0;
	if (m87_compute_bundle_digest(&approval_bundle,
				      approval_bundle.bundle_digest) != M87_OK ||
	    sign_bundle(&provider, &approval_bundle) != M90_OK ||
	    m87_verify_bundle(&service, &approval_bundle) != M87_ERR_APPROVAL)
		return fail("approval denial", M87_ERR_APPROVAL);
	printf("M90_INDEPENDENT_APPROVAL_DENIAL_OK\n");

	if (m90_provider_revoke(&provider, old_id) != M90_OK ||
	    service.trusted_key_generation != new_generation ||
	    m90_provider_sign_active(&provider, new_bundle.bundle_digest,
				      M87_DIGEST_SIZE, new_bundle.signature) != M90_OK)
		return fail("old-key revocation isolation", M90_ERR_STATE);
	printf("M90_OLD_KEY_REVOCATION_ISOLATED_OK\n");
	if (m90_provider_revoke(&provider, new_id) != M90_OK)
		return fail("active-key revoke", M90_ERR_REVOKED);
	if (m90_provider_sign_active(&provider, new_bundle.bundle_digest,
				     M87_DIGEST_SIZE, new_bundle.signature) != M90_ERR_REVOKED)
		return fail("revoked sign denial", M90_ERR_REVOKED);
	if (m87_verify_bundle(&service, &new_bundle) != M87_ERR_SIGNATURE)
		return fail("revoked service denial", M87_ERR_SIGNATURE);
	printf("M90_REVOCATION_FAIL_CLOSED_OK\n");

	rc = m90_provider_unbind_service(&provider, &service);
	if (rc != M90_OK)
		return fail("service unbind", rc);
	m87_close(&service);
	m90_provider_close(&provider);
	EVP_PKEY_free(old_key);
	EVP_PKEY_free(new_key);
	unlink(path);
	printf("M90_SELFTEST_EXIT=0\n");
	return 0;
}
