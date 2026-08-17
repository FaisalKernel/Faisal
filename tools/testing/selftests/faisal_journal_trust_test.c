#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../faisal-journal-trust/faisal_journal_trust.h"

struct test_crypto { EVP_PKEY *private_key; EVP_PKEY *public_key; };

static void fail(const char *marker, int rc)
{
	printf("FJT_FAIL %s rc=%d\n", marker, rc);
	exit(1);
}

static int sign_message(void *opaque, const uint8_t *message, size_t size,
			uint8_t signature[FJT_SIGNATURE_SIZE])
{
	struct test_crypto *crypto = opaque;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	size_t signature_size = FJT_SIGNATURE_SIZE;
	int rc = -1;
	if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, crypto->private_key) == 1 &&
	    EVP_DigestSign(ctx, signature, &signature_size, message, size) == 1 &&
	    signature_size == FJT_SIGNATURE_SIZE)
		rc = 0;
	EVP_MD_CTX_free(ctx);
	return rc;
}

static int verify_message(void *opaque, const uint8_t *message, size_t size,
			  const uint8_t signature[FJT_SIGNATURE_SIZE])
{
	struct test_crypto *crypto = opaque;
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int rc = -1;
	if (ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, crypto->public_key) == 1 &&
	    EVP_DigestVerify(ctx, signature, FJT_SIGNATURE_SIZE, message, size) == 1)
		rc = 0;
	EVP_MD_CTX_free(ctx);
	return rc;
}

static int quote_message(void *opaque, const uint8_t nonce[FJT_NONCE_SIZE],
			 const uint8_t digest[FJT_DIGEST_SIZE],
			 uint8_t quote[FJT_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int length = 0;
	uint8_t material[FJT_NONCE_SIZE + FJT_DIGEST_SIZE];
	int rc = -1;
	(void)opaque;
	memcpy(material, nonce, FJT_NONCE_SIZE);
	memcpy(material + FJT_NONCE_SIZE, digest, FJT_DIGEST_SIZE);
	if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, material, sizeof(material)) == 1 &&
	    EVP_DigestFinal_ex(ctx, quote, &length) == 1 && length == FJT_DIGEST_SIZE)
		rc = 0;
	EVP_MD_CTX_free(ctx);
	return rc;
}

int main(void)
{
	static const uint8_t seed[32] = {
		0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,
		0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f,
		0x01,0x12,0x23,0x34,0x45,0x56,0x67,0x78,
		0x89,0x9a,0xab,0xbc,0xcd,0xde,0xef,0xf0
	};
	struct test_crypto crypto = { 0 };
	struct fjt_provider provider = { 0 }, software_provider = { 0 };
	struct fjt_journal_attestation report = { 0 };
	struct fjt_signed_attestation signed_report = { 0 };
	struct fjt_replica_observation replicas[3] = { 0 };
	struct fjt_quorum_config config = { 3, 2, 7 };
	uint64_t term, sequence;
	uint8_t digest[FJT_DIGEST_SIZE];
	size_t public_key_size = sizeof(digest);
	int rc;
	unsigned int i;

	crypto.private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
							 seed, sizeof(seed));
	if (!crypto.private_key ||
	    EVP_PKEY_get_raw_public_key(crypto.private_key, digest, &public_key_size) != 1)
		fail("KEY_SETUP", FJT_ERR_CRYPTO);
	crypto.public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
							 digest, public_key_size);
	if (!crypto.public_key)
		fail("PUBLIC_KEY_SETUP", FJT_ERR_CRYPTO);
	provider.provider_mask = FJT_PROVIDER_TPM2 | FJT_PROVIDER_REMOTE_VERIFIER;
	provider.key_generation = 11;
	provider.ctx = &crypto;
	provider.sign = sign_message;
	provider.verify = verify_message;
	provider.quote = quote_message;
	for (i = 0; i < FJT_DIGEST_SIZE; i++)
		report.chain_digest[i] = (uint8_t)(i + 3);
	for (i = 0; i < FJT_NONCE_SIZE; i++)
		report.nonce[i] = (uint8_t)(0xa0 + i);
	report.format_version = FJT_FORMAT_VERSION;
	report.record_count = 72;
	report.last_sequence = 72;
	report.root_generation = 4;
	report.observed_at_ns = 900;
	rc = fjt_sign_attestation(&report, &provider, &signed_report);
	if (rc != FJT_OK) fail("SIGN", rc);
	if (fjt_verify_attestation(&signed_report, &provider) != FJT_OK)
		fail("VERIFY", FJT_ERR_CRYPTO);
	printf("FJT_REMOTE_ATTESTATION_SIGN_VERIFY_OK generation=%llu\n",
	       (unsigned long long)signed_report.key_generation);
	signed_report.signature[0] ^= 1;
	if (fjt_verify_attestation(&signed_report, &provider) != FJT_ERR_CRYPTO)
		fail("TAMPERED_SIGNATURE", FJT_ERR_CRYPTO);
	printf("FJT_TAMPERED_ATTESTATION_DENIED_OK\n");
	signed_report.signature[0] ^= 1;
	if (fjt_bind_hardware_quote(&signed_report, &provider) != FJT_OK)
		fail("TPM2_QUOTE", FJT_ERR_PROVIDER);
	printf("FJT_TPM2_PROVIDER_QUOTE_OK\n");
	software_provider.provider_mask = FJT_PROVIDER_REMOTE_VERIFIER;
	software_provider.key_generation = 11;
	software_provider.ctx = &crypto;
	software_provider.quote = quote_message;
	if (fjt_bind_hardware_quote(&signed_report, &software_provider) != FJT_ERR_PROVIDER)
		fail("SOFTWARE_HARDWARE_GATE", FJT_ERR_PROVIDER);
	printf("FJT_HARDWARE_ROOT_GATE_FAIL_CLOSED_OK\n");
	for (i = 0; i < 3; i++) {
		replicas[i].replica_id = i + 1;
		replicas[i].term = 7;
		replicas[i].last_sequence = 72;
		replicas[i].healthy = 1;
		replicas[i].signature_valid = 1;
		memcpy(replicas[i].chain_digest, report.chain_digest, FJT_DIGEST_SIZE);
	}
	if (fjt_quorum_commit(&config, replicas, 3, &term, &sequence, digest) != FJT_OK ||
	    term != 7 || sequence != 72 || memcmp(digest, report.chain_digest, FJT_DIGEST_SIZE))
		fail("QUORUM_COMMIT", FJT_ERR_QUORUM);
	printf("FJT_QUORUM_COMMIT_OK term=%llu sequence=%llu\n",
	       (unsigned long long)term, (unsigned long long)sequence);
	replicas[2].chain_digest[0] ^= 1;
	if (fjt_quorum_commit(&config, replicas, 3, &term, &sequence, digest) != FJT_OK)
		fail("QUORUM_TWO_OF_THREE", FJT_ERR_QUORUM);
	config.quorum_size = 3;
	replicas[1].chain_digest[0] ^= 1;
	if (fjt_quorum_commit(&config, replicas, 3, &term, &sequence, digest) != FJT_ERR_QUORUM)
		fail("SPLIT_BRAIN_DENIAL", FJT_ERR_QUORUM);
	printf("FJT_SPLIT_BRAIN_DENIED_OK\n");
	replicas[1].chain_digest[0] ^= 1;
	replicas[1].term = 8;
	if (fjt_quorum_commit(&config, replicas, 3, &term, &sequence, digest) != FJT_ERR_STALE)
		fail("FUTURE_TERM_DENIAL", FJT_ERR_STALE);
	printf("FJT_FUTURE_TERM_DENIED_OK\n");
	EVP_PKEY_free(crypto.public_key);
	EVP_PKEY_free(crypto.private_key);
	printf("FJT_SELFTEST_OK\n");
	return 0;
}
