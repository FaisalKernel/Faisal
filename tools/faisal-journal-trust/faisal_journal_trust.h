#ifndef FAISAL_JOURNAL_TRUST_H
#define FAISAL_JOURNAL_TRUST_H

#include <stddef.h>
#include <stdint.h>

#define FJT_DIGEST_SIZE 32U
#define FJT_PUBLIC_KEY_SIZE 32U
#define FJT_SIGNATURE_SIZE 64U
#define FJT_NONCE_SIZE 32U
#define FJT_MAX_REPLICAS 16U
#define FJT_FORMAT_VERSION 1U

#define FJT_PROVIDER_SOFTWARE 0U
#define FJT_PROVIDER_TPM2 (1U << 0)
#define FJT_PROVIDER_SECURE_ENCLAVE (1U << 1)
#define FJT_PROVIDER_REMOTE_VERIFIER (1U << 2)

#define FJT_OK 0
#define FJT_ERR_ARGUMENT -1
#define FJT_ERR_CRYPTO -2
#define FJT_ERR_PROVIDER -3
#define FJT_ERR_POLICY -4
#define FJT_ERR_QUORUM -5
#define FJT_ERR_CONFLICT -6
#define FJT_ERR_STALE -7
#define FJT_ERR_ATTESTATION -8

struct fjt_journal_attestation {
	uint32_t format_version;
	uint32_t provider_mask;
	uint64_t record_count;
	uint64_t last_sequence;
	uint64_t root_generation;
	uint64_t observed_at_ns;
	uint8_t chain_digest[FJT_DIGEST_SIZE];
	uint8_t nonce[FJT_NONCE_SIZE];
};

struct fjt_provider {
	uint32_t provider_mask;
	uint64_t key_generation;
	void *ctx;
	int (*sign)(void *ctx, const uint8_t *message, size_t message_size,
			uint8_t signature[FJT_SIGNATURE_SIZE]);
	int (*verify)(void *ctx, const uint8_t *message, size_t message_size,
			const uint8_t signature[FJT_SIGNATURE_SIZE]);
	int (*quote)(void *ctx, const uint8_t nonce[FJT_NONCE_SIZE],
		     const uint8_t journal_digest[FJT_DIGEST_SIZE],
		     uint8_t quote_digest[FJT_DIGEST_SIZE]);
};

struct fjt_signed_attestation {
	struct fjt_journal_attestation report;
	uint8_t quote_digest[FJT_DIGEST_SIZE];
	uint8_t signature[FJT_SIGNATURE_SIZE];
	uint64_t key_generation;
};

struct fjt_replica_observation {
	uint64_t replica_id;
	uint64_t term;
	uint64_t last_sequence;
	uint8_t chain_digest[FJT_DIGEST_SIZE];
	uint32_t healthy;
	uint32_t signature_valid;
};

struct fjt_quorum_config {
	uint32_t replica_count;
	uint32_t quorum_size;
	uint64_t current_term;
};

int fjt_sign_attestation(const struct fjt_journal_attestation *report,
			 const struct fjt_provider *provider,
			 struct fjt_signed_attestation *out);
int fjt_verify_attestation(const struct fjt_signed_attestation *signed_report,
			   const struct fjt_provider *provider);
int fjt_bind_hardware_quote(struct fjt_signed_attestation *signed_report,
			    const struct fjt_provider *provider);
int fjt_quorum_validate_config(const struct fjt_quorum_config *config);
int fjt_quorum_commit(const struct fjt_quorum_config *config,
			 const struct fjt_replica_observation *observations,
			 size_t observation_count,
			 uint64_t *committed_term, uint64_t *committed_sequence,
			 uint8_t committed_digest[FJT_DIGEST_SIZE]);

#endif
