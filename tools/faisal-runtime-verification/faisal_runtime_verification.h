#ifndef FAISAL_RUNTIME_VERIFICATION_H
#define FAISAL_RUNTIME_VERIFICATION_H

#include <stdint.h>
#include "../faisal-attestation/faisal_runtime_attestation.h"
#include "../faisal-self-healing/faisal_self_healing.h"

#define M87_DIGEST_SIZE FRA_DIGEST_SIZE
#define M87_SIGNATURE_SIZE 64
#define M87_MAX_BUNDLE_ID 96
#define M87_MAX_PAYLOAD 512
#define M87_MAX_SIGNED_BYTES (M87_MAX_BUNDLE_ID + M87_MAX_PAYLOAD + 128)
#define M87_MAX_JOURNAL_PATH 256

#define M87_PROVIDER_SOFTWARE 0U
#define M87_PROVIDER_HARDWARE_ATTESTATION (1U << 0)
#define M87_PROVIDER_REMOTE_ATTESTATION (1U << 1)

#define M87_SIGNAL_BOUND (1U << 0)
#define M87_BUNDLE_DIGEST_VALID (1U << 1)
#define M87_SIGNATURE_VALID (1U << 2)
#define M87_ATTESTATION_BOUND (1U << 3)
#define M87_PROVIDER_VALID (1U << 4)
#define M87_APPROVALS_VALID (1U << 5)

#define M87_OK 0
#define M87_ERR_ARGUMENT -1
#define M87_ERR_ATTESTATION -2
#define M87_ERR_SIGNAL -3
#define M87_ERR_DIGEST -4
#define M87_ERR_SIGNATURE -5
#define M87_ERR_PROVIDER -6
#define M87_ERR_APPROVAL -7
#define M87_ERR_POLICY -8
#define M87_ERR_STATE -9

struct m87_runtime_signal {
	uint64_t sequence;
	uint64_t observed_at_ns;
	uint32_t kind;
	uint32_t severity;
	int32_t status;
	uint64_t correlation;
	uint8_t attestation_digest[M87_DIGEST_SIZE];
};

struct m87_repair_bundle {
	char bundle_id[M87_MAX_BUNDLE_ID];
	uint8_t payload[M87_MAX_PAYLOAD];
	uint32_t payload_size;
	uint32_t required_provider;
	uint64_t policy_generation;
	uint64_t cpu_budget_ns;
	uint64_t memory_limit_pages;
	uint64_t canary_window_ns;
	uint8_t payload_digest[M87_DIGEST_SIZE];
	uint8_t bundle_digest[M87_DIGEST_SIZE];
	uint8_t attestation_digest[M87_DIGEST_SIZE];
	uint64_t signal_sequence;
	uint32_t supervisor_approved;
	uint32_t operator_approved;
	uint32_t integrity_measured;
	uint32_t canary_required;
	uint8_t signature[M87_SIGNATURE_SIZE];
};

struct m87_verification {
	uint32_t valid_mask;
	uint32_t provider_mask;
	uint64_t signal_sequence;
	uint32_t signal_kind;
	uint32_t signal_severity;
	int32_t status;
	uint8_t attestation_digest[M87_DIGEST_SIZE];
	uint8_t payload_digest[M87_DIGEST_SIZE];
	uint8_t bundle_digest[M87_DIGEST_SIZE];
	uint32_t state;
};

enum m87_state {
	M87_STATE_EMPTY = 0,
	M87_STATE_ATTESTED = 1,
	M87_STATE_SIGNAL_BOUND = 2,
	M87_STATE_BUNDLE_VERIFIED = 3,
	M87_STATE_REPAIR_ADMITTED = 4,
	M87_STATE_REPAIR_RECOVERED = 5,
	M87_STATE_REPAIR_ROLLED_BACK = 6,
	M87_STATE_QUARANTINED = 7
};

struct m87_service {
	struct fra_service attestation;
	char journal_path[M87_MAX_JOURNAL_PATH];
	struct fas_service healing;
	struct m87_runtime_signal signal;
	struct m87_verification verification;
	uint8_t trusted_public_key[32];
	uint32_t trusted_public_key_size;
	uint32_t provider_mask;
	uint32_t state;
};

int m87_open(struct m87_service *service, const char *journal_path);
void m87_close(struct m87_service *service);
int m87_sample_attestation(struct m87_service *service);
int m87_bind_signal(struct m87_service *service,
			const struct m87_runtime_signal *signal);
int m87_compute_payload_digest(const struct m87_repair_bundle *bundle,
			       uint8_t digest[M87_DIGEST_SIZE]);
int m87_compute_bundle_digest(const struct m87_repair_bundle *bundle,
			      uint8_t digest[M87_DIGEST_SIZE]);
int m87_verify_bundle(struct m87_service *service,
			     const struct m87_repair_bundle *bundle);
int m87_admit_repair(struct m87_service *service,
			    const struct m87_repair_bundle *bundle,
			    struct m78_candidate *candidate);
int m87_execute_repair(struct m87_service *service,
			      struct m78_candidate *candidate,
			      uint32_t canary_health);
int m87_provider_available(const struct m87_service *service,
			   uint32_t required_provider);
int m87_test_tampered_bundle(struct m87_service *service,
			     const struct m87_repair_bundle *bundle);
int m87_test_model_authority_denial(struct m87_service *service,
				    struct m78_candidate *candidate);

#endif
