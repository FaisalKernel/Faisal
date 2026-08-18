#include "faisal_platform_adapter.h"

#include <openssl/evp.h>
#include <string.h>

static int bounded_string(const char *value, size_t size)
{
	return value != NULL && value[0] != '\0' && memchr(value, '\0', size) != NULL;
}

static int digest_bytes(const void *data, size_t length,
			uint8_t digest[FPL_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0U;
	int result = FPA_ERR_TAMPER;

	if ((data == NULL && length != 0U) || digest == NULL)
		return FPA_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL)
		return FPA_ERR_TAMPER;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(ctx, data, length) == 1 &&
	    EVP_DigestFinal_ex(ctx, digest, &digest_length) == 1 &&
	    digest_length == FPL_DIGEST_SIZE)
		result = FPA_OK;
	EVP_MD_CTX_free(ctx);
	return result;
}

int fpa_provider_claim_digest(const struct fpa_provider_claim *claim,
			      uint8_t digest[FPL_DIGEST_SIZE])
{
	struct fpa_provider_claim canonical;

	if (claim == NULL || digest == NULL)
		return FPA_ERR_ARGUMENT;
	canonical = *claim;
	memset(canonical.claim_digest, 0, sizeof(canonical.claim_digest));
	return digest_bytes(&canonical, sizeof(canonical), digest);
}

int fpa_validate_provider_claim(const struct fpa_provider_claim *claim)
{
	uint8_t digest[FPL_DIGEST_SIZE];

	if (claim == NULL || claim->abi_version != FPA_ABI_VERSION ||
	    claim->provider_kind < FPL_PROVIDER_KUBERNETES_DRA ||
	    claim->provider_kind > FPL_PROVIDER_EDGE || claim->workload_id == 0U ||
	    claim->requested_devices == 0U || claim->requested_memory_bytes == 0U ||
	    claim->requested_network_mbps == 0U || claim->requested_storage_bytes == 0U ||
	    claim->flags & ~(FPA_FLAG_DEVICE_SHARING | FPA_FLAG_TOPOLOGY_BOUND |
			     FPA_FLAG_CHECKPOINT_CAPABLE | FPA_FLAG_NETWORK_DIRECT) ||
	    !bounded_string(claim->claim_id, sizeof(claim->claim_id)) ||
	    !bounded_string(claim->runtime_ref, sizeof(claim->runtime_ref)) ||
	    !bounded_string(claim->device_class, sizeof(claim->device_class)) ||
	    !bounded_string(claim->topology, sizeof(claim->topology)) ||
	    fpa_provider_claim_digest(claim, digest) != FPA_OK ||
	    memcmp(digest, claim->claim_digest, FPL_DIGEST_SIZE) != 0)
		return FPA_ERR_TAMPER;
	return FPA_OK;
}

int fpa_bind_provider_claim(struct fpl_intent *intent,
			    struct fpa_provider_claim *claim)
{
	uint8_t digest[FPL_DIGEST_SIZE];

	if (intent == NULL || claim == NULL || claim->workload_id != intent->workload_id ||
	    claim->requested_devices != intent->required_accelerator_count ||
	    claim->requested_memory_bytes != intent->required_memory_bytes ||
	    claim->requested_network_mbps != intent->required_network_mbps ||
	    claim->requested_storage_bytes != intent->required_storage_bytes ||
	    claim->device_mask != intent->required_accelerator_mask)
		return FPA_ERR_WORKLOAD;
	if (claim->abi_version != FPA_ABI_VERSION ||
	    claim->provider_kind < FPL_PROVIDER_KUBERNETES_DRA ||
	    claim->provider_kind > FPL_PROVIDER_EDGE ||
	    !bounded_string(claim->claim_id, sizeof(claim->claim_id)) ||
	    !bounded_string(claim->runtime_ref, sizeof(claim->runtime_ref)) ||
	    !bounded_string(claim->device_class, sizeof(claim->device_class)) ||
	    !bounded_string(claim->topology, sizeof(claim->topology)))
		return FPA_ERR_BOUNDS;
	if (fpa_provider_claim_digest(claim, digest) != FPA_OK)
		return FPA_ERR_TAMPER;
	memcpy(claim->claim_digest, digest, FPL_DIGEST_SIZE);
	intent->provider_kind = claim->provider_kind;
	memcpy(intent->provider_claim_digest, digest, FPL_DIGEST_SIZE);
	return FPA_OK;
}

int fpa_test_untrusted_provider_metadata(const struct fpa_provider_claim *claim)
{
	struct fpa_provider_claim mutated;
	uint8_t digest[FPL_DIGEST_SIZE];

	if (claim == NULL || fpa_provider_claim_digest(claim, digest) != FPA_OK)
		return FPA_ERR_ARGUMENT;
	mutated = *claim;
	memcpy(mutated.claim_digest, digest, FPL_DIGEST_SIZE);
	mutated.claim_digest[0] ^= 0x01U;
	return fpa_validate_provider_claim(&mutated) != FPA_OK ? FPA_OK : FPA_ERR_TAMPER;
}
