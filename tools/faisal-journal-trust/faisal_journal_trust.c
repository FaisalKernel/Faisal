#include "faisal_journal_trust.h"
#include <string.h>

static int hardware_provider(const struct fjt_provider *provider)
{
	return provider && (provider->provider_mask &
			(FJT_PROVIDER_TPM2 | FJT_PROVIDER_SECURE_ENCLAVE));
}

int fjt_sign_attestation(const struct fjt_journal_attestation *report,
			 const struct fjt_provider *provider,
			 struct fjt_signed_attestation *out)
{
	if (!report || !provider || !out || !provider->sign ||
	    !(provider->provider_mask & FJT_PROVIDER_REMOTE_VERIFIER))
		return FJT_ERR_ARGUMENT;
	if (report->format_version != FJT_FORMAT_VERSION || !report->record_count ||
	    report->last_sequence != report->record_count || !provider->key_generation)
		return FJT_ERR_POLICY;
	memset(out, 0, sizeof(*out));
	out->report = *report;
	out->key_generation = provider->key_generation;
	if (provider->sign(provider->ctx, (const uint8_t *)&out->report,
			  sizeof(out->report), out->signature) != 0)
		return FJT_ERR_CRYPTO;
	return FJT_OK;
}

int fjt_verify_attestation(const struct fjt_signed_attestation *signed_report,
			   const struct fjt_provider *provider)
{
	if (!signed_report || !provider || !provider->verify ||
	    !(provider->provider_mask & FJT_PROVIDER_REMOTE_VERIFIER))
		return FJT_ERR_ARGUMENT;
	if (signed_report->report.format_version != FJT_FORMAT_VERSION ||
	    !signed_report->report.record_count ||
	    signed_report->report.last_sequence != signed_report->report.record_count ||
	    signed_report->key_generation != provider->key_generation)
		return FJT_ERR_ATTESTATION;
	if (provider->verify(provider->ctx,
			    (const uint8_t *)&signed_report->report,
			    sizeof(signed_report->report), signed_report->signature) != 0)
		return FJT_ERR_CRYPTO;
	return FJT_OK;
}

int fjt_bind_hardware_quote(struct fjt_signed_attestation *signed_report,
			    const struct fjt_provider *provider)
{
	if (!signed_report || !provider || !provider->quote)
		return FJT_ERR_ARGUMENT;
	if (!hardware_provider(provider))
		return FJT_ERR_PROVIDER;
	if (provider->key_generation != signed_report->key_generation)
		return FJT_ERR_ATTESTATION;
	if (provider->quote(provider->ctx, signed_report->report.nonce,
			    signed_report->report.chain_digest,
			    signed_report->quote_digest) != 0)
		return FJT_ERR_PROVIDER;
	return FJT_OK;
}

int fjt_quorum_validate_config(const struct fjt_quorum_config *config)
{
	if (!config || !config->replica_count ||
	    config->replica_count > FJT_MAX_REPLICAS || !config->current_term ||
	    config->quorum_size <= config->replica_count / 2 ||
	    config->quorum_size > config->replica_count)
		return FJT_ERR_POLICY;
	return FJT_OK;
}

int fjt_quorum_commit(const struct fjt_quorum_config *config,
			 const struct fjt_replica_observation *observations,
			 size_t observation_count,
			 uint64_t *committed_term, uint64_t *committed_sequence,
			 uint8_t committed_digest[FJT_DIGEST_SIZE])
{
	size_t i, j;
	uint32_t best_count = 0;
	uint64_t best_sequence = 0;
	uint8_t best_digest[FJT_DIGEST_SIZE] = { 0 };

	if (fjt_quorum_validate_config(config) != FJT_OK || !observations ||
	    !observation_count || !committed_term || !committed_sequence ||
	    !committed_digest || observation_count > FJT_MAX_REPLICAS)
		return FJT_ERR_ARGUMENT;
	for (i = 0; i < observation_count; i++) {
		if (!observations[i].replica_id)
			return FJT_ERR_ARGUMENT;
		if (observations[i].term > config->current_term)
			return FJT_ERR_STALE;
		for (j = 0; j < i; j++)
			if (observations[j].replica_id == observations[i].replica_id)
				return FJT_ERR_CONFLICT;
	}
	for (i = 0; i < observation_count; i++) {
		uint32_t count = 0;
		if (!observations[i].healthy || !observations[i].signature_valid ||
		    observations[i].term != config->current_term)
			continue;
		for (j = 0; j < observation_count; j++)
			if (observations[j].healthy && observations[j].signature_valid &&
			    observations[j].term == config->current_term &&
			    observations[j].last_sequence == observations[i].last_sequence &&
			    memcmp(observations[j].chain_digest, observations[i].chain_digest,
				   FJT_DIGEST_SIZE) == 0)
				count++;
		if (count > best_count) {
			best_count = count;
			best_sequence = observations[i].last_sequence;
			memcpy(best_digest, observations[i].chain_digest, FJT_DIGEST_SIZE);
		}
	}
	if (best_count < config->quorum_size)
		return FJT_ERR_QUORUM;
	*committed_term = config->current_term;
	*committed_sequence = best_sequence;
	memcpy(committed_digest, best_digest, FJT_DIGEST_SIZE);
	return FJT_OK;
}
