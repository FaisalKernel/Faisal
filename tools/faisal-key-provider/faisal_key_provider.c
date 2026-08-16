#include "faisal_key_provider.h"

#include <string.h>

static struct m90_key_slot *find_key(struct m90_key_provider *provider,
				      const uint8_t key_id[M90_KEY_ID_SIZE])
{
	size_t i;

	for (i = 0; i < provider->count; i++)
		if (memcmp(provider->slots[i].key_id, key_id,
			   M90_KEY_ID_SIZE) == 0)
			return &provider->slots[i];
	return NULL;
}

static void invalidate_service(struct m87_service *service)
{
	if (!service)
		return;
	if (service->state >= M87_STATE_BUNDLE_VERIFIED) {
		service->state = M87_STATE_SIGNAL_BOUND;
		service->verification.state = M87_STATE_SIGNAL_BOUND;
		service->verification.valid_mask = M87_SIGNAL_BOUND |
			M87_ATTESTATION_BOUND;
	}
}

static struct m90_key_slot *active_key(struct m90_key_provider *provider)
{
	size_t i;

	for (i = 0; i < provider->count; i++)
		if (provider->slots[i].active && !provider->slots[i].revoked)
			return &provider->slots[i];
	return NULL;
}

int m90_provider_init(struct m90_key_provider *provider)
{
	if (!provider)
		return M90_ERR_ARGUMENT;
	memset(provider, 0, sizeof(*provider));
	provider->next_generation = 1;
	return M90_OK;
}

void m90_provider_close(struct m90_key_provider *provider)
{
	size_t i;

	if (!provider)
		return;
	for (i = 0; i < provider->count; i++) {
		EVP_PKEY_free(provider->slots[i].private_key);
		provider->slots[i].private_key = NULL;
	}
	memset(provider, 0, sizeof(*provider));
}

int m90_provider_key_id(EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE])
{
	uint8_t public_key[M90_PUBLIC_KEY_SIZE];
	size_t public_size = sizeof(public_key);
	unsigned int digest_size = M90_KEY_ID_SIZE;

	if (!key || !key_id ||
	    EVP_PKEY_get_raw_public_key(key, public_key, &public_size) != 1 ||
	    public_size != M90_PUBLIC_KEY_SIZE ||
	    EVP_Digest(public_key, public_size, key_id, &digest_size,
		       EVP_sha256(), NULL) != 1 ||
	    digest_size != M90_KEY_ID_SIZE)
		return M90_ERR_KEY;
	return M90_OK;
}

static int add_key(struct m90_key_provider *provider, EVP_PKEY *key,
		   uint8_t key_id[M90_KEY_ID_SIZE], uint64_t *generation,
		   struct m90_key_slot **slot_out)
{
	struct m90_key_slot *slot;

	if (!provider || !key || !key_id || !generation)
		return M90_ERR_ARGUMENT;
	if (provider->count >= M90_MAX_KEYS)
		return M90_ERR_CAPACITY;
	if (m90_provider_key_id(key, key_id) != M90_OK)
		return M90_ERR_KEY;
	if (find_key(provider, key_id))
		return M90_ERR_STATE;
	if (EVP_PKEY_up_ref(key) != 1)
		return M90_ERR_KEY;
	slot = &provider->slots[provider->count++];
	memcpy(slot->key_id, key_id, M90_KEY_ID_SIZE);
	slot->generation = provider->next_generation++;
	slot->private_key = key;
	slot->active = 1;
	slot->revoked = 0;
	*generation = slot->generation;
	if (slot_out)
		*slot_out = slot;
	return M90_OK;
}

int m90_provider_provision(struct m90_key_provider *provider,
			   EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE],
			   uint64_t *generation)
{
	return add_key(provider, key, key_id, generation, NULL);
}

int m90_provider_rotate(struct m90_key_provider *provider,
			 EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE],
			 uint64_t *generation)
{
	struct m90_key_slot *slot;
	size_t i;
	int rc;

	rc = add_key(provider, key, key_id, generation, &slot);
	if (rc != M90_OK)
		return rc;
	for (i = 0; i < provider->count; i++)
		if (&provider->slots[i] != slot && provider->slots[i].active)
			provider->slots[i].active = 0;
	return M90_OK;
}

int m90_provider_revoke(struct m90_key_provider *provider,
			const uint8_t key_id[M90_KEY_ID_SIZE])
{
	struct m90_key_slot *slot;

	if (!provider || !key_id)
		return M90_ERR_ARGUMENT;
	slot = find_key(provider, key_id);
	if (!slot)
		return M90_ERR_NOT_FOUND;
	slot->active = 0;
	slot->revoked = 1;
	if (provider->bound_service &&
	    memcmp(provider->bound_service->trusted_key_id, key_id,
		   M90_KEY_ID_SIZE) == 0)
		m90_provider_unbind_service(provider, provider->bound_service);
	EVP_PKEY_free(slot->private_key);
	slot->private_key = NULL;
	return M90_OK;
}

int m90_provider_sign_active(struct m90_key_provider *provider,
			     const void *data, size_t size,
			     uint8_t signature[M87_SIGNATURE_SIZE])
{
	struct m90_key_slot *slot;
	EVP_MD_CTX *ctx;
	size_t signature_size = M87_SIGNATURE_SIZE;
	int rc = M90_ERR_SIGNATURE;

	if (!provider || (!data && size) || !signature)
		return M90_ERR_ARGUMENT;
	slot = active_key(provider);
	if (!slot)
		return M90_ERR_REVOKED;
	ctx = EVP_MD_CTX_new();
	if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, slot->private_key) == 1 &&
	    EVP_DigestSign(ctx, signature, &signature_size, data, size) == 1 &&
	    signature_size == M87_SIGNATURE_SIZE)
		rc = M90_OK;
	EVP_MD_CTX_free(ctx);
	return rc;
}

int m90_provider_bind_service(struct m90_key_provider *provider,
			      struct m87_service *service)
{
	struct m90_key_slot *slot;
	size_t public_size = sizeof(service->trusted_public_key);

	if (!provider || !service)
		return M90_ERR_ARGUMENT;
	slot = active_key(provider);
	if (!slot)
		return M90_ERR_REVOKED;
	if (EVP_PKEY_get_raw_public_key(slot->private_key,
					service->trusted_public_key,
					&public_size) != 1 ||
	    public_size != sizeof(service->trusted_public_key))
		return M90_ERR_KEY;
	memcpy(service->trusted_key_id, slot->key_id, M90_KEY_ID_SIZE);
	service->trusted_key_generation = slot->generation;
	service->trusted_key_required = 1;
	service->trusted_public_key_size = public_size;
	invalidate_service(service);
	provider->bound_service = service;
	return M90_OK;
}

int m90_provider_unbind_service(struct m90_key_provider *provider,
				struct m87_service *service)
{
	if (!service)
		return M90_ERR_ARGUMENT;
	memset(service->trusted_public_key, 0, sizeof(service->trusted_public_key));
	service->trusted_public_key_size = 0;
	memset(service->trusted_key_id, 0, sizeof(service->trusted_key_id));
	service->trusted_key_generation = 0;
	service->trusted_key_required = 1;
	invalidate_service(service);
	if (provider && provider->bound_service == service)
		provider->bound_service = NULL;
	return M90_OK;
}
