#include "faisal_key_provider.h"

#include <string.h>

static struct m90_key_slot *find_key_locked(struct m90_key_provider *provider,
					     const uint8_t key_id[M90_KEY_ID_SIZE])
{
	size_t i;

	for (i = 0; i < provider->count; i++)
		if (memcmp(provider->slots[i].key_id, key_id,
			   M90_KEY_ID_SIZE) == 0)
			return &provider->slots[i];
	return NULL;
}

static struct m90_key_slot *active_key_locked(struct m90_key_provider *provider)
{
	size_t i;

	for (i = 0; i < provider->count; i++)
		if (provider->slots[i].active && !provider->slots[i].revoked)
			return &provider->slots[i];
	return NULL;
}

static int service_index_locked(struct m90_key_provider *provider,
				struct m87_service *service)
{
	size_t i;

	for (i = 0; i < provider->service_count; i++)
		if (provider->services[i].service == service)
			return (int)i;
	return -1;
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

static void clear_service_locked(struct m90_key_provider *provider,
				 struct m87_service *service)
{
	if (!service)
		return;
	memset(service->trusted_public_key, 0, sizeof(service->trusted_public_key));
	service->trusted_public_key_size = 0;
	memset(service->trusted_key_id, 0, sizeof(service->trusted_key_id));
	service->trusted_key_generation = 0;
	service->trusted_key_required = 1;
	invalidate_service(service);
	(void)provider;
}

static int register_service_locked(struct m90_key_provider *provider,
				   struct m87_service *service)
{
	if (!service)
		return M90_ERR_ARGUMENT;
	if (service_index_locked(provider, service) >= 0)
		return M90_OK;
	if (provider->service_count >= M93_MAX_SERVICES)
		return M90_ERR_CAPACITY;
	provider->services[provider->service_count++].service = service;
	return M90_OK;
}

static void unregister_service_locked(struct m90_key_provider *provider,
				      struct m87_service *service)
{
	int index = service_index_locked(provider, service);
	size_t i;

	if (index < 0)
		return;
	clear_service_locked(provider, service);
	for (i = (size_t)index; i + 1 < provider->service_count; i++)
		provider->services[i] = provider->services[i + 1];
	provider->services[provider->service_count - 1].service = NULL;
	provider->service_count--;
}

static void clear_all_services_locked(struct m90_key_provider *provider)
{
	size_t i;

	for (i = 0; i < provider->service_count; i++)
		clear_service_locked(provider, provider->services[i].service);
	memset(provider->services, 0, sizeof(provider->services));
	provider->service_count = 0;
}

int m90_provider_init(struct m90_key_provider *provider)
{
	if (!provider)
		return M90_ERR_ARGUMENT;
	memset(provider, 0, sizeof(*provider));
	if (pthread_mutex_init(&provider->lock, NULL) != 0)
		return M90_ERR_STATE;
	provider->next_generation = 1;
	provider->initialized = 1;
	return M90_OK;
}

void m90_provider_close(struct m90_key_provider *provider)
{
	size_t i;

	if (!provider || !provider->initialized)
		return;
	pthread_mutex_lock(&provider->lock);
	clear_all_services_locked(provider);
	for (i = 0; i < provider->count; i++) {
		EVP_PKEY_free(provider->slots[i].private_key);
		provider->slots[i].private_key = NULL;
	}
	provider->initialized = 0;
	pthread_mutex_unlock(&provider->lock);
	pthread_mutex_destroy(&provider->lock);
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

static int add_key_locked(struct m90_key_provider *provider, EVP_PKEY *key,
			  uint8_t key_id[M90_KEY_ID_SIZE], uint64_t *generation,
			  struct m90_key_slot **slot_out)
{
	struct m90_key_slot *slot;

	if (!key || !key_id || !generation)
		return M90_ERR_ARGUMENT;
	if (provider->count >= M90_MAX_KEYS)
		return M90_ERR_CAPACITY;
	if (m90_provider_key_id(key, key_id) != M90_OK)
		return M90_ERR_KEY;
	if (find_key_locked(provider, key_id))
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
	int rc;

	if (!provider || !provider->initialized)
		return M90_ERR_STATE;
	pthread_mutex_lock(&provider->lock);
	rc = add_key_locked(provider, key, key_id, generation, NULL);
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_rotate(struct m90_key_provider *provider,
			 EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE],
			 uint64_t *generation)
{
	struct m90_key_slot *slot;
	size_t i;
	int rc;

	if (!provider || !provider->initialized)
		return M90_ERR_STATE;
	pthread_mutex_lock(&provider->lock);
	rc = add_key_locked(provider, key, key_id, generation, &slot);
	if (rc == M90_OK)
		for (i = 0; i < provider->count; i++)
			if (&provider->slots[i] != slot && provider->slots[i].active)
				provider->slots[i].active = 0;
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_revoke(struct m90_key_provider *provider,
			const uint8_t key_id[M90_KEY_ID_SIZE])
{
	struct m90_key_slot *slot;
	size_t i;
	int rc = M90_OK;

	if (!provider || !provider->initialized || !key_id)
		return M90_ERR_ARGUMENT;
	pthread_mutex_lock(&provider->lock);
	slot = find_key_locked(provider, key_id);
	if (!slot) {
		rc = M90_ERR_NOT_FOUND;
		goto out;
	}
	slot->active = 0;
	slot->revoked = 1;
	for (i = 0; i < provider->service_count; i++)
		if (memcmp(provider->services[i].service->trusted_key_id, key_id,
			   M90_KEY_ID_SIZE) == 0)
			clear_service_locked(provider, provider->services[i].service);
	EVP_PKEY_free(slot->private_key);
	slot->private_key = NULL;
out:
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_sign_active(struct m90_key_provider *provider,
			     const void *data, size_t size,
			     uint8_t signature[M87_SIGNATURE_SIZE])
{
	struct m90_key_slot *slot;
	EVP_MD_CTX *ctx;
	size_t signature_size = M87_SIGNATURE_SIZE;
	int rc = M90_ERR_SIGNATURE;

	if (!provider || !provider->initialized || (!data && size) || !signature)
		return M90_ERR_ARGUMENT;
	pthread_mutex_lock(&provider->lock);
	slot = active_key_locked(provider);
	if (!slot) {
		rc = M90_ERR_REVOKED;
		goto out;
	}
	ctx = EVP_MD_CTX_new();
	if (ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, slot->private_key) == 1 &&
	    EVP_DigestSign(ctx, signature, &signature_size, data, size) == 1 &&
	    signature_size == M87_SIGNATURE_SIZE)
		rc = M90_OK;
	EVP_MD_CTX_free(ctx);
out:
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_register_service(struct m90_key_provider *provider,
					struct m87_service *service)
{
	int rc;

	if (!provider || !provider->initialized || !service)
		return M90_ERR_ARGUMENT;
	pthread_mutex_lock(&provider->lock);
	rc = register_service_locked(provider, service);
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_unregister_service(struct m90_key_provider *provider,
				      struct m87_service *service)
{
	if (!provider || !provider->initialized || !service)
		return M90_ERR_ARGUMENT;
	pthread_mutex_lock(&provider->lock);
	unregister_service_locked(provider, service);
	pthread_mutex_unlock(&provider->lock);
	return M90_OK;
}

int m90_provider_bind_service(struct m90_key_provider *provider,
			      struct m87_service *service)
{
	struct m90_key_slot *slot;
	size_t public_size = sizeof(service->trusted_public_key);
	int rc = M90_OK;

	if (!provider || !provider->initialized || !service)
		return M90_ERR_ARGUMENT;
	pthread_mutex_lock(&provider->lock);
	rc = register_service_locked(provider, service);
	if (rc != M90_OK)
		goto out;
	slot = active_key_locked(provider);
	if (!slot) {
		rc = M90_ERR_REVOKED;
		goto out;
	}
	if (EVP_PKEY_get_raw_public_key(slot->private_key,
					service->trusted_public_key,
					&public_size) != 1 ||
	    public_size != sizeof(service->trusted_public_key)) {
		rc = M90_ERR_KEY;
		goto out;
	}
	memcpy(service->trusted_key_id, slot->key_id, M90_KEY_ID_SIZE);
	service->trusted_key_generation = slot->generation;
	service->trusted_key_required = 1;
	service->trusted_public_key_size = public_size;
	invalidate_service(service);
out:
	pthread_mutex_unlock(&provider->lock);
	return rc;
}

int m90_provider_unbind_service(struct m90_key_provider *provider,
				struct m87_service *service)
{
	if (!service)
		return M90_ERR_ARGUMENT;
	if (!provider || !provider->initialized)
		return M90_ERR_STATE;
	pthread_mutex_lock(&provider->lock);
	if (service_index_locked(provider, service) < 0) {
		pthread_mutex_unlock(&provider->lock);
		return M90_ERR_NOT_FOUND;
	}
	clear_service_locked(provider, service);
	pthread_mutex_unlock(&provider->lock);
	return M90_OK;
}
