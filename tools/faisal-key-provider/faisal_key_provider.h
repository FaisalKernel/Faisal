#ifndef FAISAL_KEY_PROVIDER_H
#define FAISAL_KEY_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <pthread.h>

#include "../faisal-runtime-verification/faisal_runtime_verification.h"

#define M90_MAX_KEYS 4
#define M90_PUBLIC_KEY_SIZE 32
#define M90_KEY_ID_SIZE M87_KEY_ID_SIZE

#define M90_OK 0
#define M90_ERR_ARGUMENT -1
#define M90_ERR_CAPACITY -2
#define M90_ERR_KEY -3
#define M90_ERR_REVOKED -4
#define M90_ERR_NOT_FOUND -5
#define M90_ERR_STATE -6
#define M90_ERR_SIGNATURE -7

struct m90_key_slot {
	uint8_t key_id[M90_KEY_ID_SIZE];
	uint64_t generation;
	EVP_PKEY *private_key;
	int active;
	int revoked;
};

struct m90_key_provider {
	struct m90_key_slot slots[M90_MAX_KEYS];
	size_t count;
	uint64_t next_generation;
	struct m87_service *bound_service;
	pthread_mutex_t lock;
	int initialized;
};

int m90_provider_init(struct m90_key_provider *provider);
void m90_provider_close(struct m90_key_provider *provider);
int m90_provider_key_id(EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE]);
int m90_provider_provision(struct m90_key_provider *provider,
			   EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE],
			   uint64_t *generation);
int m90_provider_rotate(struct m90_key_provider *provider,
			 EVP_PKEY *key, uint8_t key_id[M90_KEY_ID_SIZE],
			 uint64_t *generation);
int m90_provider_revoke(struct m90_key_provider *provider,
			const uint8_t key_id[M90_KEY_ID_SIZE]);
int m90_provider_sign_active(struct m90_key_provider *provider,
			     const void *data, size_t size,
			     uint8_t signature[M87_SIGNATURE_SIZE]);
int m90_provider_bind_service(struct m90_key_provider *provider,
			      struct m87_service *service);
int m90_provider_unbind_service(struct m90_key_provider *provider,
				struct m87_service *service);

#endif
