// SPDX-License-Identifier: GPL-2.0-only
#include "../../faisal-key-provider/faisal_key_provider.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define M93_SERVICES M93_MAX_SERVICES
#define M93_CONCURRENT_ITERATIONS 64

struct m93_worker_arg {
	struct m90_key_provider *provider;
	struct m87_service *service;
	int result;
};

static void *concurrent_worker(void *opaque)
{
	struct m93_worker_arg *arg = opaque;
	unsigned int i;

	arg->result = 0;
	for (i = 0; i < M93_CONCURRENT_ITERATIONS; i++) {
		if (m90_provider_register_service(arg->provider, arg->service) != M90_OK ||
		    m90_provider_bind_service(arg->provider, arg->service) != M90_OK ||
		    m90_provider_unbind_service(arg->provider, arg->service) != M90_OK ||
		    m90_provider_unregister_service(arg->provider, arg->service) != M90_OK) {
			arg->result = M90_ERR_STATE;
			return NULL;
		}
	}
	return NULL;
}

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M93_FAIL:%s rc=%d\n", what, rc);
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

static int service_init(struct m87_service *service, const char *path)
{
	if (getenv("FAISAL_M93_HOST_MODE")) {
		memset(service, 0, sizeof(*service));
		service->trusted_key_required = 1;
		return M87_OK;
	}
	return m87_open(service, path);
}

static void service_close(struct m87_service *service)
{
	if (!getenv("FAISAL_M93_HOST_MODE"))
		m87_close(service);
}

static int all_bound(struct m87_service *services, unsigned int count,
			     const uint8_t key_id[M90_KEY_ID_SIZE],
			     uint64_t generation)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (services[i].trusted_public_key_size != M90_PUBLIC_KEY_SIZE ||
		    services[i].trusted_key_generation != generation ||
		    memcmp(services[i].trusted_key_id, key_id,
			   M90_KEY_ID_SIZE) != 0)
			return 0;
	return 1;
}

static int all_cleared(struct m87_service services[M93_SERVICES],
			       unsigned int first, unsigned int count)
{
	unsigned int i;

	for (i = first; i < first + count; i++)
		if (services[i].trusted_public_key_size != 0 ||
		    services[i].trusted_key_generation != 0 ||
		    !services[i].trusted_key_required)
			return 0;
	return 1;
}

int main(void)
{
	struct m90_key_provider provider;
	struct m87_service services[M93_SERVICES];
	struct m87_service extra_service;
	EVP_PKEY *key = NULL;
	EVP_PKEY *restart_key = NULL;
	EVP_PKEY *concurrent_key = NULL;
	uint8_t key_id[M90_KEY_ID_SIZE];
	uint8_t restart_id[M90_KEY_ID_SIZE];
	uint8_t concurrent_id[M90_KEY_ID_SIZE];
	uint64_t generation;
	uint64_t restart_generation;
	uint64_t concurrent_generation;
	char path[64];
	pthread_t threads[M93_SERVICES];
	struct m93_worker_arg workers[M93_SERVICES];
	unsigned int i;

	memset(services, 0, sizeof(services));
	if (m90_provider_init(&provider) != M90_OK || make_key(&key) != 0)
		return fail("initialization", M90_ERR_STATE);
	if (m90_provider_provision(&provider, key, key_id, &generation) != M90_OK)
		return fail("provision", M90_ERR_KEY);
	for (i = 0; i < M93_SERVICES; i++) {
		snprintf(path, sizeof(path), "/tmp/faisal-m93-%u", i);
		if (service_init(&services[i], path) != M87_OK ||
		    m90_provider_register_service(&provider, &services[i]) != M90_OK ||
		    m90_provider_bind_service(&provider, &services[i]) != M90_OK)
			return fail("service registration", M90_ERR_STATE);
	}
	if (provider.service_count != M93_SERVICES ||
	    !all_bound(services, M93_SERVICES, key_id, generation))
		return fail("multi-service binding", M90_ERR_STATE);
	printf("M93_MULTI_SERVICE_BIND_OK services=%zu\n", provider.service_count);
	if (service_init(&extra_service, "/tmp/faisal-m93-capacity") != M87_OK ||
	    m90_provider_register_service(&provider, &extra_service) !=
		M90_ERR_CAPACITY)
		return fail("service capacity", M90_ERR_CAPACITY);
	service_close(&extra_service);
	printf("M93_SERVICE_CAPACITY_DENIAL_OK capacity=%u\n", M93_MAX_SERVICES);

	if (m90_provider_revoke(&provider, key_id) != M90_OK ||
	    !all_cleared(services, 0, M93_SERVICES))
		return fail("revocation broadcast", M90_ERR_REVOKED);
	printf("M93_REVOCATION_BROADCAST_OK services=%u\n", M93_SERVICES);

	if (m90_provider_unregister_service(&provider, &services[0]) != M90_OK ||
	    provider.service_count != M93_SERVICES - 1)
		return fail("service unregister", M90_ERR_STATE);
	service_close(&services[0]);
	printf("M93_SAFE_SERVICE_CLOSE_OK remaining=%zu\n", provider.service_count);

	m90_provider_close(&provider);
	if (!all_cleared(services, 1, M93_SERVICES - 1) ||
	    provider.service_count != 0)
		return fail("provider close cleanup", M90_ERR_STATE);
	for (i = 1; i < M93_SERVICES; i++)
		service_close(&services[i]);
	printf("M93_PROVIDER_CLOSE_CLEANUP_OK\n");

	if (m90_provider_init(&provider) != M90_OK || make_key(&restart_key) != 0 ||
	    m90_provider_provision(&provider, restart_key, restart_id,
				   &restart_generation) != M90_OK)
		return fail("restart init", M90_ERR_STATE);
	for (i = 1; i < M93_SERVICES; i++) {
		snprintf(path, sizeof(path), "/tmp/faisal-m93-restart-%u", i);
		if (service_init(&services[i], path) != M87_OK ||
		    m90_provider_register_service(&provider, &services[i]) != M90_OK ||
		    m90_provider_bind_service(&provider, &services[i]) != M90_OK)
			return fail("restart service recovery", M90_ERR_STATE);
	}
	if (!all_bound(services + 1, M93_SERVICES - 1, restart_id, restart_generation))
		return fail("restart binding", M90_ERR_STATE);
	printf("M93_CONTROLLED_RESTART_RECOVERY_OK services=%zu\n",
	       provider.service_count);
	for (i = 1; i < M93_SERVICES; i++) {
		if (m90_provider_unregister_service(&provider, &services[i]) != M90_OK)
			return fail("restart unregister", M90_ERR_STATE);
		service_close(&services[i]);
	}
	m90_provider_close(&provider);

	if (m90_provider_init(&provider) != M90_OK ||
	    make_key(&concurrent_key) != 0 ||
	    m90_provider_key_id(concurrent_key, concurrent_id) != M90_OK ||
	    m90_provider_provision(&provider, concurrent_key, concurrent_id,
				   &concurrent_generation) != M90_OK)
		return fail("concurrent init", M90_ERR_STATE);
	for (i = 0; i < M93_SERVICES; i++) {
		snprintf(path, sizeof(path), "/tmp/faisal-m93-concurrent-%u", i);
		if (service_init(&services[i], path) != M87_OK)
			return fail("concurrent service init", M90_ERR_STATE);
		workers[i].provider = &provider;
		workers[i].service = &services[i];
		workers[i].result = M90_ERR_STATE;
		if (pthread_create(&threads[i], NULL, concurrent_worker, &workers[i]) != 0)
			return fail("concurrent thread create", M90_ERR_STATE);
	}
	for (i = 0; i < M93_SERVICES; i++)
		if (pthread_join(threads[i], NULL) != 0 || workers[i].result != 0)
			return fail("concurrent table stress", M90_ERR_STATE);
	if (provider.service_count != 0)
		return fail("concurrent table cleanup", M90_ERR_STATE);
	for (i = 0; i < M93_SERVICES; i++)
		service_close(&services[i]);
	m90_provider_close(&provider);
	EVP_PKEY_free(concurrent_key);
	EVP_PKEY_free(key);
	EVP_PKEY_free(restart_key);
	printf("M93_CONCURRENT_TABLE_STRESS_OK workers=%u iterations=%u\n",
	       M93_SERVICES, M93_CONCURRENT_ITERATIONS);
	printf("M93_PROCESS_CRASH_RECOVERY_NONCLAIM_OK\n");
	printf("M93_SELFTEST_EXIT=0\n");
	return 0;
}
