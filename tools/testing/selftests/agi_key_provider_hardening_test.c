// SPDX-License-Identifier: GPL-2.0-only
#include "../../faisal-key-provider/faisal_key_provider.h"

#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define M92_SIGN_WORKERS 4
#define M92_TOTAL_WORKERS 7
#define M92_SIGN_ITERATIONS 128
#define M92_BIND_ITERATIONS 128
#define M92_REVOKE_ITERATIONS 256

struct m92_context {
	struct m90_key_provider provider;
	struct m87_service service;
	EVP_PKEY *keys[4];
	uint8_t ids[4][M90_KEY_ID_SIZE];
	uint64_t generations[4];
	pthread_barrier_t barrier;
	atomic_int failures;
	atomic_uint sign_ops;
	atomic_uint rotate_ops;
	atomic_uint revoke_ops;
};

static int fail(const char *what, int rc)
{
	fprintf(stderr, "M92_FAIL:%s rc=%d\n", what, rc);
	return 1;
}

static void record_failure(struct m92_context *ctx)
{
	atomic_fetch_add_explicit(&ctx->failures, 1, memory_order_relaxed);
}

static int make_key(EVP_PKEY **key)
{
	EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	int rc = -1;

	if (gen && EVP_PKEY_keygen_init(gen) == 1 &&
	    EVP_PKEY_keygen(gen, key) == 1)
		rc = 0;
	EVP_PKEY_CTX_free(gen);
	return rc;
}

static void *sign_worker(void *arg)
{
	struct m92_context *ctx = arg;
	uint8_t data[32] = { 0 };
	uint8_t signature[M87_SIGNATURE_SIZE];
	unsigned int i;

	pthread_barrier_wait(&ctx->barrier);
	for (i = 0; i < M92_SIGN_ITERATIONS; i++) {
		memcpy(data, &i, sizeof(i));
		{
			int rc = m90_provider_sign_active(&ctx->provider, data,
						   sizeof(data), signature);

			if (rc != M90_OK && rc != M90_ERR_REVOKED)
				record_failure(ctx);
			else if (rc == M90_OK)
				atomic_fetch_add_explicit(&ctx->sign_ops, 1,
							  memory_order_relaxed);
		}
	}
	return NULL;
}

static void *rotation_worker(void *arg)
{
	struct m92_context *ctx = arg;
	unsigned int i;

	pthread_barrier_wait(&ctx->barrier);
	for (i = 1; i < 4; i++) {
		if (m90_provider_rotate(&ctx->provider, ctx->keys[i], ctx->ids[i],
					&ctx->generations[i]) != M90_OK)
			record_failure(ctx);
		else
			atomic_fetch_add_explicit(&ctx->rotate_ops, 1,
						  memory_order_relaxed);
		usleep(1000);
	}
	return NULL;
}

static void *revoke_worker(void *arg)
{
	struct m92_context *ctx = arg;
	unsigned int i;
	int rc;

	pthread_barrier_wait(&ctx->barrier);
	for (i = 0; i < M92_REVOKE_ITERATIONS; i++) {
		rc = m90_provider_revoke(&ctx->provider,
					 ctx->ids[i % 3]);
		if (rc != M90_OK && rc != M90_ERR_NOT_FOUND)
			record_failure(ctx);
		else
			atomic_fetch_add_explicit(&ctx->revoke_ops, 1,
						  memory_order_relaxed);
	}
	return NULL;
}

static void *bind_worker(void *arg)
{
	struct m92_context *ctx = arg;
	unsigned int i;
	int rc;

	pthread_barrier_wait(&ctx->barrier);
	for (i = 0; i < M92_BIND_ITERATIONS; i++) {
		rc = m90_provider_bind_service(&ctx->provider, &ctx->service);
		if (rc == M90_OK)
			rc = m90_provider_unbind_service(&ctx->provider,
						  &ctx->service);
		if (rc != M90_OK && rc != M90_ERR_REVOKED)
			record_failure(ctx);
	}
	return NULL;
}

static int malformed_cases(struct m92_context *ctx)
{
	uint8_t id[M90_KEY_ID_SIZE];
	uint8_t signature[M87_SIGNATURE_SIZE];
	uint64_t generation = 0;
	unsigned int i;

	memset(id, 0xa5, sizeof(id));
	if (m90_provider_key_id(NULL, id) != M90_ERR_KEY ||
	    m90_provider_provision(&ctx->provider, NULL, id, &generation) !=
		M90_ERR_ARGUMENT ||
	    m90_provider_rotate(&ctx->provider, NULL, id, &generation) !=
		M90_ERR_ARGUMENT ||
	    m90_provider_revoke(&ctx->provider, NULL) != M90_ERR_ARGUMENT ||
	    m90_provider_sign_active(&ctx->provider, NULL, 1, signature) !=
		M90_ERR_ARGUMENT ||
	    m90_provider_sign_active(&ctx->provider, "x", 1, NULL) !=
		M90_ERR_ARGUMENT)
		return -1;
	for (i = 0; i < 256; i++) {
		memset(id, (int)(i ^ 0x5a), sizeof(id));
		if (m90_provider_revoke(&ctx->provider, id) != M90_ERR_NOT_FOUND)
			return -1;
	}
	printf("M92_MALFORMED_INPUTS_OK cases=261\n");
	return 0;
}

int main(void)
{
	struct m92_context ctx;
	pthread_t threads[M92_TOTAL_WORKERS];
	unsigned int i;

	memset(&ctx, 0, sizeof(ctx));
	atomic_init(&ctx.failures, 0);
	atomic_init(&ctx.sign_ops, 0);
	atomic_init(&ctx.rotate_ops, 0);
	atomic_init(&ctx.revoke_ops, 0);
	if (m90_provider_init(&ctx.provider) != M90_OK)
		return fail("provider init", M90_ERR_STATE);
	for (i = 0; i < 4; i++) {
		if (make_key(&ctx.keys[i]) != 0)
			return fail("key generation", M90_ERR_KEY);
	}
	if (m90_provider_provision(&ctx.provider, ctx.keys[0], ctx.ids[0],
				   &ctx.generations[0]) != M90_OK)
		return fail("initial provision", M90_ERR_KEY);
	if (malformed_cases(&ctx) != 0)
		return fail("malformed cases", M90_ERR_ARGUMENT);
	if (pthread_barrier_init(&ctx.barrier, NULL, M92_TOTAL_WORKERS + 1) != 0)
		return fail("barrier init", M90_ERR_STATE);
	for (i = 0; i < M92_SIGN_WORKERS; i++)
		if (pthread_create(&threads[i], NULL, sign_worker, &ctx) != 0)
			return fail("sign worker", M90_ERR_STATE);
	if (pthread_create(&threads[4], NULL, rotation_worker, &ctx) != 0 ||
	    pthread_create(&threads[5], NULL, revoke_worker, &ctx) != 0 ||
	    pthread_create(&threads[6], NULL, bind_worker, &ctx) != 0)
		return fail("control worker", M90_ERR_STATE);
	{
		int barrier_rc = pthread_barrier_wait(&ctx.barrier);

		if (barrier_rc != 0 && barrier_rc != PTHREAD_BARRIER_SERIAL_THREAD)
			return fail("barrier release", barrier_rc);
	}
	for (i = 0; i < M92_TOTAL_WORKERS; i++)
		pthread_join(threads[i], NULL);
	if (atomic_load_explicit(&ctx.failures, memory_order_relaxed) != 0 ||
	    atomic_load_explicit(&ctx.rotate_ops, memory_order_relaxed) != 3 ||
	    atomic_load_explicit(&ctx.sign_ops, memory_order_relaxed) == 0)
		return fail("concurrent stress", -1);
	printf("M92_CONCURRENT_STRESS_OK sign_ops=%u rotate_ops=%u revoke_ops=%u\n",
	       atomic_load_explicit(&ctx.sign_ops, memory_order_relaxed),
	       atomic_load_explicit(&ctx.rotate_ops, memory_order_relaxed),
	       atomic_load_explicit(&ctx.revoke_ops, memory_order_relaxed));
	if (m90_provider_bind_service(&ctx.provider, &ctx.service) != M90_OK)
		return fail("lifetime bind", M90_ERR_STATE);
	m90_provider_close(&ctx.provider);
	if (ctx.service.trusted_public_key_size != 0 ||
	    ctx.service.trusted_key_generation != 0 ||
	    !ctx.service.trusted_key_required)
		return fail("lifetime invalidation", M90_ERR_STATE);
	printf("M92_SERVICE_LIFETIME_OK\n");
	for (i = 0; i < 4; i++)
		EVP_PKEY_free(ctx.keys[i]);
	pthread_barrier_destroy(&ctx.barrier);
	printf("M92_SELFTEST_EXIT=0\n");
	return 0;
}
