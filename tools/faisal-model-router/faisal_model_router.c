#include "faisal_model_router.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static struct fmr_model *find_model(struct fmr_router *router, uint64_t model_id)
{
	size_t i;

	if (!router)
		return NULL;
	for (i = 0; i < router->count; i++) {
		if (router->models[i].model_id == model_id)
			return &router->models[i];
	}
	return NULL;
}

static const struct fmr_model *find_model_const(const struct fmr_router *router,
						uint64_t model_id)
{
	size_t i;

	if (!router)
		return NULL;
	for (i = 0; i < router->count; i++) {
		if (router->models[i].model_id == model_id)
			return &router->models[i];
	}
	return NULL;
}

static int copy_text(char *dst, size_t dst_size, const char *src)
{
	size_t length;

	if (!dst || !dst_size || !src || !src[0])
		return FMR_ERR_ARGUMENT;
	length = strlen(src);
	if (length >= dst_size)
		return FMR_ERR_ARGUMENT;
	memcpy(dst, src, length + 1);
	return FMR_OK;
}

static void hash_u32(EVP_MD_CTX *ctx, uint32_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_u64(EVP_MD_CTX *ctx, uint64_t value)
{
	(void)EVP_DigestUpdate(ctx, &value, sizeof(value));
}

static void hash_text(EVP_MD_CTX *ctx, const char *text)
{
	uint32_t length = (uint32_t)strlen(text);

	hash_u32(ctx, length);
	(void)EVP_DigestUpdate(ctx, text, length);
}

static int route_digest(const struct fmr_model *model,
			const struct fmr_request *request,
			const struct fmr_route *route,
			uint8_t digest[FMR_DIGEST_SIZE])
{
	EVP_MD_CTX *ctx;
	unsigned int digest_length = 0;

	if (!model || !request || !route || !digest || request->request_sequence == 0)
		return FMR_ERR_ARGUMENT;
	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return FMR_ERR_CORRUPT;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(ctx);
		return FMR_ERR_CORRUPT;
	}
	hash_u64(ctx, request->request_sequence);
	hash_u64(ctx, request->now_ns);
	hash_u32(ctx, request->difficulty);
	hash_u32(ctx, request->required_modalities);
	hash_u32(ctx, request->required_capabilities);
	hash_u32(ctx, request->privacy_level);
	hash_u32(ctx, request->retry_budget);
	hash_u64(ctx, request->max_latency_ns);
	hash_u64(ctx, request->max_cost_micro);
	hash_u32(ctx, request->min_accuracy_ppm);
	hash_u64(ctx, request->context_tokens);
	hash_u64(ctx, request->hardware_mask);
	hash_u64(ctx, request->locality_mask);
	hash_u32(ctx, request->require_local);
	hash_u32(ctx, request->allow_cloud);
	hash_u64(ctx, model->model_id);
	hash_u64(ctx, model->generation);
	hash_text(ctx, model->provider);
	hash_text(ctx, model->name);
	hash_u64(ctx, route->model_id);
	hash_u64(ctx, route->model_generation);
	hash_u32(ctx, route->state);
	hash_u32(ctx, route->attempt);
	hash_u32(ctx, route->score);
	hash_u32(ctx, route->fallback_count);
	hash_u64(ctx, route->estimated_latency_ns);
	hash_u64(ctx, route->estimated_cost_micro);
	if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
	    digest_length != FMR_DIGEST_SIZE) {
		EVP_MD_CTX_free(ctx);
		return FMR_ERR_CORRUPT;
	}
	EVP_MD_CTX_free(ctx);
	return FMR_OK;
}

static uint32_t uncertainty_for(uint64_t successes, uint64_t failures)
{
	uint64_t samples = successes + failures;
	uint64_t uncertainty;

	if (!samples)
		return FMR_SCORE_MAX;
	uncertainty = FMR_SCORE_MAX / (samples + 1);
	return uncertainty > FMR_SCORE_MAX ? FMR_SCORE_MAX : (uint32_t)uncertainty;
}

static uint32_t confidence_for(const struct fmr_model *model)
{
	uint64_t base;
	uint64_t certainty;

	base = ((uint64_t)model->health_ppm + model->accuracy_ppm) / 2;
	certainty = FMR_SCORE_MAX - model->uncertainty_ppm;
	return (uint32_t)((base * certainty) / FMR_SCORE_MAX);
}

static int circuit_available(const struct fmr_model *model, uint64_t now_ns,
				int *half_open)
{
	if (!model || !half_open)
		return 0;
	*half_open = 0;
	if (model->circuit_state == FMR_CIRCUIT_CLOSED)
		return 1;
	if (model->circuit_state == FMR_CIRCUIT_OPEN &&
	    now_ns >= model->cooldown_until_ns) {
		*half_open = 1;
		return 1;
	}
	return 0;
}

static int allowed(const struct fmr_model *model,
		   const struct fmr_request *request, int *half_open)
{
	if (!model || !request || !half_open)
		return 0;
	if ((model->modalities & request->required_modalities) !=
	    request->required_modalities)
		return 0;
	if ((model->capability_mask & request->required_capabilities) !=
	    request->required_capabilities)
		return 0;
	if (model->context_tokens < request->context_tokens)
		return 0;
	if (request->require_local && !(model->provider_kind & FMR_LOCAL))
		return 0;
	if (!request->allow_cloud && (model->provider_kind & FMR_CLOUD))
		return 0;
	if (model->privacy_level < request->privacy_level)
		return 0;
	if (request->hardware_mask &&
	    !(model->hardware_mask & request->hardware_mask))
		return 0;
	if (request->locality_mask &&
	    !(model->locality_mask & request->locality_mask))
		return 0;
	if (request->max_latency_ns && model->latency_ns > request->max_latency_ns)
		return 0;
	if (request->max_cost_micro && model->cost_micro > request->max_cost_micro)
		return 0;
	if (request->min_accuracy_ppm &&
	    model->accuracy_ppm < request->min_accuracy_ppm)
		return 0;
	if (model->health_ppm < 100000)
		return 0;
	return circuit_available(model, request->now_ns, half_open);
}

static uint64_t route_score(const struct fmr_model *model,
			    const struct fmr_request *request, int half_open)
{
	uint64_t score;
	uint64_t latency_bonus = 0;
	uint64_t cost_bonus = 0;
	uint64_t capability_bonus = 0;

	score = (uint64_t)model->accuracy_ppm * 3ULL +
		(uint64_t)model->health_ppm * 2ULL +
		(uint64_t)model->confidence_ppm * 2ULL;
	if (request->max_latency_ns)
		latency_bonus = ((request->max_latency_ns - model->latency_ns) *
				  500000ULL) / request->max_latency_ns;
	else if (model->latency_ns < 1000000000ULL)
		latency_bonus = 1000000000ULL / (model->latency_ns + 1);
	if (request->max_cost_micro)
		cost_bonus = ((request->max_cost_micro - model->cost_micro) *
			      500000ULL) / request->max_cost_micro;
	else
		cost_bonus = 1000000000ULL / (model->cost_micro + 1);
	if (request->required_capabilities)
		capability_bonus = 250000ULL;
	if (half_open)
		/* Recovery probes are deliberately less attractive than closed peers. */
		score /= 2;
	return score + latency_bonus + cost_bonus + capability_bonus;
}

int fmr_init(struct fmr_router *router)
{
	if (!router)
		return FMR_ERR_ARGUMENT;
	memset(router, 0, sizeof(*router));
	router->next_model_id = 1;
	router->next_generation = 1;
	router->failure_threshold = FMR_DEFAULT_FAILURE_THRESHOLD;
	router->cooldown_ns = FMR_DEFAULT_COOLDOWN_NS;
	return FMR_OK;
}

int fmr_register(struct fmr_router *router, const char *provider,
		const char *name, uint32_t provider_kind, uint32_t modalities,
		uint32_t health_ppm, uint64_t latency_ns, uint64_t cost_micro,
		uint64_t context_tokens, uint64_t hardware_mask,
		uint32_t privacy_level, uint32_t locality_mask,
		struct fmr_model *out)
{
	struct fmr_model *model;

	if (!router || !provider || !name || !out || !provider[0] || !name[0])
		return FMR_ERR_ARGUMENT;
	if (router->count >= FMR_MAX_MODELS || health_ppm > FMR_SCORE_MAX)
		return FMR_ERR_FULL;
	model = &router->models[router->count++];
	memset(model, 0, sizeof(*model));
	model->model_id = router->next_model_id++;
	model->generation = router->next_generation++;
	model->provider_kind = provider_kind;
	model->modalities = modalities;
	model->health_ppm = health_ppm;
	model->accuracy_ppm = health_ppm;
	model->confidence_ppm = health_ppm / 2;
	model->uncertainty_ppm = FMR_SCORE_MAX;
	model->circuit_state = FMR_CIRCUIT_CLOSED;
	model->failure_threshold = router->failure_threshold;
	model->latency_ns = latency_ns;
	model->cost_micro = cost_micro;
	model->context_tokens = context_tokens;
	model->hardware_mask = hardware_mask;
	model->privacy_level = privacy_level;
	model->locality_mask = locality_mask;
	if (copy_text(model->provider, sizeof(model->provider), provider) != FMR_OK ||
	    copy_text(model->name, sizeof(model->name), name) != FMR_OK)
		return FMR_ERR_ARGUMENT;
	*out = *model;
	return FMR_OK;
}

int fmr_set_capabilities(struct fmr_router *router, uint64_t model_id,
			 uint32_t capability_mask, uint32_t confidence_ppm)
{
	struct fmr_model *model;

	if (!router || confidence_ppm > FMR_SCORE_MAX)
		return FMR_ERR_ARGUMENT;
	model = find_model(router, model_id);
	if (!model)
		return FMR_ERR_NOT_FOUND;
	model->capability_mask = capability_mask;
	model->confidence_ppm = confidence_ppm;
	return FMR_OK;
}

int fmr_set_generation(struct fmr_router *router, uint64_t model_id,
			uint64_t generation)
{
	struct fmr_model *model;

	if (!router || !generation)
		return FMR_ERR_ARGUMENT;
	model = find_model(router, model_id);
	if (!model)
		return FMR_ERR_NOT_FOUND;
	model->generation = generation;
	return FMR_OK;
}

int fmr_record_result_at(struct fmr_router *router, uint64_t model_id,
			int success, uint64_t latency_ns, uint32_t accuracy_ppm,
			uint64_t now_ns, const char *error_text)
{
	struct fmr_model *model;
	uint64_t samples;

	if (!router || (success != 0 && success != 1) ||
	    accuracy_ppm > FMR_SCORE_MAX)
		return FMR_ERR_ARGUMENT;
	model = find_model(router, model_id);
	if (!model)
		return FMR_ERR_NOT_FOUND;
	if (success) {
		model->successes++;
		model->failure_streak = 0;
		model->circuit_state = FMR_CIRCUIT_CLOSED;
		model->cooldown_until_ns = 0;
		model->last_error[0] = '\0';
	} else {
		model->failures++;
		model->failure_streak++;
		if (error_text && error_text[0])
			(void)snprintf(model->last_error, sizeof(model->last_error),
				       "%s", error_text);
		if (model->failure_streak >= model->failure_threshold) {
			model->circuit_state = FMR_CIRCUIT_OPEN;
			if (UINT64_MAX - now_ns < router->cooldown_ns)
				model->cooldown_until_ns = UINT64_MAX;
			else
				model->cooldown_until_ns = now_ns + router->cooldown_ns;
		}
	}
	model->total_latency_ns += latency_ns;
	model->last_result_ns = now_ns;
	samples = model->successes + model->failures;
	model->health_ppm = (uint32_t)((model->successes * FMR_SCORE_MAX) /
					(samples ? samples : 1));
	if (accuracy_ppm)
		model->accuracy_ppm = accuracy_ppm;
	model->uncertainty_ppm = uncertainty_for(model->successes,
						 model->failures);
	model->confidence_ppm = confidence_for(model);
	return FMR_OK;
}

int fmr_record_result(struct fmr_router *router, uint64_t model_id,
			 int success, uint64_t latency_ns, uint32_t accuracy_ppm)
{
	return fmr_record_result_at(router, model_id, success, latency_ns,
					accuracy_ppm, 0, NULL);
}

int fmr_route(const struct fmr_router *router,
	      const struct fmr_request *request, struct fmr_route *out)
{
	const struct fmr_model *best = NULL;
	uint64_t best_score = 0;
	int best_half_open = 0;
	size_t i;

	if (!router || !request || !out || request->request_sequence == 0)
		return FMR_ERR_ARGUMENT;
	for (i = 0; i < router->count; i++) {
		const struct fmr_model *model = &router->models[i];
		uint64_t score;
		int half_open;

		if (!allowed(model, request, &half_open))
			continue;
		score = route_score(model, request, half_open);
		if (!best || score > best_score ||
		    (score == best_score && model->model_id < best->model_id)) {
			best = model;
			best_score = score;
			best_half_open = half_open;
		}
	}
	if (!best)
		return FMR_ERR_NO_ROUTE;
	memset(out, 0, sizeof(*out));
	out->request_sequence = request->request_sequence;
	out->model_id = best->model_id;
	out->model_generation = best->generation;
	out->attempt = 1;
	out->score = best_score > UINT32_MAX ? UINT32_MAX : (uint32_t)best_score;
	out->estimated_latency_ns = best->latency_ns;
	out->estimated_cost_micro = best->cost_micro;
	out->state = FMR_ROUTE_SELECTED;
	if (request->difficulty >= 800)
		out->state = FMR_ROUTE_ESCALATED;
	else if (request->difficulty <= 200 && best->cost_micro < 1000)
		out->state = FMR_ROUTE_DEESCALATED;
	if (best_half_open) {
		out->state = FMR_ROUTE_FALLBACK;
		out->fallback_count = 1;
	}
	if (snprintf(out->reason, sizeof(out->reason),
		     "selected provider=%s model=%s health_ppm=%u accuracy_ppm=%u confidence_ppm=%u circuit=%s",
		     best->provider, best->name, best->health_ppm,
		     best->accuracy_ppm, best->confidence_ppm,
		     best_half_open ? "half-open" : "closed") < 0)
		return FMR_ERR_CORRUPT;
	return route_digest(best, request, out, out->receipt_digest);
}

int fmr_verify_route(const struct fmr_router *router,
		     const struct fmr_request *request,
		     const struct fmr_route *route)
{
	const struct fmr_model *model;
	uint8_t expected[FMR_DIGEST_SIZE];

	if (!router || !request || !route || request->request_sequence == 0 ||
	    route->request_sequence != request->request_sequence)
		return FMR_ERR_ARGUMENT;
	model = find_model_const(router, route->model_id);
	if (!model)
		return FMR_ERR_NOT_FOUND;
	if (model->generation != route->model_generation)
		return FMR_ERR_STALE;
	if (route_digest(model, request, route, expected) != FMR_OK)
		return FMR_ERR_CORRUPT;
	if (memcmp(expected, route->receipt_digest, FMR_DIGEST_SIZE) != 0)
		return FMR_ERR_CORRUPT;
	return FMR_OK;
}

int fmr_get(const struct fmr_router *router, uint64_t model_id,
	   struct fmr_model *out)
{
	const struct fmr_model *model;

	if (!router || !out)
		return FMR_ERR_ARGUMENT;
	model = find_model_const(router, model_id);
	if (!model)
		return FMR_ERR_NOT_FOUND;
	*out = *model;
	return FMR_OK;
}
