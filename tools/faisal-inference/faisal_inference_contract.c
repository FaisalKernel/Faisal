#include "faisal_inference_contract.h"
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>

static int has_nul(const char *s, size_t n)
{
	return memchr(s, '\0', n) != NULL;
}

static uint32_t choose_kv_tier(const struct fic_objective *o)
{
	static const uint32_t order[] = {
		FIC_KV_GPU, FIC_KV_HOST, FIC_KV_LOCAL_STORAGE, FIC_KV_REMOTE
	};
	size_t i;
	for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
		if (!(o->kv_tier_mask & order[i]))
			continue;
		if (order[i] == FIC_KV_REMOTE &&
		    !(o->route_flags & FIC_ROUTE_ALLOW_REMOTE))
			continue;
		return order[i];
	}
	return 0;
}

static void make_digest(const struct fic_objective *o,
	const struct fmr_route *route, uint32_t kv_tier, uint8_t out[FIC_DIGEST_SIZE])
{
	char canonical[768];
	int n;
	SHA256_CTX ctx;

	n = snprintf(canonical, sizeof(canonical),
		"fic-v%u|obj=%llu|tenant=%llu|model=%llu|phase=%u|kv=%u|"
		"deadline=%llu|ttft=%llu|itl=%llu|cost=%llu|hw=%llu|loc=%llu|"
		"difficulty=%u|privacy=%u|model-digest=",
		o->abi_version,
		(unsigned long long)o->objective_id,
		(unsigned long long)o->tenant_id,
		(unsigned long long)route->model_id,
		o->requested_phases, kv_tier,
		(unsigned long long)o->deadline_ns,
		(unsigned long long)o->max_ttft_ns,
		(unsigned long long)o->max_itl_ns,
		(unsigned long long)o->max_cost_micro,
		(unsigned long long)o->required_hardware_mask,
		(unsigned long long)o->required_locality_mask,
		o->difficulty, o->privacy_level);
	if (n < 0 || (size_t)n >= sizeof(canonical)) {
		memset(out, 0, FIC_DIGEST_SIZE);
		return;
	}
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, canonical, (size_t)n);
	SHA256_Update(&ctx, o->model_digest, sizeof(o->model_digest));
	SHA256_Update(&ctx, o->input_digest, sizeof(o->input_digest));
	SHA256_Update(&ctx, o->tenant, strnlen(o->tenant, sizeof(o->tenant)));
	SHA256_Update(&ctx, o->objective, strnlen(o->objective, sizeof(o->objective)));
	SHA256_Final(out, &ctx);
}

int fic_init(struct fic_service *service, struct fmr_router *router)
{
	if (!service || !router)
		return FIC_ERR_ARGUMENT;
	memset(service, 0, sizeof(*service));
	service->router = router;
	service->next_sequence = 1;
	return FIC_OK;
}

int fic_validate_objective(const struct fic_objective *o)
{
	if (!o || o->abi_version != FIC_ABI_VERSION || !o->objective_id ||
	    !o->tenant_id || !o->requested_phases ||
	    (o->requested_phases & ~FIC_PHASE_BOTH) || !o->kv_tier_mask ||
	    (o->kv_tier_mask & ~(FIC_KV_GPU | FIC_KV_HOST | FIC_KV_LOCAL_STORAGE |
		FIC_KV_REMOTE)) || (o->route_flags & ~(FIC_ROUTE_ALLOW_REMOTE |
		FIC_ROUTE_REQUIRE_KV_LOCALITY | FIC_ROUTE_FAIL_CLOSED)) ||
	    !(o->route_flags & FIC_ROUTE_FAIL_CLOSED) || !o->deadline_ns ||
	    !o->max_ttft_ns || !o->max_itl_ns || !o->max_cost_micro ||
	    !has_nul(o->tenant, sizeof(o->tenant)) ||
	    !has_nul(o->objective, sizeof(o->objective)) || !o->tenant[0] ||
	    !o->objective[0] || o->reserved[0] || o->reserved[1])
		return FIC_ERR_ARGUMENT;
	if ((o->route_flags & FIC_ROUTE_REQUIRE_KV_LOCALITY) &&
	    !choose_kv_tier(o))
		return FIC_ERR_POLICY;
	return FIC_OK;
}

int fic_admit_and_route(struct fic_service *service,
	const struct fic_objective *o, struct fic_route_decision *decision)
{
	struct fmr_request request;
	struct fmr_route route;
	uint32_t kv_tier;
	int rc;

	if (!service || !service->router || !decision)
		return FIC_ERR_ARGUMENT;
	rc = fic_validate_objective(o);
	if (rc != FIC_OK)
		return rc;
	kv_tier = choose_kv_tier(o);
	if (!kv_tier)
		return FIC_ERR_POLICY;
	memset(&request, 0, sizeof(request));
	request.difficulty = o->difficulty;
	request.required_modalities = o->required_modalities;
	request.privacy_level = o->privacy_level;
	request.max_latency_ns = o->max_ttft_ns;
	request.max_cost_micro = o->max_cost_micro;
	request.min_accuracy_ppm = o->min_accuracy_ppm;
	request.context_tokens = 1;
	request.hardware_mask = o->required_hardware_mask;
	request.locality_mask = o->required_locality_mask;
	request.require_local = (o->route_flags & FIC_ROUTE_ALLOW_REMOTE) ? 0 : 1;
	request.allow_cloud = (o->route_flags & FIC_ROUTE_ALLOW_REMOTE) ? 1 : 0;
	rc = fmr_route(service->router, &request, &route);
	if (rc != FMR_OK)
		return FIC_ERR_NO_ROUTE;
	memset(decision, 0, sizeof(*decision));
	decision->objective_id = o->objective_id;
	decision->tenant_id = o->tenant_id;
	decision->model_id = route.model_id;
	decision->route_state = route.state;
	decision->selected_phases = o->requested_phases;
	decision->selected_kv_tier = kv_tier;
	decision->estimated_ttft_ns = route.estimated_latency_ns;
	decision->estimated_cost_micro = route.estimated_cost_micro;
	decision->decision_sequence = service->next_sequence++;
	decision->admission_state = FIC_ADMITTED;
	make_digest(o, &route, kv_tier, decision->provenance_digest);
	snprintf(decision->reason, sizeof(decision->reason),
		"admitted obj=%llu model=%llu phases=0x%x kv=0x%x fail_closed=1; %.160s",
		(unsigned long long)o->objective_id,
		(unsigned long long)route.model_id, o->requested_phases, kv_tier,
		route.reason);
	return FIC_OK;
}

int fic_verify_decision(const struct fic_service *service,
	const struct fic_objective *o, const struct fic_route_decision *decision)
{
	struct fmr_model model;
	struct fmr_route route;
	uint8_t digest[FIC_DIGEST_SIZE];

	if (!service || !service->router || !o || !decision || !decision->model_id)
		return FIC_ERR_ARGUMENT;
	if (decision->objective_id != o->objective_id ||
	    decision->tenant_id != o->tenant_id ||
	    decision->selected_phases != o->requested_phases ||
	    fmr_get(service->router, decision->model_id, &model) != FMR_OK)
		return FIC_ERR_TAMPER;
	memset(&route, 0, sizeof(route));
	route.model_id = model.model_id;
	route.estimated_latency_ns = model.latency_ns;
	route.estimated_cost_micro = model.cost_micro;
	make_digest(o, &route, decision->selected_kv_tier, digest);
	return CRYPTO_memcmp(digest, decision->provenance_digest,
		FIC_DIGEST_SIZE) == 0 ? FIC_OK : FIC_ERR_TAMPER;
}

int fic_record_completion(struct fic_service *service,
	const struct fic_objective *o, struct fic_route_decision *decision,
	const struct fic_completion *completion)
{
	uint32_t violations = 0;
	int rc;

	if (!service || !service->router || !o || !decision || !completion)
		return FIC_ERR_ARGUMENT;
	if (decision->admission_state != FIC_ADMITTED ||
	    decision->objective_id != o->objective_id ||
	    decision->tenant_id != o->tenant_id || !decision->model_id)
		return FIC_ERR_STATE;
	if (fic_verify_decision(service, o, decision) != FIC_OK)
		return FIC_ERR_TAMPER;

	if (completion->ttft_ns > o->max_ttft_ns)
		violations |= FIC_VIOLATION_TTFT;
	if (completion->itl_ns > o->max_itl_ns)
		violations |= FIC_VIOLATION_ITL;
	if (completion->cost_micro > o->max_cost_micro)
		violations |= FIC_VIOLATION_COST;
	if (completion->accelerator_memory_bytes > o->max_accelerator_memory_bytes &&
	    o->max_accelerator_memory_bytes)
		violations |= FIC_VIOLATION_BUDGET;
	if ((completion->completed_phases & o->requested_phases) !=
	    o->requested_phases)
		violations |= FIC_VIOLATION_PHASE;
	if ((o->route_flags & FIC_ROUTE_REQUIRE_KV_LOCALITY) &&
	    !(o->kv_tier_mask & completion->observed_kv_tier))
		violations |= FIC_VIOLATION_KV_LOCALITY;
	if (!completion->authorized_result)
		violations |= FIC_VIOLATION_AUTHORITY;
	decision->violation_mask = violations;
	decision->admission_state = violations ? FIC_VIOLATED : FIC_COMPLETED;
	decision->estimated_ttft_ns = completion->ttft_ns;
	decision->estimated_cost_micro = completion->cost_micro;
	rc = fmr_record_result(service->router, decision->model_id,
		violations == 0, completion->ttft_ns, violations == 0 ? 1000000 : 0);
	if (rc != FMR_OK)
		return FIC_ERR_STATE;
	return violations ? FIC_ERR_SLO : FIC_OK;
}

int fic_test_policy_boundaries(struct fic_service *service)
{
	struct fic_objective o;
	struct fic_route_decision d;
	struct fic_completion c;
	int rc;

	if (!service)
		return FIC_ERR_ARGUMENT;
	memset(&o, 0, sizeof(o));
	o.abi_version = FIC_ABI_VERSION;
	o.requested_phases = FIC_PHASE_BOTH;
	o.kv_tier_mask = FIC_KV_GPU | FIC_KV_HOST;
	o.route_flags = FIC_ROUTE_REQUIRE_KV_LOCALITY | FIC_ROUTE_FAIL_CLOSED;
	o.objective_id = 9001;
	o.tenant_id = 77;
	o.deadline_ns = 1000000000ULL;
	o.max_ttft_ns = 1000000ULL;
	o.max_itl_ns = 1000000ULL;
	o.max_cost_micro = 10000ULL;
	o.max_accelerator_memory_bytes = 1ULL << 30;
	o.difficulty = 500;
	o.privacy_level = 1;
	strcpy(o.tenant, "tenant-77");
	strcpy(o.objective, "dynamo-parity-contract");
	rc = fic_validate_objective(&o);
	if (rc != FIC_OK)
		return rc;
	if (fic_admit_and_route(service, &o, &d) != FIC_OK)
		return FIC_ERR_NO_ROUTE;
	c.ttft_ns = d.estimated_ttft_ns;
	c.itl_ns = 100;
	c.cost_micro = d.estimated_cost_micro;
	c.accelerator_memory_bytes = 1ULL << 20;
	c.completed_phases = FIC_PHASE_BOTH;
	c.observed_kv_tier = d.selected_kv_tier;
	c.authorized_result = 1;
	return fic_record_completion(service, &o, &d, &c);
}
