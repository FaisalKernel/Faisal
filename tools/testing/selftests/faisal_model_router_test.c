#include "../../faisal-model-router/faisal_model_router.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *name, int rc)
{
	fprintf(stderr, "M230_FAIL:%s rc=%d\n", name, rc);
	return 1;
}

int main(void)
{
	struct fmr_router router;
	struct fmr_model local_model;
	struct fmr_model cloud_model;
	struct fmr_request request;
	struct fmr_route route;
	struct fmr_model observed;
	unsigned int i;

	if (fmr_init(&router) != FMR_OK)
		return fail("init", FMR_ERR_ARGUMENT);
	if (fmr_register(&router, "local-vllm", "open-coder", FMR_LOCAL | FMR_OPEN,
			 FMR_CODING | FMR_REASONING, 950000, 1000000, 100,
			 32768, 1, 900000, 1, &local_model) != FMR_OK)
		return fail("local register", FMR_ERR_ARGUMENT);
	if (fmr_register(&router, "cloud-provider", "premium-reasoner",
			 FMR_CLOUD | FMR_PROPRIETARY | FMR_REASONING,
			 FMR_CODING | FMR_REASONING, 990000, 5000000, 10000,
			 131072, 1, 900000, 1, &cloud_model) != FMR_OK)
		return fail("cloud register", FMR_ERR_ARGUMENT);
	if (fmr_set_capabilities(&router, local_model.model_id,
			 FMR_CAP_STRUCTURED_OUTPUT | FMR_CAP_TOOL_CALLING |
			 FMR_CAP_JSON_SCHEMA | FMR_CAP_STREAMING, 850000) != FMR_OK)
		return fail("local capabilities", FMR_ERR_ARGUMENT);
	if (fmr_set_capabilities(&router, cloud_model.model_id,
			 FMR_CAP_STRUCTURED_OUTPUT | FMR_CAP_TOOL_CALLING |
			 FMR_CAP_JSON_SCHEMA | FMR_CAP_BACKGROUND, 980000) != FMR_OK)
		return fail("cloud capabilities", FMR_ERR_ARGUMENT);

	memset(&request, 0, sizeof(request));
	request.request_sequence = 1;
	request.now_ns = 100;
	request.difficulty = 100;
	request.required_modalities = FMR_CODING | FMR_REASONING;
	request.required_capabilities = FMR_CAP_STRUCTURED_OUTPUT |
					FMR_CAP_TOOL_CALLING | FMR_CAP_JSON_SCHEMA;
	request.privacy_level = 900000;
	request.retry_budget = 2;
	request.max_latency_ns = 2000000;
	request.max_cost_micro = 1000;
	request.min_accuracy_ppm = 900000;
	request.context_tokens = 16000;
	request.hardware_mask = 1;
	request.locality_mask = 1;
	request.require_local = 1;
	request.allow_cloud = 0;
	if (fmr_route(&router, &request, &route) != FMR_OK ||
	    route.model_id != local_model.model_id ||
	    route.state != FMR_ROUTE_DEESCALATED)
		return fail("local capability route", FMR_ERR_NO_ROUTE);
	printf("M230_LOCAL_CAPABILITY_ROUTE_OK model=%llu score=%u\n",
	       (unsigned long long)route.model_id, route.score);
	if (fmr_verify_route(&router, &request, &route) != FMR_OK)
		return fail("route receipt verify", FMR_ERR_CORRUPT);
	printf("M230_ROUTE_RECEIPT_VERIFY_OK\n");

	route.receipt_digest[0] ^= 1;
	if (fmr_verify_route(&router, &request, &route) != FMR_ERR_CORRUPT)
		return fail("route receipt tamper", FMR_ERR_CORRUPT);
	printf("M230_ROUTE_TAMPER_REJECT_OK\n");
	if (fmr_route(&router, &request, &route) != FMR_OK)
		return fail("route after tamper copy", FMR_ERR_NO_ROUTE);

	for (i = 0; i < 10; i++)
		if (fmr_record_result_at(&router, local_model.model_id, 1,
					 1000000, 950000, 100 + i, NULL) != FMR_OK)
			return fail("success history", FMR_ERR_ARGUMENT);
	for (i = 0; i < router.failure_threshold; i++)
		if (fmr_record_result_at(&router, local_model.model_id, 0,
					 1200000, 900000, 200 + i, "timeout") != FMR_OK)
			return fail("failure history", FMR_ERR_ARGUMENT);
	if (fmr_get(&router, local_model.model_id, &observed) != FMR_OK ||
	    observed.circuit_state != FMR_CIRCUIT_OPEN ||
	    observed.failure_streak != router.failure_threshold)
		return fail("circuit open", FMR_ERR_COOLDOWN);
	printf("M230_CIRCUIT_OPEN_OK failures=%u cooldown_until=%llu\n",
	       observed.failure_streak,
	       (unsigned long long)observed.cooldown_until_ns);

	request.request_sequence = 2;
	request.now_ns = 500;
	request.require_local = 0;
	request.allow_cloud = 1;
	request.max_latency_ns = 10000000;
	request.max_cost_micro = 20000;
	if (fmr_route(&router, &request, &route) != FMR_OK ||
	    route.model_id != cloud_model.model_id)
		return fail("cloud fallback route", FMR_ERR_NO_ROUTE);
	printf("M230_CLOUD_FALLBACK_ROUTE_OK model=%llu\n",
	       (unsigned long long)route.model_id);
	if (fmr_verify_route(&router, &request, &route) != FMR_OK)
		return fail("fallback receipt verify", FMR_ERR_CORRUPT);

	request.request_sequence = 3;
	request.now_ns = observed.cooldown_until_ns + 1;
	request.require_local = 1;
	request.allow_cloud = 0;
	request.max_latency_ns = 2000000;
	request.max_cost_micro = 1000;
	if (fmr_route(&router, &request, &route) != FMR_OK ||
	    route.model_id != local_model.model_id ||
	    route.state != FMR_ROUTE_FALLBACK || route.fallback_count != 1)
		return fail("half-open probe", FMR_ERR_COOLDOWN);
	printf("M230_HALF_OPEN_PROBE_OK\n");

	if (fmr_set_generation(&router, local_model.model_id, 99) != FMR_OK)
		return fail("generation update", FMR_ERR_ARGUMENT);
	if (fmr_verify_route(&router, &request, &route) != FMR_ERR_STALE)
		return fail("generation fence", FMR_ERR_STALE);
	printf("M230_GENERATION_FENCE_OK\n");

	request.request_sequence = 4;
	request.now_ns = 1000;
	request.required_capabilities = FMR_CAP_BACKGROUND;
	request.require_local = 1;
	request.allow_cloud = 0;
	if (fmr_route(&router, &request, &route) != FMR_ERR_NO_ROUTE)
		return fail("no route policy", FMR_ERR_NO_ROUTE);
	printf("M230_NO_ROUTE_POLICY_OK\n");

	if (fmr_record_result_at(&router, local_model.model_id, 1,
				 1000000, 950000, request.now_ns, NULL) != FMR_OK)
		return fail("recovery result", FMR_ERR_ARGUMENT);
	if (fmr_get(&router, local_model.model_id, &observed) != FMR_OK ||
	    observed.circuit_state != FMR_CIRCUIT_CLOSED ||
	    observed.failure_streak != 0)
		return fail("circuit recovery", FMR_ERR_COOLDOWN);
	printf("M230_CIRCUIT_RECOVERY_OK\n");
	printf("M230_SELFTEST_EXIT=0\n");
	return 0;
}
