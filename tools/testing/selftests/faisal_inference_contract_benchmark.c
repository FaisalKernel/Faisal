#define _GNU_SOURCE
#include "../../faisal-inference/faisal_inference_contract.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ITERATIONS 100000U

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void seed_objective(struct fic_objective *o)
{
	memset(o, 0, sizeof(*o));
	o->abi_version = FIC_ABI_VERSION;
	o->requested_phases = FIC_PHASE_BOTH;
	o->kv_tier_mask = FIC_KV_GPU | FIC_KV_HOST;
	o->route_flags = FIC_ROUTE_REQUIRE_KV_LOCALITY | FIC_ROUTE_FAIL_CLOSED;
	o->objective_id = 900000;
	o->tenant_id = 77;
	o->deadline_ns = 5000000000ULL;
	o->max_ttft_ns = 5000000ULL;
	o->max_itl_ns = 5000000ULL;
	o->max_cost_micro = 1000ULL;
	o->max_accelerator_memory_bytes = 1ULL << 30;
	o->required_hardware_mask = 1;
	o->required_locality_mask = 1;
	o->difficulty = 500;
	o->privacy_level = 1;
	strcpy(o->tenant, "benchmark-tenant");
	strcpy(o->objective, "contract-overhead");
	o->model_digest[0] = 0x23;
	o->input_digest[0] = 0x42;
}

int main(void)
{
	struct fmr_router router;
	struct fmr_model model;
	struct fic_service service;
	struct fic_objective o;
	struct fic_route_decision d;
	struct fic_completion c;
	struct fmr_request request;
	struct fmr_route route;
	uint64_t start, end, plain_ns, contract_ns;
	unsigned int i;
	unsigned int completed = 0;

	if (fmr_init(&router) != FMR_OK ||
	    fmr_register(&router, "local-provider", "benchmark-local", FMR_LOCAL,
		FMR_REASONING, 990000, 100, 10, 8192, 1, 1, 1, &model) != FMR_OK ||
	    fic_init(&service, &router) != FIC_OK)
		return 1;
	seed_objective(&o);
	memset(&request, 0, sizeof(request));
	request.difficulty = o.difficulty;
	request.required_modalities = o.required_modalities;
	request.privacy_level = o.privacy_level;
	request.max_latency_ns = o.max_ttft_ns;
	request.max_cost_micro = o.max_cost_micro;
	request.context_tokens = 1;
	request.hardware_mask = o.required_hardware_mask;
	request.locality_mask = o.required_locality_mask;
	request.require_local = 1;
	request.allow_cloud = 0;

	start = now_ns();
	for (i = 0; i < ITERATIONS; i++) {
		if (fmr_route(&router, &request, &route) != FMR_OK)
			return 2;
		completed += route.model_id != 0;
	}
	end = now_ns();
	plain_ns = end - start;

	start = now_ns();
	for (i = 0; i < ITERATIONS; i++) {
		o.objective_id++;
		if (fic_admit_and_route(&service, &o, &d) != FIC_OK)
			return 3;
		memset(&c, 0, sizeof(c));
		c.ttft_ns = d.estimated_ttft_ns;
		c.itl_ns = 100;
		c.cost_micro = d.estimated_cost_micro;
		c.accelerator_memory_bytes = 1ULL << 20;
		c.completed_phases = FIC_PHASE_BOTH;
		c.observed_kv_tier = d.selected_kv_tier;
		c.authorized_result = 1;
		if (fic_record_completion(&service, &o, &d, &c) != FIC_OK)
			return 4;
	}
	end = now_ns();
	contract_ns = end - start;

	printf("FIC_BENCH iterations=%u plain_route_total_ns=%llu contract_admit_complete_total_ns=%llu\n",
		ITERATIONS, (unsigned long long)plain_ns,
		(unsigned long long)contract_ns);
	printf("FIC_BENCH plain_route_ns_per_op=%llu contract_ns_per_op=%llu overhead_x100=%llu completed=%u\n",
		(unsigned long long)(plain_ns / ITERATIONS),
		(unsigned long long)(contract_ns / ITERATIONS),
		plain_ns ? (unsigned long long)((contract_ns * 100ULL) / plain_ns) : 0,
		completed);
	printf("FIC_BENCH_SCOPE=local transparent fixture; not Dynamo, GPU, NIXL, KV-cache, or cluster qualification\n");
	return 0;
}
