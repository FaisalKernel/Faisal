#define _GNU_SOURCE
#include "../../faisal-model-router/faisal_model_router.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void)
{
	const uint64_t rounds = 100000;
	struct fmr_router router;
	struct fmr_model model;
	struct fmr_request request;
	struct fmr_route route;
	uint64_t start;
	uint64_t elapsed;
	uint64_t i;
	uint64_t operations = 0;

	if (fmr_init(&router) != FMR_OK)
		return 1;
	if (fmr_register(&router, "local-runtime", "router-benchmark-model",
			 FMR_LOCAL | FMR_OPEN | FMR_REASONING,
			 FMR_CODING | FMR_REASONING, 950000, 1000000, 100,
			 65536, 1, 900000, 1, &model) != FMR_OK)
		return 2;
	if (fmr_set_capabilities(&router, model.model_id,
			 FMR_CAP_STRUCTURED_OUTPUT | FMR_CAP_TOOL_CALLING |
			 FMR_CAP_JSON_SCHEMA, 900000) != FMR_OK)
		return 3;
	memset(&request, 0, sizeof(request));
	request.now_ns = 1000;
	request.difficulty = 600;
	request.required_modalities = FMR_CODING | FMR_REASONING;
	request.required_capabilities = FMR_CAP_STRUCTURED_OUTPUT |
					FMR_CAP_TOOL_CALLING | FMR_CAP_JSON_SCHEMA;
	request.privacy_level = 900000;
	request.max_latency_ns = 2000000;
	request.max_cost_micro = 1000;
	request.min_accuracy_ppm = 900000;
	request.context_tokens = 16000;
	request.hardware_mask = 1;
	request.locality_mask = 1;
	request.require_local = 1;
	request.allow_cloud = 0;

	start = now_ns();
	for (i = 1; i <= rounds; i++) {
		request.request_sequence = i;
		request.now_ns++;
		if (fmr_route(&router, &request, &route) != FMR_OK)
			return 4;
		if (fmr_verify_route(&router, &request, &route) != FMR_OK)
			return 5;
		operations += 2;
	}
	elapsed = now_ns() - start;
	printf("M230_BENCHMARK_ROUNDS=%llu\n", (unsigned long long)rounds);
	printf("M230_BENCHMARK_OPERATIONS=%llu\n", (unsigned long long)operations);
	printf("M230_BENCHMARK_TOTAL_NS=%llu\n", (unsigned long long)elapsed);
	printf("M230_BENCHMARK_NS_PER_OPERATION=%llu\n",
	       (unsigned long long)(elapsed / operations));
	printf("M230_BENCHMARK_EXIT=0\n");
	return 0;
}
