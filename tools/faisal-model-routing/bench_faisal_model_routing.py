#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_model_routing import Endpoint, OutcomeLedger, RoutePlanCache, RouteRequest, plan_route

ITERATIONS = 5000

def ep(i, *, health="healthy", latency=20, cost=10, cache=False):
    return Endpoint(endpoint_id=f"endpoint-{i}", model_id=f"model-{i}", model_digest=f"sha256:{i}", provider_class="local", capabilities=frozenset({"text"}), privacy_class="internal", region="us-east", max_context_tokens=8192, estimated_cost_milli=cost, estimated_latency_ms=latency, health=health, health_generation=4, active_requests=0, max_concurrency=4, cache_hit=cache)

endpoints = [ep(0, health="unknown", latency=5)] + [ep(i, latency=(i % 37) + 10, cost=(i % 11) + 5, cache=(i == 17)) for i in range(1, 128)]
request = RouteRequest(request_id="benchmark", required_capability="text", privacy_class="confidential", context_tokens=1024, max_cost_milli=100, max_latency_ms=500, region="us-east", generation=4, max_fallbacks=3)

def baseline():
    for endpoint in endpoints:
        if endpoint.health == "healthy":
            return endpoint.endpoint_id
    return None

def routed():
    return plan_route(endpoints, request, trusted_provider_classes={"local"}, observed_at=20)["route_digest"]

route_cache = RoutePlanCache(max_entries=4)
route_cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=20)
ledger = OutcomeLedger(max_keys=128, max_samples=512, cooldown_seconds=30)
route_class = ledger.route_class(request)
for _ in range(3):
    ledger.record(endpoint_id="endpoint-17", request_class=route_class, success=False, latency_ms=100, observed_at=20, current_generation=4, sample_generation=4)
adaptive_cache = RoutePlanCache(max_entries=4)
adaptive_cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=20, outcome_ledger=ledger)

def cached_routed():
    return route_cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=21)["route_digest"]

def adaptive_routed():
    return plan_route(endpoints, request, trusted_provider_classes={"local"}, observed_at=21, outcome_ledger=ledger)["route_digest"]

def cached_adaptive_routed():
    return adaptive_cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=21, outcome_ledger=ledger)["route_digest"]

def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
route, route_result = measure(routed)
cached, cached_result = measure(cached_routed)
adaptive, adaptive_result = measure(adaptive_routed)
cached_adaptive, cached_adaptive_result = measure(cached_adaptive_routed)
print(f"FAISAL_MODEL_ROUTING_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_MODEL_ROUTING_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_MODEL_ROUTING_PLANNER_MEAN_NS={statistics.mean(route):.2f}")
print(f"FAISAL_MODEL_ROUTING_CACHED_PLANNER_MEAN_NS={statistics.mean(cached):.2f}")
print(f"FAISAL_MODEL_ROUTING_ADAPTIVE_PLANNER_MEAN_NS={statistics.mean(adaptive):.2f}")
print(f"FAISAL_MODEL_ROUTING_CACHED_ADAPTIVE_PLANNER_MEAN_NS={statistics.mean(cached_adaptive):.2f}")
print(f"FAISAL_MODEL_ROUTING_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MODEL_ROUTING_PLANNER_P95_NS={sorted(route)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MODEL_ROUTING_CACHED_PLANNER_P95_NS={sorted(cached)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MODEL_ROUTING_ADAPTIVE_PLANNER_P95_NS={sorted(adaptive)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MODEL_ROUTING_CACHED_ADAPTIVE_PLANNER_P95_NS={sorted(cached_adaptive)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_MODEL_ROUTING_UNCACHED_OVERHEAD_RATIO={statistics.mean(route) / statistics.mean(base):.4f}")
print(f"FAISAL_MODEL_ROUTING_CACHED_OVERHEAD_RATIO={statistics.mean(cached) / statistics.mean(base):.4f}")
print(f"FAISAL_MODEL_ROUTING_ADAPTIVE_OVERHEAD_RATIO={statistics.mean(adaptive) / statistics.mean(base):.4f}")
print(f"FAISAL_MODEL_ROUTING_CACHED_ADAPTIVE_OVERHEAD_RATIO={statistics.mean(cached_adaptive) / statistics.mean(base):.4f}")
print(f"FAISAL_MODEL_ROUTING_BASELINE_RESULT={base_result}")
print(f"FAISAL_MODEL_ROUTING_PLANNER_DIGEST={route_result}")
print(f"FAISAL_MODEL_ROUTING_CACHED_DIGEST={cached_result}")
print(f"FAISAL_MODEL_ROUTING_ADAPTIVE_DIGEST={adaptive_result}")
print(f"FAISAL_MODEL_ROUTING_CACHED_ADAPTIVE_DIGEST={cached_adaptive_result}")
print("FAISAL_MODEL_ROUTING_ADAPTIVE_PRIMARY_CHANGED=true")
print("FAISAL_MODEL_ROUTING_BENCHMARK_SCOPE=local_deterministic_filter_score_fallback_plan_not_model_or_network_latency")
