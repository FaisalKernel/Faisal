#!/usr/bin/env python3
import copy
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from faisal_model_routing import Endpoint, OutcomeLedger, RoutePlanCache, RouteRequest, RoutingContractError, plan_route, verify_route


def endpoint(endpoint_id, model_id, *, health="healthy", generation=3, cost=10, latency=20, region="us-east", privacy="internal", capability="text", active=0, max_concurrency=4, cache=False, provider="local"):
    capabilities = frozenset({capability}) if capability != "text" else frozenset({"text"})
    return Endpoint(endpoint_id=endpoint_id, model_id=model_id, model_digest="sha256:" + endpoint_id, provider_class=provider, capabilities=capabilities, privacy_class=privacy, region=region, max_context_tokens=8192, estimated_cost_milli=cost, estimated_latency_ms=latency, health=health, health_generation=generation, active_requests=active, max_concurrency=max_concurrency, cache_hit=cache)


class ModelRoutingTests(unittest.TestCase):
    def request(self, **kwargs):
        values = dict(request_id="req-1", required_capability="text", privacy_class="confidential", context_tokens=1024, max_cost_milli=100, max_latency_ms=500, region="us-east", generation=3, max_fallbacks=2)
        values.update(kwargs)
        return RouteRequest(**values)

    def test_deterministic_preference_cache_and_fallback_order(self):
        endpoints = [
            endpoint("b", "small", cost=5, latency=30),
            endpoint("a", "preferred", cost=20, latency=50, cache=True),
            endpoint("c", "fallback", cost=15, latency=25),
        ]
        route = plan_route(endpoints, self.request(preferred_models=("preferred",)), trusted_provider_classes={"local"}, observed_at=10)
        self.assertEqual(route["primary"]["endpoint_id"], "a")
        self.assertEqual([x["endpoint_id"] for x in route["fallbacks"]], ["c", "b"])
        self.assertEqual(verify_route(route, expected_request_id="req-1", expected_generation=3)["verified"], True)

    def test_fail_closed_filters(self):
        endpoints = [
            endpoint("bad-cap", "vision", capability="vision"),
            endpoint("bad-privacy", "restricted", privacy="restricted"),
            endpoint("bad-health", "unknown", health="unknown"),
            endpoint("bad-region", "west", region="us-west"),
            endpoint("bad-generation", "stale", generation=2),
            endpoint("bad-full", "full", active=4),
            endpoint("bad-provider", "other", provider="untrusted"),
        ]
        with self.assertRaises(RoutingContractError):
            plan_route(endpoints, self.request(max_cost_milli=1), trusted_provider_classes={"local"}, observed_at=10)
        route = plan_route(endpoints + [endpoint("good", "good")], self.request(), trusted_provider_classes={"local"}, observed_at=10)
        self.assertEqual(route["primary"]["endpoint_id"], "good")
        self.assertIn("provider_class_not_allowed", route["rejections"].values())
        self.assertIn("health_below_minimum", route["rejections"].values())

    def test_cross_region_and_privacy_policy(self):
        with self.assertRaises(RoutingContractError):
            plan_route([endpoint("west", "west", region="us-west")], self.request(), trusted_provider_classes={"local"})
        route = plan_route([endpoint("west", "west", region="us-west")], self.request(allow_cross_region=True), trusted_provider_classes={"local"})
        self.assertEqual(route["primary"]["endpoint_id"], "west")

    def test_generation_and_digest_fencing(self):
        route = plan_route([endpoint("a", "model")], self.request(), trusted_provider_classes={"local"}, observed_at=10)
        with self.assertRaises(RoutingContractError):
            verify_route(route, expected_request_id="req-1", expected_generation=4)
        tampered = copy.deepcopy(route)
        tampered["primary"]["model_id"] = "changed"
        with self.assertRaises(RoutingContractError):
            verify_route(tampered, expected_request_id="req-1", expected_generation=3)

    def test_route_plan_cache_hit_and_health_generation_invalidation(self):
        cache = RoutePlanCache(max_entries=2)
        snapshot = [endpoint("a", "model")]
        request = self.request()
        first = cache.plan(snapshot, request, trusted_provider_classes={"local"}, observed_at=10)
        second = cache.plan(snapshot, request, trusted_provider_classes={"local"}, observed_at=20)
        self.assertEqual(first["route_digest"], second["route_digest"])
        self.assertEqual(second["observed_at"], 10)
        self.assertEqual(len(cache), 1)
        changed = cache.plan([endpoint("a", "model", generation=4)], request, trusted_provider_classes={"local"}, observed_at=20)
        self.assertNotEqual(first["observed_at"], changed["observed_at"])
        self.assertEqual(len(cache), 2)

    def test_outcome_feedback_adapts_route_and_invalidates_cache(self):
        ledger = OutcomeLedger(max_keys=4, max_samples=16, cooldown_seconds=30)
        endpoints = [endpoint("a", "a", latency=10), endpoint("b", "b", latency=20)]
        request = self.request()
        cache = RoutePlanCache(max_entries=4)
        first = cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=100, outcome_ledger=ledger)
        self.assertEqual(first["primary"]["endpoint_id"], "a")
        for _ in range(3):
            ledger.record(endpoint_id="a", request_class=ledger.route_class(request), success=False, latency_ms=100, observed_at=100, current_generation=3, sample_generation=3)
        second = cache.plan(endpoints, request, trusted_provider_classes={"local"}, observed_at=100, outcome_ledger=ledger)
        self.assertEqual(second["primary"]["endpoint_id"], "b")
        self.assertIn("outcome_cooldown", second["rejections"].values())
        self.assertEqual(ledger.stats(endpoint_id="a", request_class=ledger.route_class(request))["failure_streak"], 3)
        with self.assertRaises(RoutingContractError):
            ledger.record(endpoint_id="a", request_class="text:confidential", success=True, latency_ms=1, observed_at=100, current_generation=4, sample_generation=3)

    def test_bound_outcome_receipt_requires_route_identity_and_rejects_replay(self):
        ledger = OutcomeLedger(max_keys=4, max_samples=16, cooldown_seconds=30)
        request = self.request(request_id="bound-1", generation=3)
        route = plan_route([endpoint("a", "a"), endpoint("b", "b", latency=30)], request, trusted_provider_classes={"local"}, observed_at=100, outcome_ledger=ledger)
        receipt = ledger.record_bound_outcome(route=route, request=request, endpoint_id=route["primary"]["endpoint_id"], success=False, latency_ms=44, observed_at=101, current_generation=3, sample_generation=3, evidence_digest="sha256:" + "e" * 64)
        self.assertTrue(receipt["verified"])
        self.assertFalse(receipt["outcomes_are_authority"])
        self.assertEqual(receipt["route_digest"], route["route_digest"])
        with self.assertRaises(RoutingContractError):
            ledger.record_bound_outcome(route=route, request=request, endpoint_id=route["primary"]["endpoint_id"], success=False, latency_ms=44, observed_at=101, current_generation=3, sample_generation=3, evidence_digest="sha256:" + "e" * 64)

    def test_bound_outcome_rejects_stale_future_or_nonroute_inputs(self):
        ledger = OutcomeLedger(max_keys=4, max_samples=16, cooldown_seconds=30)
        request = self.request(request_id="bound-2", generation=3)
        route = plan_route([endpoint("a", "a"), endpoint("b", "b")], request, trusted_provider_classes={"local"}, observed_at=100, outcome_ledger=ledger)
        cases = [
            dict(observed_at=99, current_generation=3, sample_generation=3, endpoint_id="a"),
            dict(observed_at=401, current_generation=3, sample_generation=3, endpoint_id="a"),
            dict(observed_at=101, current_generation=4, sample_generation=4, endpoint_id="a"),
            dict(observed_at=101, current_generation=3, sample_generation=3, endpoint_id="outside"),
        ]
        for case in cases:
            with self.assertRaises(RoutingContractError):
                ledger.record_bound_outcome(route=route, request=request, success=True, latency_ms=1, evidence_digest="sha256:" + "f" * 64, max_age_seconds=300, **case)

    def test_duplicate_endpoint_and_empty_policy_rejected(self):
        with self.assertRaises(RoutingContractError):
            plan_route([endpoint("a", "one"), endpoint("a", "two")], self.request(), trusted_provider_classes={"local"})
        with self.assertRaises(RoutingContractError):
            plan_route([endpoint("a", "one")], self.request(), trusted_provider_classes=set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
