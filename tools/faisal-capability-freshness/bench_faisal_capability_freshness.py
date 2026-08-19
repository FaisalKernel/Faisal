from __future__ import annotations

import statistics
import time

from faisal_capability_freshness import CapabilityFreshnessLedger, CapabilityManifest, FreshnessPolicy, FreshnessRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_metadata_is_authority": False,
    "manifest_claim_is_attestation": False,
    "freshness_receipt_is_execution_authority": False,
    "freshness_receipt_is_policy_authority": False,
    "freshness_receipt_is_production_authority": False,
}


def make_pair():
    p = FreshnessPolicy("p", "v1", 7, ("model-a",), ("read", "write"), ("route-a",), "audience-tools")
    l = CapabilityFreshnessLedger(p)
    a = CapabilityManifest("a", "agent-a", "model-a", "v1", ("read",), "route-a", "audience-tools", "task-1", 7, 1, 10, 100)
    o = CapabilityManifest("o", "agent-a", "model-a", "v1", ("read",), "route-a", "audience-tools", "task-1", 7, 1, 10, 100)
    l.register_manifest(a); l.register_manifest(o)
    return l, a, o


def make_request(i, a, o):
    return FreshnessRequest(f"use-{i}", "agent-a", "task-1", "audience-tools", "route-a", a.manifest_id, a.manifest_digest, o.manifest_id, o.manifest_digest, digest({"hop": 1}), 7, 7, 1, 1, 20, 80, f"nonce-{i}")


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    l, a, o = make_pair()

    def baseline(i):
        return a.manifest_digest == o.manifest_digest and a.model_id == o.model_id and a.tools == o.tools and a.route_id == o.route_id

    def verify(i):
        ledger, admitted, observed = make_pair()
        return ledger.admit(make_request(i, admitted, observed), now=21, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("freshness_verify_admit", verify)):
        mean, p95 = measure(fn)
        print(f"FAISAL_CAPABILITY_FRESHNESS_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
