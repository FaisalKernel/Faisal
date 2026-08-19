#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../faisal-trace-cert"))
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceProposal, TraceStep, certify_trace
from faisal_trace_conformance import RealizedStep, verify_conformance

ITERATIONS = 5000
evidence = {"sha256:obs": EvidenceRef("sha256:obs", "observation", "obs://bench")}
s1 = TraceStep("s1", "read", "read", "example", "read:example", ("sha256:obs",), generation=6)
s2 = TraceStep("s2", "transform", "transform", "local", "transform:local", ("sha256:obs",), depends_on=("s1",), generation=6)
proposal = TraceProposal("conformance-bench", "bench-agent", "policy-11", 6, "bench-nonce", (s1, s2), 10, frozenset({"read:example", "transform:local"}))
certificate = certify_trace(proposal, evidence, expected_policy_version="policy-11", expected_generation=6, replay_guard=ReplayGuard())
realized = [RealizedStep("s1", "read", "example", "read:example", "completed", "sha256:" + "1" * 64, generation=6), RealizedStep("s2", "transform", "local", "transform:local", "completed", "sha256:" + "2" * 64, generation=6)]


def baseline():
    return [(item.step_id, item.status) for item in realized]


def checked():
    result = verify_conformance(proposal, certificate, realized, expected_generation=6)
    return result["conformance"], result["completion"]


def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
checked_samples, checked_result = measure(checked)
print(f"FAISAL_TRACE_CONFORMANCE_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_TRACE_CONFORMANCE_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_TRACE_CONFORMANCE_VALIDATED_MEAN_NS={statistics.mean(checked_samples):.2f}")
print(f"FAISAL_TRACE_CONFORMANCE_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_TRACE_CONFORMANCE_VALIDATED_P95_NS={sorted(checked_samples)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_TRACE_CONFORMANCE_OVERHEAD_RATIO={statistics.mean(checked_samples) / statistics.mean(base):.4f}")
print(f"FAISAL_TRACE_CONFORMANCE_BASELINE_RESULT={base_result}")
print(f"FAISAL_TRACE_CONFORMANCE_VALIDATED_RESULT={checked_result}")
print("FAISAL_TRACE_CONFORMANCE_BENCHMARK_SCOPE=local_step_projection_vs_post_execution_conformance_and_hash_chain_verification_not_tool_or_execution_latency")
