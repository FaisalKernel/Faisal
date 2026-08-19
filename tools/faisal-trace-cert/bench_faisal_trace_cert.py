#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_trace_cert import EvidenceRef, ReplayGuard, TraceProposal, TraceStep, certify_trace, verify_certificate

ITERATIONS = 5000
evidence = {"sha256:obs": EvidenceRef("sha256:obs", "observation", "obs://bench")}
step = TraceStep("s1", "read", "read", "example", "read:example", ("sha256:obs",), cost_units=2, generation=5)
proposal = TraceProposal("bench-trace", "bench-agent", "policy-9", 5, "bench-nonce", (step,), 10, frozenset({"read:example"}))


def baseline():
    return [(x.step_id, x.action, x.target) for x in proposal.steps]


def certified():
    cert = certify_trace(proposal, evidence, expected_policy_version="policy-9", expected_generation=5, replay_guard=ReplayGuard())
    return cert["certificate_digest"], verify_certificate(cert, proposal)


def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
checked, checked_result = measure(certified)
print(f"FAISAL_TRACE_CERT_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_TRACE_CERT_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_TRACE_CERT_VALIDATED_MEAN_NS={statistics.mean(checked):.2f}")
print(f"FAISAL_TRACE_CERT_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_TRACE_CERT_VALIDATED_P95_NS={sorted(checked)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_TRACE_CERT_OVERHEAD_RATIO={statistics.mean(checked) / statistics.mean(base):.4f}")
print(f"FAISAL_TRACE_CERT_BASELINE_RESULT={base_result}")
print(f"FAISAL_TRACE_CERT_VALIDATED_RESULT={checked_result}")
print("FAISAL_TRACE_CERT_BENCHMARK_SCOPE=local_projection_vs_deterministic_certification_and_verification_not_model_or_execution_latency")
