#!/usr/bin/env python3
import statistics
import time

from faisal_delegation import DelegationScope, Invocation, authorize_invocation, derive_child, issue_root

ITERATIONS = 5000
root_scope = DelegationScope(frozenset({"read", "write"}), frozenset({"repo", "issues"}), frozenset(), 10)
root = issue_root(delegation_id="bench-root", issuer="user", delegatee="planner", issued_at=100, expires_at=1000, scope=root_scope, max_depth=4, holder_proof_digest="sha256:" + "1" * 64, nonce="bench-root-nonce")
child = derive_child(root, delegation_id="bench-child", delegatee="worker", issued_at=150, expires_at=800, scope=DelegationScope(frozenset({"read"}), frozenset({"repo"}), frozenset(), 4), holder_proof_digest="sha256:" + "2" * 64, nonce="bench-child-nonce")
invocation = Invocation("read", "repo", None, "bench-call")


def baseline():
    return invocation.tool in child.scope.tools and invocation.resource in child.scope.resources


def checked():
    result = authorize_invocation((root, child), invocation, now=200)
    return result["authorized"]


def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - start)
    return samples, result

base, base_result = measure(baseline)
validated, validated_result = measure(checked)
print(f"FAISAL_DELEGATION_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_DELEGATION_BASELINE_MEAN_NS={statistics.mean(base):.2f}")
print(f"FAISAL_DELEGATION_VALIDATED_MEAN_NS={statistics.mean(validated):.2f}")
print(f"FAISAL_DELEGATION_BASELINE_P95_NS={sorted(base)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_DELEGATION_VALIDATED_P95_NS={sorted(validated)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_DELEGATION_OVERHEAD_RATIO={statistics.mean(validated) / statistics.mean(base):.4f}")
print(f"FAISAL_DELEGATION_BASELINE_RESULT={base_result}")
print(f"FAISAL_DELEGATION_VALIDATED_RESULT={validated_result}")
print("FAISAL_DELEGATION_BENCHMARK_SCOPE=local_scope_lookup_vs_offline_chain_verification_and_invocation_authorization_not_network_or_tool_latency")
