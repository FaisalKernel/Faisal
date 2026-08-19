from __future__ import annotations

import statistics
import time

from faisal_path_governance import ActionRequest, PathGovernanceLedger, PathPolicy, PathRule, PathStep, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "path_receipt_is_execution_authority": False,
    "path_receipt_is_production_authority": False,
}

def make_step(i: int) -> PathStep:
    return PathStep(f"s-{i}", "agent-a", "tool_call", frozenset({"public_read"}), 7, i, digest({"i": i}), digest({"o": i}))

def make_request(i: int, labels=frozenset({"public_write"}), cost=2) -> ActionRequest:
    return ActionRequest(f"d-{i}", "agent-a", "tool_call", labels, 7, digest({"i": i}), digest({"p": i}), cost)

def measure(factory, count=1000):
    samples = []
    for i in range(count):
        started = time.perf_counter_ns()
        factory(i)
        samples.append(time.perf_counter_ns() - started)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]

def main() -> None:
    def allow(i):
        ledger = PathGovernanceLedger(PathPolicy("p", "v1", 7, max_risk_budget=100))
        ledger.append_observed(make_step(i))
        return ledger.admit(make_request(i), now=i + 1, authority=AUTHORITY)

    def deny(i):
        ledger = PathGovernanceLedger(PathPolicy("p", "v1", 7, max_risk_budget=1))
        ledger.append_observed(make_step(i))
        return ledger.admit(make_request(i, cost=2), now=i + 1, authority=AUTHORITY)

    def baseline(i):
        # Previous-version control-plane baseline: construct the same request
        # and path evidence without evaluating a governance decision.
        _ = make_step(i)
        return make_request(i)

    def rule_match(i):
        rule = PathRule("deny-export", "v1", frozenset({"private_read"}), frozenset({"external_write"}))
        ledger = PathGovernanceLedger(PathPolicy("p", "v1", 7, max_risk_budget=100, rules=(rule,)))
        ledger.append_observed(PathStep(f"s-{i}", "agent-a", "read", frozenset({"private_read"}), 7, i, digest({"i": i}), digest({"o": i})))
        return ledger.admit(make_request(i, labels=frozenset({"external_write"})), now=i + 1, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("allow", allow), ("deny", deny), ("rule_match", rule_match)):
        mean, p95 = measure(fn)
        print(f"FAISAL_PATH_GOVERNANCE_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")

if __name__ == "__main__":
    main()
