from __future__ import annotations

import statistics
import time

from faisal_intervention import InterventionLedger, InterventionPolicy, InterventionRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "intervention_receipt_is_execution_authority": False,
    "intervention_receipt_is_production_authority": False,
}


def request(i: int, intervention="pause", approval=None) -> InterventionRequest:
    return InterventionRequest(
        f"i-{i}", "supervisor-a", "task-1", intervention, 7, 10, 100,
        digest({"observation": i}), digest({"state": i}), digest({"checkpoint": i}),
        digest({"proposed": i}), digest({"reason": i}), 1, approval,
    )


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns()
        fn(i)
        samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    def baseline(i):
        return request(i)

    def admit(i):
        ledger = InterventionLedger(InterventionPolicy("p", "v1", 7, frozenset({"pause"})))
        return ledger.admit(request(i), now=20, authority=AUTHORITY)

    def approval(i):
        ledger = InterventionLedger(InterventionPolicy("p", "v1", 7, frozenset({"terminate"}), approval_required=frozenset({"terminate"})))
        return ledger.admit(request(i, "terminate"), now=20, authority=AUTHORITY)

    def complete(i):
        ledger = InterventionLedger(InterventionPolicy("p", "v1", 7, frozenset({"pause"})))
        ledger.admit(request(i), now=20, authority=AUTHORITY)
        return ledger.complete(f"i-{i}", post_state_digest=digest({"post": i}), post_trace_digest=digest({"trace": i}), now=21, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("admit", admit), ("approval_gate", approval), ("complete", complete)):
        mean, p95 = measure(fn)
        print(f"FAISAL_INTERVENTION_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
