from __future__ import annotations

import statistics
import time

from faisal_interaction_ledger import InteractionLedger, LedgerPolicy, LedgerRequest, SegmentAnchor, TerminalVerification, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "telemetry_is_kernel_ground_truth": False,
    "span_content_is_truth": False,
    "ledger_receipt_is_execution_authority": False,
    "ledger_receipt_is_policy_authority": False,
    "ledger_receipt_is_production_authority": False,
}
CAP = digest({"manifest": "m1"})
DELEGATION = digest({"chain": "d1"})
ROUTE = digest({"route": "r1"})


def build():
    p = LedgerPolicy("p", "v1", 7, "audience-tools", max_ttl=120, max_spans=8)
    l = InteractionLedger(p)
    s1 = SegmentAnchor("s1", "trace", "task", "artifact", CAP, DELEGATION, ROUTE, "audience-tools", 7, p.policy_digest, 1, None, digest({"span": 1}), 10, 100)
    d1 = l.append(s1)
    s2 = SegmentAnchor("s2", "trace", "task", "artifact", CAP, DELEGATION, ROUTE, "audience-tools", 7, p.policy_digest, 2, d1, digest({"span": 2}), 11, 100)
    l.append(s2)
    return p, l, s1, s2


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    p, l, s1, s2 = build()
    terminal = TerminalVerification("term", "s2", digest({"result": "ok"}), True, "verifier", 30, "completed")

    def baseline(i):
        return [s1.segment_digest, s2.segment_digest, terminal.verification_digest]

    def verify(i):
        policy, ledger, first, second = build()
        term = TerminalVerification(f"term-{i}", "s2", digest({"result": "ok"}), True, "verifier", 30, "completed")
        request = LedgerRequest(f"req-{i}", "trace", "task", "artifact", CAP, DELEGATION, ROUTE, "audience-tools", 7, policy.policy_digest, "s2", 1, 2, (first.segment_digest, second.segment_digest), term, 20, 80, f"nonce-{i}")
        return ledger.admit(request, now=31, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("ledger_verify_admit", verify)):
        mean, p95 = measure(fn)
        print(f"FAISAL_INTERACTION_LEDGER_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
