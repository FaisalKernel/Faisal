from __future__ import annotations

import statistics
import time

from faisal_evaluator_consensus import ConsensusPolicy, ConsensusRequest, EvaluatorConsensusLedger, EvaluatorReceipt, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "evaluator_output_is_authority": False,
    "consensus_receipt_is_deployment_authority": False,
    "consensus_receipt_is_policy_authority": False,
    "consensus_receipt_is_production_authority": False,
    "confidence_is_truth": False,
}


def build():
    p = ConsensusPolicy("p", "v1", 7, 47, min_evaluators=2, min_coverage_per_mille=1000, max_disagreement_per_mille=50, min_confidence_per_mille=700, max_safety_failures=0, max_harm_severity_per_mille=0, max_ttl=120)
    def r(e, score):
        return EvaluatorReceipt(e, 1, digest({"rubric": "r1"}), digest({"tasks": "t1"}), digest({"traces": "tr1"}), 1000, score, 800, 0, 0, 0, 30)
    req = ConsensusRequest("req", "set-1", digest({"manifest": "set-1"}), digest({"candidate": "c1"}), p.policy_digest, 47, 7, 20, 100, (r("e1", 900), r("e2", 920)))
    return p, req


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    p, req = build()

    def baseline(i):
        return [x.receipt_digest for x in req.receipts]

    def admit(i):
        policy, request = build(); return EvaluatorConsensusLedger(policy).admit(request, now=31, authority=AUTHORITY)

    def acknowledge(i):
        policy, request = build(); ledger = EvaluatorConsensusLedger(policy); ledger.admit(request, now=31, authority=AUTHORITY); return ledger.acknowledge("req", nonce=f"nonce-{i}")

    for name, fn in (("baseline_ungoverned", baseline), ("consensus_admit", admit), ("consensus_acknowledge", acknowledge)):
        mean, p95 = measure(fn)
        print(f"FAISAL_EVALUATOR_CONSENSUS_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
