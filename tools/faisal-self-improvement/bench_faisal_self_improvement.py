from __future__ import annotations

import statistics
import time

from faisal_self_improvement import EvaluationEvidence, ImprovementCandidate, ImprovementPolicy, PromotionReceipt, SelfImprovementLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "candidate_claim_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "self_improvement_receipt_is_policy_authority": False,
    "self_improvement_receipt_is_production_authority": False,
    "autonomous_privileged_modification_allowed": False,
}


def build():
    p = ImprovementPolicy("p", "v1", 7, 47, max_ttl=120, max_canary_per_mille=100, min_quality_delta_per_mille=10, max_safety_regression_per_mille=0, require_approval=True)
    base = digest({"component": "baseline"}); changed = digest({"component": "candidate"})
    ev = EvaluationEvidence("e", base, changed, digest({"tasks": 1}), digest({"traces": 1}), 20, 0, 0, 8, 30)
    c = ImprovementCandidate("candidate", "routing_policy", base, changed, digest({"diff": 1}), p.policy_digest, 47, 7, 20, 100, 50, "rollback", ev, "approval")
    return p, c


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        start = time.perf_counter_ns(); fn(i); samples.append(time.perf_counter_ns() - start)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    p, c = build()

    def baseline(i):
        return {"candidate_id": c.candidate_id, "component": c.component, "candidate_digest": c.candidate_digest, "quality": c.evidence.quality_delta_per_mille}

    def admit(i):
        policy, candidate = build(); l = SelfImprovementLedger(policy)
        return l.admit_candidate(candidate, now=31, authority=AUTHORITY)

    def canary(i):
        policy, candidate = build(); l = SelfImprovementLedger(policy)
        l.admit_candidate(candidate, now=31, authority=AUTHORITY)
        receipt = PromotionReceipt(f"promotion-{i}", candidate.candidate_id, candidate.candidate_digest, 40, 60, 25, 0, False, "verifier")
        return l.verify_canary(receipt, now=61, authority=AUTHORITY, nonce=f"nonce-{i}")

    for name, fn in (("baseline_ungoverned", baseline), ("candidate_admit", admit), ("canary_verify", canary)):
        mean, p95 = measure(fn)
        print(f"FAISAL_SELF_IMPROVEMENT_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
