from __future__ import annotations

import unittest

from faisal_self_improvement import EvaluationEvidence, ImprovementCandidate, ImprovementPolicy, PromotionReceipt, SelfImprovementError, SelfImprovementLedger, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "candidate_claim_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "self_improvement_receipt_is_policy_authority": False,
    "self_improvement_receipt_is_production_authority": False,
    "autonomous_privileged_modification_allowed": False,
}


def policy():
    return ImprovementPolicy("improvement-policy", "v1", 7, 47, max_ttl=120, max_canary_per_mille=100, min_quality_delta_per_mille=10, max_safety_regression_per_mille=0, require_approval=True)


def evidence(base, candidate, quality=20, safety=0, regressions=0, recorded=30):
    return EvaluationEvidence("evidence-1", base, candidate, digest({"tasks": "held-out"}), digest({"traces": "raw"}), quality, safety, regressions, 8, recorded)


def candidate(base=None, changed=None, component="routing_policy", approval="approval-1", generation=7, abi=47, expires=100, ev=None):
    base = base or digest({"routing": "baseline"})
    changed = changed or digest({"routing": "candidate"})
    ev = ev or evidence(base, changed)
    p = policy()
    return ImprovementCandidate("candidate-1", component, base, changed, digest({"diff": changed}), p.policy_digest, abi, generation, 20, expires, 50, "FAISAL-FRONTIER-INTERACTION-LEDGER-2026-08-19", ev, approval)


class SelfImprovementTests(unittest.TestCase):
    def test_valid_scaffold_candidate_and_canary(self):
        l = SelfImprovementLedger(policy())
        c = candidate()
        admitted = l.admit_candidate(c, now=31, authority=AUTHORITY)
        self.assertTrue(admitted["admitted"])
        self.assertFalse(admitted["code_modified"])
        self.assertFalse(admitted["deployment_executed"])
        receipt = PromotionReceipt("promotion-1", c.candidate_id, c.candidate_digest, 40, 60, 25, 0, False, "verifier-a")
        verified = l.verify_canary(receipt, now=61, authority=AUTHORITY, nonce="nonce-1")
        self.assertTrue(verified["canary_verified"])
        self.assertFalse(verified["promotion_executed"])

    def test_approval_and_component_boundaries(self):
        l = SelfImprovementLedger(policy())
        with self.assertRaises(SelfImprovementError):
            l.admit_candidate(candidate(approval=None), now=31, authority=AUTHORITY)
        with self.assertRaises(SelfImprovementError):
            l.admit_candidate(candidate(component="kernel_code"), now=31, authority=AUTHORITY)
        with self.assertRaises(SelfImprovementError):
            l.admit_candidate(candidate(abi=48), now=31, authority=AUTHORITY)

    def test_evidence_quality_safety_and_regression_gates(self):
        l = SelfImprovementLedger(policy())
        b = digest({"b": 1}); c = digest({"c": 1})
        for name, ev in (("quality", evidence(b, c, quality=0)), ("safety", evidence(b, c, safety=-1)), ("regressions", evidence(b, c, regressions=1))):
            with self.assertRaises(SelfImprovementError):
                l.admit_candidate(candidate(base=b, changed=c, ev=ev), now=31, authority=AUTHORITY)

    def test_expiry_replay_rollback_and_tamper(self):
        l = SelfImprovementLedger(policy())
        c = candidate()
        l.admit_candidate(c, now=31, authority=AUTHORITY)
        with self.assertRaises(SelfImprovementError):
            l.admit_candidate(c, now=31, authority=AUTHORITY)
        with self.assertRaises(SelfImprovementError):
            l.verify_canary(PromotionReceipt("bad", c.candidate_id, digest({"wrong": 1}), 40, 60, 25, 0, False, "v"), now=61, authority=AUTHORITY, nonce="bad")
        with self.assertRaises(SelfImprovementError):
            l.verify_canary(PromotionReceipt("rollback", c.candidate_id, c.candidate_digest, 40, 60, 25, 0, True, "v"), now=61, authority=AUTHORITY, nonce="rollback")
        expired = SelfImprovementLedger(policy())
        old = candidate(expires=40)
        expired.admit_candidate(old, now=31, authority=AUTHORITY)
        with self.assertRaises(SelfImprovementError):
            expired.verify_canary(PromotionReceipt("expired", old.candidate_id, old.candidate_digest, 35, 40, 25, 0, False, "v"), now=40, authority=AUTHORITY, nonce="expired")

    def test_authority_boundary(self):
        l = SelfImprovementLedger(policy())
        with self.assertRaises(SelfImprovementError):
            l.admit_candidate(candidate(), now=31, authority=dict(AUTHORITY, autonomous_privileged_modification_allowed=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
