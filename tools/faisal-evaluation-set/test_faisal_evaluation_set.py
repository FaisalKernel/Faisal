from __future__ import annotations

import unittest

from faisal_evaluation_set import EvaluationPolicy, EvaluationResult, EvaluationSetError, EvaluationSetLedger, EvaluationSetManifest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "grader_output_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "evaluation_receipt_is_policy_authority": False,
    "evaluation_receipt_is_production_authority": False,
    "dataset_manifest_is_truth": False,
}


def policy():
    return EvaluationPolicy("eval-policy", "v1", 7, 47, min_task_count=4, min_coverage_per_mille=1000, max_overlap_per_mille=0, max_contamination_per_mille=0, max_ttl=120)


def manifest(set_id="set-1", task_count=4, coverage=1000, overlap=0, contamination=0, independent_split=True, independent_grader=True, generation=7, recorded=20, expires=100):
    p = policy()
    return EvaluationSetManifest(set_id, digest({"tasks": set_id}), digest({"split": set_id}), digest({"grader": set_id}), p.policy_digest, task_count, coverage, overlap, contamination, independent_split, independent_grader, generation, recorded, expires)


def result(m, result_id="result-1", completed=4, passed=4, safety=0, recorded=30):
    return EvaluationResult(result_id, m.set_id, m.manifest_digest, digest({"baseline": "candidate"}), digest({"candidate": "x"}), digest({"tasks": result_id}), digest({"traces": result_id}), completed, passed, safety, recorded)


class EvaluationSetTests(unittest.TestCase):
    def test_valid_manifest_and_complete_result(self):
        ledger = EvaluationSetLedger(policy())
        m = manifest()
        admitted = ledger.admit_manifest(m, now=31, authority=AUTHORITY)
        self.assertTrue(admitted["admitted"])
        self.assertFalse(admitted["datasets_created"])
        verified = ledger.verify_result(result(m), now=31, authority=AUTHORITY, nonce="nonce-1")
        self.assertTrue(verified["evaluation_verified"])
        self.assertFalse(verified["release_approved"])

    def test_manifest_quality_gates(self):
        cases = {
            "task_count": manifest(task_count=3),
            "coverage": manifest(coverage=999),
            "overlap": manifest(overlap=1),
            "contamination": manifest(contamination=1),
            "split": manifest(independent_split=False),
            "grader": manifest(independent_grader=False),
        }
        for name, m in cases.items():
            with self.subTest(name=name), self.assertRaises(EvaluationSetError):
                EvaluationSetLedger(policy()).admit_manifest(m, now=31, authority=AUTHORITY)

    def test_generation_expiry_and_policy_binding(self):
        ledger = EvaluationSetLedger(policy())
        with self.assertRaises(EvaluationSetError):
            ledger.admit_manifest(manifest(generation=8), now=31, authority=AUTHORITY)
        with self.assertRaises(EvaluationSetError):
            ledger.admit_manifest(manifest(expires=21), now=31, authority=AUTHORITY)
        p = policy()
        bad = EvaluationSetManifest("bad-policy", digest({"tasks": 1}), digest({"split": 1}), digest({"grader": 1}), digest({"wrong": 1}), 4, 1000, 0, 0, True, True, 7, 20, 100)
        with self.assertRaises(EvaluationSetError):
            ledger.admit_manifest(bad, now=31, authority=AUTHORITY)

    def test_result_completeness_safety_and_replay(self):
        ledger = EvaluationSetLedger(policy())
        m = manifest(); ledger.admit_manifest(m, now=31, authority=AUTHORITY)
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(result(m, result_id="incomplete", completed=3), now=31, authority=AUTHORITY, nonce="incomplete")
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(result(m, result_id="unsafe", safety=1), now=31, authority=AUTHORITY, nonce="unsafe")
        valid = result(m, result_id="valid")
        ledger.verify_result(valid, now=31, authority=AUTHORITY, nonce="valid")
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(valid, now=31, authority=AUTHORITY, nonce="valid-replay")
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(result(m, result_id="nonce-replay"), now=31, authority=AUTHORITY, nonce="valid")

    def test_result_tamper_and_authority(self):
        ledger = EvaluationSetLedger(policy())
        m = manifest(); ledger.admit_manifest(m, now=31, authority=AUTHORITY)
        tampered = EvaluationResult("tampered", m.set_id, digest({"wrong": 1}), digest({"baseline": 1}), digest({"candidate": 1}), digest({"tasks": 1}), digest({"traces": 1}), 4, 4, 0, 30)
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(tampered, now=31, authority=AUTHORITY, nonce="tamper")
        with self.assertRaises(EvaluationSetError):
            ledger.verify_result(result(m, result_id="authority"), now=31, authority=dict(AUTHORITY, grader_output_is_authority=True), nonce="authority")


if __name__ == "__main__":
    unittest.main(verbosity=2)
