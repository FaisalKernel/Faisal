from __future__ import annotations

import unittest

from faisal_evaluator_consensus import ConsensusPolicy, ConsensusRequest, EvaluatorConsensusError, EvaluatorConsensusLedger, EvaluatorReceipt, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "evaluator_output_is_authority": False,
    "consensus_receipt_is_deployment_authority": False,
    "consensus_receipt_is_policy_authority": False,
    "consensus_receipt_is_production_authority": False,
    "confidence_is_truth": False,
}


def policy():
    return ConsensusPolicy("consensus-policy", "v1", 7, 47, min_evaluators=2, min_coverage_per_mille=1000, max_disagreement_per_mille=50, min_confidence_per_mille=700, max_safety_failures=0, max_harm_severity_per_mille=0, max_ttl=120)


def receipt(evaluator="e1", score=900, confidence=800, disagreement=0, safety=0, harm=0, key=1):
    return EvaluatorReceipt(evaluator, key, digest({"rubric": "r1"}), digest({"tasks": "t1"}), digest({"traces": "tr1"}), 1000, score, confidence, disagreement, safety, harm, 30)


def request(receipts=None, request_id="req-1", generation=7, abi=47, expires=100):
    p = policy()
    return ConsensusRequest(request_id, "set-1", digest({"manifest": "set-1"}), digest({"candidate": "c1"}), p.policy_digest, abi, generation, 20, expires, tuple(receipts or (receipt("e1"), receipt("e2", score=920))))


class EvaluatorConsensusTests(unittest.TestCase):
    def test_valid_consensus_and_ack(self):
        ledger = EvaluatorConsensusLedger(policy())
        r = ledger.admit(request(), now=31, authority=AUTHORITY)
        self.assertTrue(r["consensus_verified"])
        self.assertEqual(r["evaluator_count"], 2)
        self.assertFalse(r["release_approved"])
        ack = ledger.acknowledge("req-1", nonce="ack-1")
        self.assertTrue(ack["acknowledged"])
        self.assertFalse(ack["release_approved"])

    def test_identity_rubric_and_lineage_gates(self):
        cases = {
            "duplicate_identity": (receipt("e1"), receipt("e1", score=910)),
            "rubric": (receipt("e1"), EvaluatorReceipt("e2", 1, digest({"rubric": "r2"}), digest({"tasks": "t1"}), digest({"traces": "tr1"}), 1000, 900, 800, 0, 0, 0, 30)),
            "task_lineage": (receipt("e1"), EvaluatorReceipt("e2", 1, digest({"rubric": "r1"}), digest({"tasks": "t2"}), digest({"traces": "tr1"}), 1000, 900, 800, 0, 0, 0, 30)),
            "trace_lineage": (receipt("e1"), EvaluatorReceipt("e2", 1, digest({"rubric": "r1"}), digest({"tasks": "t1"}), digest({"traces": "tr2"}), 1000, 900, 800, 0, 0, 0, 30)),
        }
        for name, receipts in cases.items():
            with self.subTest(name=name), self.assertRaises(EvaluatorConsensusError):
                EvaluatorConsensusLedger(policy()).admit(request(receipts), now=31, authority=AUTHORITY)

    def test_reliability_hard_gates(self):
        cases = {
            "coverage": (receipt("e1"), EvaluatorReceipt("e2", 1, digest({"rubric": "r1"}), digest({"tasks": "t1"}), digest({"traces": "tr1"}), 999, 900, 800, 0, 0, 0, 30)),
            "confidence": (receipt("e1", confidence=600), receipt("e2", score=920)),
            "disagreement": (receipt("e1", score=800), receipt("e2", score=900)),
            "safety": (receipt("e1", safety=1), receipt("e2", score=920)),
            "harm": (receipt("e1", harm=1), receipt("e2", score=920)),
        }
        for name, receipts in cases.items():
            with self.subTest(name=name), self.assertRaises(EvaluatorConsensusError):
                EvaluatorConsensusLedger(policy()).admit(request(receipts, request_id=name), now=31, authority=AUTHORITY)

    def test_generation_expiry_tamper_replay_and_authority(self):
        ledger = EvaluatorConsensusLedger(policy())
        with self.assertRaises(EvaluatorConsensusError):
            ledger.admit(request(request_id="gen", generation=8), now=31, authority=AUTHORITY)
        with self.assertRaises(EvaluatorConsensusError):
            ledger.admit(request(request_id="expired", expires=21), now=31, authority=AUTHORITY)
        valid = ledger.admit(request(), now=31, authority=AUTHORITY)
        with self.assertRaises(EvaluatorConsensusError):
            ledger.admit(request(), now=31, authority=AUTHORITY)
        with self.assertRaises(EvaluatorConsensusError):
            ledger.admit(request(request_id="authority"), now=31, authority=dict(AUTHORITY, confidence_is_truth=True))
        ledger.acknowledge("req-1", nonce="nonce")
        with self.assertRaises(EvaluatorConsensusError):
            ledger.acknowledge("req-1", nonce="nonce")
        self.assertTrue(valid["request_digest"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
