import unittest
from faisal_intent_repair import IntentPolicy, IntentRepairError, IntentRepairLedger, RepairProposal, SubtaskProposal, digest

AUTH = {"model_output_is_authority": False, "verifier_output_is_authority": False, "artifact_is_authority": False, "intent_receipt_is_execution_authority": False, "intent_receipt_is_production_authority": False, "production_approval": False}
INTENT = digest({"task": "release-report"}); C1 = digest({"constraint": "must-test"}); C2 = digest({"constraint": "must-preserve-boundary"}); SUB = digest({"subtask": "research"}); ART = digest({"artifact": "draft"}); CK = digest({"checkpoint": 1}); VER = digest({"verifier": "v1"})
POLICY = IntentPolicy("intent-policy", INTENT, tuple(sorted((C1, C2))), 7, 10, 100, 3, 2)

def sub(i, trace, intent=INTENT, constraints=(C1, C2), issued=20):
    return SubtaskProposal(f"sub-{i}", intent, SUB, tuple(sorted(constraints)), (), CK, trace, 7, issued)

def repair(i, index=1, passed=False, intent=INTENT, failed=(C1,), issued=20):
    return RepairProposal(f"repair-{i}", intent, ART, tuple(sorted(failed)), VER, CK, 10 + index, index, 7, issued, passed)

class IntentRepairTests(unittest.TestCase):
    def test_subtask_binding_and_monotonic_trace(self):
        ledger = IntentRepairLedger(POLICY)
        first = ledger.admit_subtask(sub(1, 1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        second = ledger.admit_subtask(sub(2, 2), current_generation=7, nonce="n2", authority=AUTH, now=22)
        self.assertEqual(first["status"], "subtask_admitted"); self.assertEqual(second["trace_position"], 2)
        self.assertFalse(second["execution_performed"]); self.assertFalse(second["artifact_modified"]); self.assertFalse(second["production_approved"])

    def test_repair_requires_failed_verification_and_is_bounded(self):
        ledger = IntentRepairLedger(POLICY)
        result = ledger.admit_repair(repair(1), current_generation=7, nonce="r1", authority=AUTH, now=21)
        self.assertEqual(result["status"], "repair_admitted")
        with self.assertRaises(IntentRepairError): ledger.admit_repair(repair(2, passed=True), current_generation=7, nonce="r2", authority=AUTH, now=22)
        with self.assertRaises(IntentRepairError): ledger.admit_repair(repair(3, index=3), current_generation=7, nonce="r3", authority=AUTH, now=23)

    def test_intent_constraint_generation_stale_and_authority_denials(self):
        cases = [
            ("intent", sub(1, 1, intent=digest({"other": True})), {"current_generation": 7, "nonce": "i"}, 21),
            ("constraint", sub(2, 1, constraints=(C1,)), {"current_generation": 7, "nonce": "c"}, 21),
            ("generation", SubtaskProposal("sub-g", INTENT, SUB, tuple(sorted((C1, C2))), (), CK, 1, 8, 20), {"current_generation": 7, "nonce": "g"}, 21),
            ("stale", sub(4, 1, issued=0), {"current_generation": 7, "nonce": "s"}, 101),
        ]
        for name, proposal, kwargs, now in cases:
            with self.subTest(name=name), self.assertRaises(IntentRepairError):
                IntentRepairLedger(POLICY).admit_subtask(proposal, authority=AUTH, now=now, **kwargs)
        with self.assertRaises(IntentRepairError): IntentRepairLedger(POLICY).admit_subtask(sub(5, 1), current_generation=7, nonce="a", authority=dict(AUTH, model_output_is_authority=True), now=21)

    def test_replay_and_ledger_digest(self):
        ledger = IntentRepairLedger(POLICY)
        first = ledger.admit_subtask(sub(1, 1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        with self.assertRaises(IntentRepairError): ledger.admit_subtask(sub(2, 2), current_generation=7, nonce="n1", authority=AUTH, now=22)
        self.assertTrue(first["receipt_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
