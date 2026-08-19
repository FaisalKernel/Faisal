import unittest
from faisal_memory_intervention import MemoryInterventionError, MemoryInterventionLedger, MemoryInterventionPolicy, MemoryInterventionRequest, digest

AUTH = {"model_output_is_authority": False, "memory_is_authority": False, "intervention_is_execution_authority": False, "intervention_is_policy_authority": False, "production_approval": False}
TASK = "task-long"; SESSION = "session-1"; INTENT = digest({"task": TASK}); MEMORY = digest({"memory": "failed-command-diagnosis"}); E1 = digest({"evidence": 1}); E2 = digest({"evidence": 2})
POLICY = MemoryInterventionPolicy("p1", TASK, SESSION, INTENT, 2, 7, 10, 100, 512, 3, 3, 0.7, 0.6)

def request(i, **overrides):
    values = {"request_id": f"r-{i}", "task_id": TASK, "session_id": SESSION, "intent_digest": INTENT, "memory_digest": MEMORY, "source_evidence_digests": tuple(sorted((E1, E2))), "trigger_reason": "failed-attempt-diagnosis", "confidence": 0.9, "novelty": 0.8, "estimated_tokens": 128, "memory_sensitivity": 1, "step": 10, "last_intervention_step": -1, "generation": 7, "issued_at": 20}
    values.update(overrides)
    return MemoryInterventionRequest(**values)

class MemoryInterventionTests(unittest.TestCase):
    def test_valid_selective_intervention_admission(self):
        result = MemoryInterventionLedger(POLICY).admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertEqual(result["status"], "intervention_admitted")
        self.assertEqual(result["trigger_reason"], "failed-attempt-diagnosis")
        self.assertTrue(result["source_evidence_digests"])
        self.assertFalse(result["memory_retrieved"]); self.assertFalse(result["prompt_injected"]); self.assertFalse(result["tools_executed"]); self.assertFalse(result["production_approved"])

    def test_threshold_budget_sensitivity_and_cooldown_denials(self):
        cases = [
            ("confidence", request(1, confidence=0.69), "c"),
            ("novelty", request(2, novelty=0.59), "n"),
            ("tokens", request(3, estimated_tokens=513), "t"),
            ("sensitivity", request(4, memory_sensitivity=3), "s"),
            ("cooldown", request(5, step=11, last_intervention_step=9), "d"),
        ]
        for name, req, nonce in cases:
            with self.subTest(name=name), self.assertRaises(MemoryInterventionError):
                MemoryInterventionLedger(POLICY).admit(req, current_generation=7, nonce=nonce, authority=AUTH, now=21)

    def test_scope_freshness_evidence_replay_and_authority_denials(self):
        cases = [
            ("task", request(1, task_id="other-task"), "task"),
            ("session", request(2, session_id="other-session"), "session"),
            ("intent", request(3, intent_digest=digest({"other": True})), "intent"),
            ("evidence", request(4, source_evidence_digests=()), "evidence"),
            ("generation", request(5, generation=8), "generation"),
            ("stale", request(6, issued_at=0), "stale"),
        ]
        for name, req, nonce in cases:
            with self.subTest(name=name), self.assertRaises(MemoryInterventionError):
                MemoryInterventionLedger(POLICY).admit(req, current_generation=7, nonce=nonce, authority=AUTH, now=101 if name == "stale" else 21)
        ledger = MemoryInterventionLedger(POLICY)
        ledger.admit(request(7), current_generation=7, nonce="replay", authority=AUTH, now=21)
        with self.assertRaises(MemoryInterventionError): ledger.admit(request(8, memory_digest=digest({"memory": "new"})), current_generation=7, nonce="replay", authority=AUTH, now=22)
        with self.assertRaises(MemoryInterventionError): MemoryInterventionLedger(POLICY).admit(request(9), current_generation=7, nonce="authority", authority=dict(AUTH, memory_is_authority=True), now=21)

    def test_ledger_digest_and_memory_digest_replay(self):
        ledger = MemoryInterventionLedger(POLICY)
        first = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        with self.assertRaises(MemoryInterventionError): ledger.admit(request(2), current_generation=7, nonce="n2", authority=AUTH, now=22)
        self.assertTrue(first["receipt_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
