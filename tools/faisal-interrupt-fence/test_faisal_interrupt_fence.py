import unittest
from faisal_interrupt_fence import InterruptFenceError, InterruptFenceLedger, InterruptFencePolicy, InterruptRequest, digest

AUTH = {"model_output_is_authority": False, "interrupt_is_execution_authority": False, "rollback_is_execution_authority": False, "revocation_is_credential_authority": False, "side_effect_ledger_is_truth": False, "production_approval": False}
TASK = "task-interrupt"; INTENT = digest({"intent": "original"}); REVISED = digest({"intent": "revised"}); CP = digest({"checkpoint": 1}); ROOT1 = digest({"effects": 1}); ROOT2 = digest({"effects": 2})
POLICY = InterruptFencePolicy("p1", TASK, INTENT, 7, 10, 100, max_checkpoint_age=100, max_trace_lag=100)

def request(i, operation="pause", **overrides):
    values = {"request_id": f"r-{i}", "operation": operation, "task_id": TASK, "parent_intent_digest": INTENT, "requested_intent_digest": INTENT, "intent_generation": 7, "checkpoint_digest": CP, "checkpoint_trace_position": 1, "current_trace_position": 2, "checkpoint_side_effect_root": ROOT1, "current_side_effect_root": ROOT1, "checkpoint_irreversible_watermark": 1, "current_irreversible_watermark": 1, "transition_sequence": i, "issued_at": 20, "expires_at": 90}
    values.update(overrides); return InterruptRequest(**values)

class InterruptFenceTests(unittest.TestCase):
    def test_pause_revision_and_resume_transition(self):
        ledger = InterruptFenceLedger(POLICY)
        paused = ledger.admit(request(1, "pause"), current_generation=7, nonce="p", authority=AUTH, now=21)
        self.assertEqual(paused["verdict"], "admit"); self.assertEqual(paused["phase"], "paused"); self.assertFalse(paused["process_paused"])
        revised = ledger.admit(request(2, "revise", parent_intent_digest=INTENT, requested_intent_digest=REVISED, intent_generation=8, transition_sequence=2), current_generation=7, nonce="r", authority=AUTH, now=22)
        self.assertEqual(revised["verdict"], "admit"); self.assertEqual(revised["phase"], "interrupted"); self.assertEqual(revised["intent_generation"], 8)
        resumed = ledger.admit(request(3, "resume", parent_intent_digest=REVISED, requested_intent_digest=REVISED, intent_generation=8, transition_sequence=3), current_generation=8, nonce="x", authority=AUTH, now=23)
        self.assertEqual(resumed["phase"], "running")

    def test_retraction_and_fork_required_rollback(self):
        ledger = InterruptFenceLedger(POLICY)
        ledger.admit(request(1, "pause"), current_generation=7, nonce="p", authority=AUTH, now=21)
        retracted = ledger.admit(request(2, "retract", requested_intent_digest=REVISED, intent_generation=8, transition_sequence=2), current_generation=7, nonce="r", authority=AUTH, now=22)
        self.assertEqual(retracted["phase"], "interrupted")
        fork = ledger.admit(request(3, "rollback", parent_intent_digest=REVISED, requested_intent_digest=REVISED, intent_generation=8, checkpoint_trace_position=1, current_trace_position=3, checkpoint_irreversible_watermark=1, current_irreversible_watermark=2, transition_sequence=3), current_generation=8, nonce="f", authority=AUTH, now=23)
        self.assertEqual(fork["verdict"], "require_fork"); self.assertTrue(fork["effect_fork_required"]); self.assertFalse(fork["rollback_executed"]); self.assertFalse(fork["external_effects_undone"])

    def test_stale_checkpoint_sequence_and_intent_denials(self):
        cases = [
            ("stale", request(1, "pause", checkpoint_trace_position=1, current_trace_position=200), 7, "s"),
            ("sequence", request(2, "pause", transition_sequence=2), 7, "q"),
            ("intent", request(1, "pause", parent_intent_digest=REVISED, requested_intent_digest=REVISED), 7, "i"),
        ]
        for name, req, generation, nonce in cases:
            ledger = InterruptFenceLedger(InterruptFencePolicy("p", TASK, INTENT, 7, 10, 100, max_checkpoint_age=100, max_trace_lag=10))
            with self.subTest(name=name), self.assertRaises(InterruptFenceError): ledger.admit(req, current_generation=generation, nonce=nonce, authority=AUTH, now=21)
        ledger = InterruptFenceLedger(POLICY); ledger.admit(request(1, "pause"), current_generation=7, nonce="p", authority=AUTH, now=21)
        with self.assertRaises(InterruptFenceError): ledger.admit(request(2, "pause", transition_sequence=2), current_generation=7, nonce="q", authority=AUTH, now=22)

    def test_replay_authority_and_ledger_digest(self):
        ledger = InterruptFenceLedger(POLICY); first = ledger.admit(request(1, "pause"), current_generation=7, nonce="n", authority=AUTH, now=21)
        with self.assertRaises(InterruptFenceError): ledger.admit(request(2, "resume"), current_generation=7, nonce="n", authority=AUTH, now=22)
        with self.assertRaises(InterruptFenceError): InterruptFenceLedger(POLICY).admit(request(1, "pause"), current_generation=7, nonce="a", authority=dict(AUTH, rollback_is_execution_authority=True), now=21)
        self.assertTrue(first["receipt_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
