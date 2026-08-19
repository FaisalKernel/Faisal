import unittest
from faisal_handoff_authorization import HandoffAuthorizationError, HandoffAuthorizationLedger, HandoffAuthorizationPolicy, HandoffAuthorizationRequest, digest

AUTH = {"model_output_is_authority": False, "agent_claim_is_authority": False, "memory_is_authority": False, "authorization_receipt_is_execution_authority": False, "authorization_receipt_is_policy_authority": False, "production_approval": False}
TASK = "task-handoff"; ORIGINAL = digest({"request": TASK}); SOURCE = digest({"policy": "source"}); M1 = digest({"memory": 1}); M2 = digest({"memory": 2})
POLICY = HandoffAuthorizationPolicy("p1", TASK, ORIGINAL, SOURCE, ("delete", "read", "search", "write"), ("write",), ("delete",), tuple(sorted((M1, M2))), 7, 10, 100, 2)

def request(i, **overrides):
    values = {"request_id": f"r-{i}", "handoff_id": f"h-{i}", "issuer_agent_id": "agent-a", "delegatee_agent_id": "agent-b", "task_id": TASK, "original_request_digest": ORIGINAL, "source_policy_digest": SOURCE, "parent_scope": ("read", "search", "write"), "requested_scope": ("read", "search"), "disclosed_memory_digests": (M1,), "generation": 7, "issued_at": 20, "expires_at": 90, "trace_position": i}
    values.update(overrides); return HandoffAuthorizationRequest(**values)

class HandoffAuthorizationTests(unittest.TestCase):
    def test_allow_attenuated_handoff_and_receipt_only_boundary(self):
        result = HandoffAuthorizationLedger().admit(request(1), policy=POLICY, current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertEqual(result["verdict"], "allow"); self.assertTrue(result["scope_attenuated"])
        self.assertEqual(result["requested_scope"], ["read", "search"]); self.assertEqual(result["disclosed_memory_digests"], [M1])
        self.assertFalse(result["memory_transferred"]); self.assertFalse(result["capabilities_delegated"]); self.assertFalse(result["tools_executed"]); self.assertFalse(result["production_approved"])

    def test_confirmation_and_deny_verdicts(self):
        confirmation = HandoffAuthorizationLedger().admit(request(1, requested_scope=("read", "write")), policy=POLICY, current_generation=7, nonce="c", authority=AUTH, now=21)
        self.assertEqual(confirmation["verdict"], "require_confirmation")
        denied_policy = HandoffAuthorizationPolicy("deny", TASK, ORIGINAL, SOURCE, ("delete", "read", "search", "write"), (), ("delete",), tuple(sorted((M1, M2))), 7, 10, 100, 2)
        denied = HandoffAuthorizationLedger().admit(request(2, parent_scope=("delete", "read", "search", "write"), requested_scope=("delete",)), policy=denied_policy, current_generation=7, nonce="d", authority=AUTH, now=21)
        self.assertEqual(denied["verdict"], "deny")

    def test_widened_scope_provenance_memory_and_budget_denials(self):
        cases = [
            ("widened", request(1, parent_scope=("read",), requested_scope=("read", "write")), POLICY, "w"),
            ("parent_outside", request(2, parent_scope=("read", "unknown"), requested_scope=("read",)), POLICY, "p"),
            ("original", request(3, original_request_digest=digest({"other": True})), POLICY, "o"),
            ("source", request(4, source_policy_digest=digest({"other": True})), POLICY, "s"),
            ("memory", request(5, disclosed_memory_digests=(M1, digest({"memory": "unapproved"}))), POLICY, "m"),
            ("generation", request(6, generation=8), POLICY, "g"),
            ("stale", request(7, issued_at=0), POLICY, "t"),
        ]
        for name, req, policy, nonce in cases:
            with self.subTest(name=name), self.assertRaises(HandoffAuthorizationError):
                HandoffAuthorizationLedger().admit(req, policy=policy, current_generation=7, nonce=nonce, authority=AUTH, now=101 if name == "stale" else 21)
        small = HandoffAuthorizationPolicy("small", TASK, ORIGINAL, SOURCE, ("read", "search", "write"), (), (), (M1, M2), 7, 10, 100, 1)
        with self.assertRaises(HandoffAuthorizationError): HandoffAuthorizationLedger().admit(request(8, disclosed_memory_digests=(M1, M2)), policy=small, current_generation=7, nonce="budget", authority=AUTH, now=21)

    def test_replay_authority_and_ledger_digest(self):
        ledger = HandoffAuthorizationLedger(); first = ledger.admit(request(1), policy=POLICY, current_generation=7, nonce="n1", authority=AUTH, now=21)
        with self.assertRaises(HandoffAuthorizationError): ledger.admit(request(2, handoff_id="h-2"), policy=POLICY, current_generation=7, nonce="n1", authority=AUTH, now=22)
        with self.assertRaises(HandoffAuthorizationError): HandoffAuthorizationLedger().admit(request(3), policy=POLICY, current_generation=7, nonce="a", authority=dict(AUTH, memory_is_authority=True), now=21)
        self.assertTrue(first["receipt_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
