import unittest
from faisal_route_receipt import RouteReceiptError, RouteReceiptLedger, RouteReceiptPolicy, RouteReceiptRequest, TrajectorySummary, digest

AUTH = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "confidence_is_truth": False, "route_receipt_is_execution_authority": False, "route_receipt_is_policy_authority": False, "production_approval": False}
TASK = "task-route"; SESSION = "session-route"; INTENT = digest({"task": TASK}); MODELS = ("model-small", "model-large"); VERSIONS = ("v1", "v2"); PROVIDERS = ("provider-a", "provider-b")
POLICY = RouteReceiptPolicy("p1", TASK, SESSION, INTENT, MODELS, VERSIONS, PROVIDERS, 2, 7, 10, 100, 1000, 0.7, 0.6)

def request(i, **overrides):
    values = {"request_id": f"r-{i}", "task_id": TASK, "session_id": SESSION, "intent_digest": INTENT, "requested_model": "model-small", "requested_version": "v1", "effective_model": "model-large", "effective_version": "v2", "effective_provider": "provider-a", "service_tier": "standard", "fallback_chain": ("model-large",), "tool_use": True, "trajectory": TrajectorySummary(3, 0.82, 0.8, 0.7, 0.75, 0.2, 1), "route_cost_milli": 200, "generation": 7, "issued_at": 20}
    values.update(overrides); return RouteReceiptRequest(**values)

class RouteReceiptTests(unittest.TestCase):
    def test_valid_route_receipt_and_transparency(self):
        result = RouteReceiptLedger(POLICY).admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertEqual(result["status"], "route_receipt_admitted")
        self.assertEqual(result["requested_model"], "model-small"); self.assertEqual(result["effective_model"], "model-large"); self.assertEqual(result["fallback_chain"], ["model-large"])
        self.assertTrue(result["route_verified"]); self.assertTrue(result["confidence_calibrated"]); self.assertTrue(result["tool_use"])
        self.assertFalse(result["inference_executed"]); self.assertFalse(result["model_selected"]); self.assertFalse(result["production_approved"])

    def test_confidence_stability_fallback_and_budget_denials(self):
        cases = [
            ("confidence", request(1, trajectory=TrajectorySummary(3, 0.75, 0.69, 0.6, 0.8, 0.1, 1)), "c"),
            ("stability", request(2, trajectory=TrajectorySummary(3, 0.75, 0.8, 0.6, 0.59, 0.1, 1)), "s"),
            ("fallback", request(3, fallback_chain=("model-large", "model-small"), trajectory=TrajectorySummary(3, 0.8, 0.8, 0.7, 0.8, 0.2, 3)), "f"),
            ("budget", request(4, route_cost_milli=1001), "b"),
        ]
        for name, req, nonce in cases:
            with self.subTest(name=name), self.assertRaises(RouteReceiptError):
                RouteReceiptLedger(POLICY).admit(req, current_generation=7, nonce=nonce, authority=AUTH, now=21)

    def test_model_version_provider_scope_and_authority_denials(self):
        cases = [
            ("model", request(1, effective_model="unapproved"), "m"),
            ("version", request(2, effective_version="v9"), "v"),
            ("provider", request(3, effective_provider="unapproved"), "p"),
            ("intent", request(4, intent_digest=digest({"other": True})), "i"),
            ("generation", request(5, generation=8), "g"),
            ("stale", request(6, issued_at=0), "stale"),
        ]
        for name, req, nonce in cases:
            with self.subTest(name=name), self.assertRaises(RouteReceiptError):
                RouteReceiptLedger(POLICY).admit(req, current_generation=7, nonce=nonce, authority=AUTH, now=101 if name == "stale" else 21)
        with self.assertRaises(RouteReceiptError): RouteReceiptLedger(POLICY).admit(request(7), current_generation=7, nonce="a", authority=dict(AUTH, confidence_is_truth=True), now=21)

    def test_replay_and_ledger_digest(self):
        ledger = RouteReceiptLedger(POLICY)
        first = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        with self.assertRaises(RouteReceiptError): ledger.admit(request(2), current_generation=7, nonce="n1", authority=AUTH, now=22)
        self.assertTrue(first["receipt_digest"].startswith("sha256:")); self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
