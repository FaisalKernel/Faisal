import unittest
from faisal_tool_attestation import ToolAttestationError, ToolAttestationLedger, ToolCallRequest, ToolPolicy, digest

AUTH = {"model_output_is_authority": False, "tool_metadata_is_authority": False, "tool_result_is_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "production_approval": False}
DEFINITION = digest({"tool": "browser.click", "version": 3})
DEPENDENCY = digest({"deps": ["playwright"]})
POLICY = ToolPolicy("p1", "browser-server", "browser.click", DEFINITION, DEPENDENCY, (1, 4, 0), frozenset(("browser.read", "browser.click")), 2, 2, 7, 10, 100, True)

def request(i, definition=DEFINITION, dependency=DEPENDENCY, version=(1, 4, 1), scopes=frozenset(("browser.read", "browser.click")), labels=(("target", 1),), confirmed=True, generation=7, issued=20):
    return ToolCallRequest(f"r-{i}", "browser-server", "browser.click", definition, dependency, version, scopes, labels, confirmed, generation, issued)

class ToolAttestationTests(unittest.TestCase):
    def test_valid_admission(self):
        result = ToolAttestationLedger(POLICY).admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertEqual(result["status"], "admitted")
        self.assertTrue(result["definition_verified"]); self.assertTrue(result["dependency_verified"]); self.assertTrue(result["scope_verified"]); self.assertTrue(result["data_flow_verified"])
        self.assertFalse(result["tool_invoked"]); self.assertFalse(result["production_approved"])

    def test_drift_version_scope_dataflow_confirmation_denials(self):
        cases = [
            ("definition", request(1, definition=digest({"tool": "changed"})), "d1"),
            ("dependency", request(2, dependency=digest({"deps": ["bad"]})), "d2"),
            ("version", request(3, version=(1, 3, 9)), "v"),
            ("scope", request(4, scopes=frozenset(("browser.read",))), "s"),
            ("dataflow", request(5, labels=(("target", 3),)), "f"),
            ("confirmation", request(6, confirmed=False), "c"),
        ]
        for name, req, nonce in cases:
            with self.subTest(name=name), self.assertRaises(ToolAttestationError):
                ToolAttestationLedger(POLICY).admit(req, current_generation=7, nonce=nonce, authority=AUTH, now=21)

    def test_replay_authority_identity_and_generation_denials(self):
        ledger = ToolAttestationLedger(POLICY)
        first = ledger.admit(request(1), current_generation=7, nonce="n1", authority=AUTH, now=21)
        self.assertTrue(first["receipt_digest"].startswith("sha256:"))
        with self.assertRaises(ToolAttestationError): ledger.admit(request(2), current_generation=7, nonce="n1", authority=AUTH, now=22)
        with self.assertRaises(ToolAttestationError): ledger.admit(request(2, generation=8), current_generation=7, nonce="n2", authority=AUTH, now=22)
        with self.assertRaises(ToolAttestationError):
            ledger.admit(ToolCallRequest("r-2", "other-server", "browser.click", DEFINITION, DEPENDENCY, (1,4,1), frozenset(("browser.read", "browser.click")), (("target", 1),), True, 7, 20), current_generation=7, nonce="n3", authority=AUTH, now=22)
        with self.assertRaises(ToolAttestationError): ledger.admit(request(2), current_generation=7, nonce="n4", authority=dict(AUTH, tool_metadata_is_authority=True), now=22)

    def test_expired_policy_and_digest(self):
        expired = ToolPolicy("expired", "browser-server", "browser.click", DEFINITION, DEPENDENCY, (1,0,0), frozenset(("browser.read",)), 2, 2, 7, 10, 20, False)
        with self.assertRaises(ToolAttestationError): ToolAttestationLedger(expired).admit(request(1, scopes=frozenset(("browser.read",)), confirmed=False), current_generation=7, nonce="x", authority=AUTH, now=20)
        self.assertTrue(ToolAttestationLedger(POLICY).ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
