import unittest

from faisal_agent_capability_attestation import AgentCapabilityAttestationError, digest
from faisal_agent_capability_possession import (
    AgentCapabilityPossessionLedger,
    AgentCapabilityPossessionPolicy,
    AgentCapabilityPossessionRequest,
)


AUTH = {
    "model_output_is_authority": False,
    "agent_identity_is_execution_authority": False,
    "attestation_is_execution_authority": False,
    "attestation_is_policy_authority": False,
    "workload_selectors_are_hardware_proof": False,
    "production_approval": False,
}
ATTESTATION = digest({"receipt": "bounded-agent-attestation"})
KEY = digest({"jwk": "fixture-key-1"})
TARGET = digest({"method": "POST", "uri": "https://faisal.local/v1/research"})
NONCE = digest({"nonce": "server-nonce-1"})
POLICY = AgentCapabilityPossessionPolicy(
    "possession-policy-1", ATTESTATION, "agent/research-1", KEY,
    frozenset(("research.read", "memory.write")), 11, 100, 400,
)


def request(
    number: int,
    *,
    attestation: str = ATTESTATION,
    agent_id: str = "agent/research-1",
    key: str = KEY,
    capability: str = "research.read",
    request_method: str = "POST",
    target: str = TARGET,
    nonce: str | None = NONCE,
    generation: int = 11,
    issued: int = 120,
    expires: int = 150,
) -> AgentCapabilityPossessionRequest:
    return AgentCapabilityPossessionRequest(
        f"proof-{number}", attestation, agent_id, key, capability, request_method,
        target, nonce, generation, issued, expires,
    )


class AgentCapabilityPossessionTests(unittest.TestCase):
    def present(self, ledger: AgentCapabilityPossessionLedger, value: AgentCapabilityPossessionRequest, **changes):
        values = {
            "expected_method": "POST",
            "expected_target_digest": TARGET,
            "expected_nonce_digest": NONCE,
            "nonce_required": True,
            "current_generation": 11,
            "authority": AUTH,
            "now": 121,
        }
        values.update(changes)
        return ledger.present(value, **values)

    def test_valid_binding_is_non_authoritative(self):
        result = self.present(AgentCapabilityPossessionLedger(POLICY), request(1))
        self.assertEqual(result["status"], "bound")
        self.assertTrue(result["attestation_binding_verified"])
        self.assertTrue(result["key_thumbprint_binding_verified"])
        self.assertTrue(result["request_binding_verified"])
        self.assertTrue(result["nonce_binding_verified"])
        self.assertFalse(result["cryptographic_proof_verified"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["production_approved"])

    def test_binding_and_capability_mismatches_are_denied(self):
        cases = (
            request(1, attestation=digest({"receipt": "other"})),
            request(2, agent_id="agent/other"),
            request(3, key=digest({"jwk": "other"})),
            request(4, capability="network.admin"),
        )
        for value in cases:
            with self.subTest(proof=value.proof_id):
                with self.assertRaises(AgentCapabilityAttestationError):
                    self.present(AgentCapabilityPossessionLedger(POLICY), value)

    def test_request_nonce_generation_and_replay_are_denied(self):
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(1), expected_method="GET")
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(2), expected_target_digest=digest({"uri": "https://faisal.local/other"}))
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(3, nonce=None))
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(4, nonce=digest({"nonce": "other"})))
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(5, generation=12))
        ledger = AgentCapabilityPossessionLedger(POLICY)
        self.present(ledger, request(6))
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(ledger, request(6))

    def test_temporal_authority_and_deterministic_ledger_denials(self):
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(1), now=150)
        with self.assertRaises(AgentCapabilityAttestationError):
            self.present(AgentCapabilityPossessionLedger(POLICY), request(2), authority=dict(AUTH, model_output_is_authority=True))
        ledger = AgentCapabilityPossessionLedger(POLICY)
        self.present(ledger, request(3))
        self.assertTrue(ledger.ledger_digest().startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
