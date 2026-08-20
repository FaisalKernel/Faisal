import unittest

from faisal_agent_capability_attestation import (
    AgentCapabilityAttestationError,
    AgentCapabilityAttestationLedger,
    AgentCapabilityPolicy,
    AgentCapabilityRequest,
    digest,
)


AUTH = {
    "model_output_is_authority": False,
    "agent_identity_is_execution_authority": False,
    "attestation_is_execution_authority": False,
    "attestation_is_policy_authority": False,
    "workload_selectors_are_hardware_proof": False,
    "production_approval": False,
}
PARENT = digest({"operator": "release-supervisor", "lease": 9})
SELECTORS = digest({"uid": 4242, "cgroup": "agent.slice", "image": "sha256:fixture"})
PURPOSE = digest({"objective": "bounded research", "task": "source review"})
POLICY = AgentCapabilityPolicy(
    "agent-policy-1", "faisal.local", "agent/research-1", "ephemeral", "agent/orchestrator-1",
    PARENT, SELECTORS, PURPOSE, frozenset(("research.read", "memory.write")), 2, 11, 100, 400,
)


def request(
    number: int,
    *,
    agent_id: str = "agent/research-1",
    agent_kind: str = "ephemeral",
    parent: str = "agent/orchestrator-1",
    parent_digest: str = PARENT,
    selectors: str = SELECTORS,
    purpose: str = PURPOSE,
    caps: frozenset[str] = frozenset(("research.read",)),
    depth: int = 1,
    generation: int = 11,
    issued: int = 120,
) -> AgentCapabilityRequest:
    return AgentCapabilityRequest(
        f"request-{number}", agent_id, agent_kind, parent, parent_digest, selectors, purpose,
        caps, depth, generation, issued,
    )


class AgentCapabilityAttestationTests(unittest.TestCase):
    def test_valid_attestation_is_non_authoritative(self):
        result = AgentCapabilityAttestationLedger(POLICY).attest(request(1), current_generation=11, nonce="n1", authority=AUTH, now=121)
        self.assertEqual(result["status"], "attested")
        self.assertTrue(result["identity_verified"])
        self.assertTrue(result["parentage_verified"])
        self.assertTrue(result["capability_attenuation_verified"])
        self.assertFalse(result["credential_issued"])
        self.assertFalse(result["execution_performed"])
        self.assertFalse(result["production_approved"])

    def test_identity_parent_selector_purpose_and_capability_denials(self):
        cases = (
            request(1, agent_id="agent/other"),
            request(2, parent="agent/other-parent"),
            request(3, selectors=digest({"uid": 999})),
            request(4, purpose=digest({"objective": "different"})),
            request(5, caps=frozenset(("research.read", "network.admin"))),
        )
        for value in cases:
            with self.subTest(request=value.request_id):
                with self.assertRaises(AgentCapabilityAttestationError):
                    AgentCapabilityAttestationLedger(POLICY).attest(value, current_generation=11, nonce=value.request_id, authority=AUTH, now=121)

    def test_replay_generation_depth_and_authority_denials(self):
        ledger = AgentCapabilityAttestationLedger(POLICY)
        ledger.attest(request(1), current_generation=11, nonce="once", authority=AUTH, now=121)
        with self.assertRaises(AgentCapabilityAttestationError):
            ledger.attest(request(2), current_generation=11, nonce="once", authority=AUTH, now=122)
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityAttestationLedger(POLICY).attest(request(3, generation=12), current_generation=11, nonce="g", authority=AUTH, now=121)
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityAttestationLedger(POLICY).attest(request(4, depth=3), current_generation=11, nonce="d", authority=AUTH, now=121)
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityAttestationLedger(POLICY).attest(request(5), current_generation=11, nonce="a", authority=dict(AUTH, model_output_is_authority=True), now=121)

    def test_expiry_and_deterministic_ledger_digest(self):
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityAttestationLedger(POLICY).attest(request(1), current_generation=11, nonce="expired", authority=AUTH, now=400)
        self.assertTrue(AgentCapabilityAttestationLedger(POLICY).ledger_digest().startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
