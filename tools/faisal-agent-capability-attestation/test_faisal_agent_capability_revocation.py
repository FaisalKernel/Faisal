import unittest

from faisal_agent_capability_attestation import AgentCapabilityAttestationError, digest
from faisal_agent_capability_revocation import AgentCapabilityRevocationLedger, AgentCapabilityRevocationPolicy, AgentCapabilityRevocationSnapshot

AUTH = {"model_output_is_authority": False, "agent_identity_is_execution_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "workload_selectors_are_hardware_proof": False, "production_approval": False}
RECEIPT = digest({"receipt": "possession-1"})
POLICY = AgentCapabilityRevocationPolicy("revocation-policy", "agent/research-1", frozenset(("research.read",)), 3)

def snapshot(epoch=3, revoked=frozenset(), issued=100, expires=200, complete=True):
    return AgentCapabilityRevocationSnapshot(f"snapshot-{epoch}", epoch, issued, expires, complete, revoked)

class AgentCapabilityRevocationTests(unittest.TestCase):
    def test_complete_fresh_snapshot_allows_non_authoritative_active_decision(self):
        ledger = AgentCapabilityRevocationLedger(POLICY)
        installed = ledger.install(snapshot(), authority=AUTH, now=120)
        result = ledger.evaluate(RECEIPT, agent_id="agent/research-1", capability="research.read", required_epoch=3, authority=AUTH, now=121)
        self.assertTrue(installed["complete_snapshot_verified"])
        self.assertEqual(result["status"], "active")
        self.assertTrue(result["revocation_checked"])
        self.assertFalse(result["revocation_source_authenticated"])
        self.assertFalse(result["execution_performed"])

    def test_revoked_incomplete_stale_and_epoch_regression_are_denied(self):
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityRevocationLedger(POLICY).install(snapshot(complete=False), authority=AUTH, now=120)
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityRevocationLedger(POLICY).install(snapshot(issued=100, expires=120), authority=AUTH, now=120)
        ledger = AgentCapabilityRevocationLedger(POLICY)
        ledger.install(snapshot(), authority=AUTH, now=120)
        with self.assertRaises(AgentCapabilityAttestationError):
            ledger.install(snapshot(), authority=AUTH, now=121)
        with self.assertRaises(AgentCapabilityAttestationError):
            AgentCapabilityRevocationLedger(POLICY).install(snapshot(2), authority=AUTH, now=120)
        revoked = AgentCapabilityRevocationLedger(POLICY)
        revoked.install(snapshot(revoked=frozenset((RECEIPT,))), authority=AUTH, now=120)
        with self.assertRaises(AgentCapabilityAttestationError):
            revoked.evaluate(RECEIPT, agent_id="agent/research-1", capability="research.read", required_epoch=3, authority=AUTH, now=121)

    def test_missing_epoch_identity_capability_and_authority_are_denied(self):
        ledger = AgentCapabilityRevocationLedger(POLICY)
        with self.assertRaises(AgentCapabilityAttestationError):
            ledger.evaluate(RECEIPT, agent_id="agent/research-1", capability="research.read", required_epoch=3, authority=AUTH, now=121)
        ledger.install(snapshot(), authority=AUTH, now=120)
        for kwargs in ({"required_epoch": 4}, {"agent_id": "agent/other"}, {"capability": "network.admin"}, {"authority": dict(AUTH, model_output_is_authority=True)}):
            values = {"agent_id": "agent/research-1", "capability": "research.read", "required_epoch": 3, "authority": AUTH, "now": 121}
            values.update(kwargs)
            with self.assertRaises(AgentCapabilityAttestationError):
                ledger.evaluate(RECEIPT, **values)
        self.assertTrue(ledger.ledger_digest().startswith("sha256:"))

if __name__ == "__main__":
    unittest.main()
