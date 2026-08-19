#!/usr/bin/env python3
from __future__ import annotations

import unittest
from faisal_multihost_qualify import (
    REQUIRED_BOUNDARIES, REQUIRED_FAULTS, REQUIRED_WORKLOADS, MultihostEvidence, MultihostLedger, MultihostPolicy, MultihostQualificationError, digest, local_single_host_status,
)

AUTH = {key: False for key in REQUIRED_BOUNDARIES}
POLICY = MultihostPolicy("multi-1", "FAISAL-MULTIHOST-TEST", "a" * 40, digest({"artifact": "fixture"}), "topology-3-node", 3, 2, REQUIRED_WORKLOADS, REQUIRED_FAULTS, "mTLS-quorum-transport", 1, 10, 100, "cluster-registry-1")

def evidence(origin="synthetic_fixture", **overrides):
    nodes = tuple({"node_id": f"node-{i}", "endpoint_reference": f"endpoint-{i}", "identity_digest": digest({"node": i}), "kernel_digest": digest({"kernel": i}), "artifact_digest": POLICY.artifact_digest, "transport_identity": f"transport-node-{i}", "clock_state": "synchronized"} for i in range(3))
    values = dict(evidence_id="multi-evidence", origin=origin, release_tag=POLICY.release_tag, release_head=POLICY.release_head, artifact_digest=POLICY.artifact_digest, topology_id=POLICY.topology_id, transport_id=POLICY.transport_id, node_records=nodes, workload_results={key: "pass" for key in REQUIRED_WORKLOADS}, fault_results={key: "pass" for key in REQUIRED_FAULTS}, quorum_observed=3, transport_evidence_digest=digest({"transport": 1}), workload_trace_digest=digest({"trace": 1}), output_digest=digest({"output": 1}), checkpoint_digest=digest({"checkpoint": 1}), recovery_digest=digest({"recovery": 1}), migration_digest=digest({"migration": 1}), cluster_report_digest=digest({"report": 1}), verification_reference="verifier-1", observed_at=20, expires_at=90, nonce="nonce-1", synthetic_fixture=True)
    values.update(overrides)
    return MultihostEvidence(**values)

class MultihostTests(unittest.TestCase):
    def test_complete_external_workload_fixture_is_structural_only(self):
        ledger = MultihostLedger(POLICY); item = evidence("live_external"); ledger.record(item, 1, item.nonce, 21, AUTH); status = ledger.status(21, AUTH)
        self.assertTrue(status["structurally_complete"])
        self.assertTrue(status["external_multihost_evidence_structurally_complete"])
        self.assertFalse(status["live_multihost_qualification_completed"])
        self.assertFalse(status["distributed_workloads_executed_live"])
        self.assertFalse(status["production_approval"])

    def test_local_single_host_never_counts_as_multihost(self):
        status = local_single_host_status(POLICY, 21)
        self.assertFalse(status["external_multihost_evidence_structurally_complete"])
        self.assertFalse(status["live_multihost_qualification_completed"])
        self.assertIn("required_node_count", status["blockers"])

    def test_node_quorum_transport_and_workload_denials(self):
        with self.assertRaises(MultihostQualificationError):
            MultihostLedger(POLICY).record(evidence(node_records=evidence().node_records[:2]), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(MultihostQualificationError):
            MultihostLedger(POLICY).record(evidence(quorum_observed=1), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(MultihostQualificationError):
            MultihostLedger(POLICY).record(evidence(workload_results={"agent_coordination": "pass"}), 1, "nonce-1", 21, AUTH)

    def test_binding_replay_and_authority_denials(self):
        ledger = MultihostLedger(POLICY); first = evidence(); ledger.record(first, 1, first.nonce, 21, AUTH)
        with self.assertRaises(MultihostQualificationError):
            ledger.record(evidence(evidence_id="second", nonce=first.nonce), 2, first.nonce, 21, AUTH)
        with self.assertRaises(MultihostQualificationError):
            MultihostLedger(POLICY).record(evidence(release_head="b" * 40), 1, "nonce-1", 21, AUTH)
        with self.assertRaises(MultihostQualificationError):
            MultihostLedger(POLICY).record(evidence(), 1, "nonce-1", 21, dict(AUTH, production_approval=True))

if __name__ == "__main__":
    unittest.main(verbosity=2)
