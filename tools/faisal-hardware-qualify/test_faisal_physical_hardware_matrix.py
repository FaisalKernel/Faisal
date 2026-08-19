#!/usr/bin/env python3
from __future__ import annotations

import unittest
from faisal_physical_hardware_matrix import (
    AUTHORITY_KEYS, CAPABILITIES, REQUIRED_TESTS, HardwareEvidence, HardwareMatrixError,
    HardwareMatrixLedger, MatrixPolicy, digest, observation_status,
)

AUTH = {key: False for key in AUTHORITY_KEYS}
POLICY = MatrixPolicy(
    "matrix-1", "FAISAL-HARDWARE-TEST", "a" * 40, digest({"bzImage": "fixture"}),
    CAPABILITIES, REQUIRED_TESTS, 1, 10, 100, "independent-observer-1"
)


def evidence(capability: str, origin: str = "external_reference", index: int = 1, **overrides) -> HardwareEvidence:
    values = dict(
        evidence_id=f"evidence-{capability}", capability=capability, origin=origin,
        release_tag=POLICY.release_tag, release_head=POLICY.release_head, artifact_digest=POLICY.artifact_digest,
        device_identity={"model": f"fixture-{capability}", "pci_bdf": f"0000:00:{index:02x}.0", "serial": f"serial-{capability}"},
        firmware_digest=digest({"firmware": capability}), driver_digest=digest({"driver": capability}),
        topology_digest=digest({"topology": capability}),
        test_results={test: "pass" for test in REQUIRED_TESTS}, benchmark_digest=digest({"benchmark": capability}),
        fault_recovery_digest=digest({"recovery": capability}), external_report_digest=digest({"report": capability}),
        verification_reference=f"external-verifier-{capability}", observed_at=20, expires_at=90,
        nonce=f"nonce-{capability}", synthetic_fixture=True,
    )
    values.update(overrides)
    return HardwareEvidence(**values)


class PhysicalHardwareMatrixTests(unittest.TestCase):
    def test_complete_external_matrix_is_structural_only_not_physical_approval(self):
        ledger = HardwareMatrixLedger(POLICY)
        for sequence, capability in enumerate(CAPABILITIES, 1):
            item = evidence(capability, index=sequence)
            ledger.record(item, sequence, item.nonce, 21, AUTH)
        status = ledger.status(21, AUTH)
        self.assertTrue(status["structurally_complete"])
        self.assertTrue(status["external_hardware_evidence_structurally_complete"])
        self.assertFalse(status["physical_qualification_completed"])
        self.assertFalse(status["production_approval"])
        self.assertIn("independent_physical_execution_and_review", status["blockers"])

    def test_host_observation_never_satisfies_external_matrix(self):
        observation = {"devices": {capability: {"state": "present"} for capability in CAPABILITIES}}
        status = observation_status(POLICY, observation, 21)
        self.assertFalse(status["structurally_complete"])
        self.assertFalse(status["external_hardware_evidence_structurally_complete"])
        self.assertFalse(status["physical_qualification_completed"])
        self.assertFalse(status["production_approval"])

    def test_manifest_test_digest_and_authority_denials(self):
        ledger = HardwareMatrixLedger(POLICY)
        with self.assertRaises(HardwareMatrixError):
            ledger.record(evidence("gpu", release_head="b" * 40), 1, "nonce-gpu", 21, AUTH)
        with self.assertRaises(HardwareMatrixError):
            ledger.record(evidence("gpu", test_results={"enumeration": "pass"}), 1, "nonce-gpu", 21, AUTH)
        with self.assertRaises(HardwareMatrixError):
            ledger.record(evidence("gpu"), 1, "nonce-gpu", 21, dict(AUTH, production_approval=True))

    def test_sequence_replay_and_missing_capability_are_denied(self):
        ledger = HardwareMatrixLedger(POLICY)
        first = evidence("gpu")
        ledger.record(first, 1, first.nonce, 21, AUTH)
        with self.assertRaises(HardwareMatrixError):
            ledger.record(evidence("npu", nonce=first.nonce), 2, first.nonce, 21, AUTH)
        with self.assertRaises(HardwareMatrixError):
            ledger.record(evidence("npu"), 3, "nonce-npu-gap", 21, AUTH)
        status = ledger.status(21, AUTH)
        self.assertIn("npu", status["missing_capabilities"])
        self.assertFalse(status["structurally_complete"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
