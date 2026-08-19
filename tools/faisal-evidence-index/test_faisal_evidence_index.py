#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from faisal_evidence_index import EvidenceIndexError, EvidenceIndexLedger, EvidenceIndexPolicy, build_snapshot, digest, verify_snapshot


def fixture(root: Path, head: str = "a" * 40):
    artifact = "b" * 64
    evidence_path = root / "tools/faisal-build/evidence/frontier-signing-ceremony-validation.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps({"record_digest": "sha256:fixture", "boundary": {"production_approval": False}, "security_boundaries": {"production_approval": False}}, sort_keys=True))
    manifest = {"repository_head": head, "artifact": {"bzImage_sha256": artifact}, "evidence_index": [{"path": str(evidence_path.relative_to(root)), "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest()}], "release_blockers": ["external"]}
    policy = EvidenceIndexPolicy("FAISAL-TEST", head, "sha256:" + artifact, 10, 100, ("operator_signing", "physical_hardware"))
    return manifest, policy, evidence_path


class EvidenceIndexTests(unittest.TestCase):
    def test_deterministic_snapshot_is_locally_verified_but_not_authoritative(self):
        with tempfile.TemporaryDirectory() as work:
            manifest, policy, _ = fixture(Path(work))
            first = build_snapshot(Path(work), manifest, policy, 20)
            second = build_snapshot(Path(work), manifest, policy, 20)
            self.assertEqual(first["snapshot_digest"], second["snapshot_digest"])
            self.assertTrue(first["state"]["local_index_verified"])
            self.assertFalse(first["state"]["production_ready"])
            self.assertFalse(first["state"]["production_approval"])
            self.assertTrue(verify_snapshot(first, policy, 20))

    def test_tamper_manifest_or_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); manifest, policy, evidence = fixture(root)
            evidence.write_text("tampered")
            with self.assertRaises(EvidenceIndexError): build_snapshot(root, manifest, policy, 20)
            manifest, policy, _ = fixture(root, "c" * 40)
            with self.assertRaises(EvidenceIndexError): build_snapshot(root, manifest, EvidenceIndexPolicy("FAISAL-TEST", "a" * 40, policy.artifact_digest, 10, 100, policy.required_external_categories), 20)

    def test_replay_and_authority_violations_are_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); manifest, policy, _ = fixture(root); snapshot = build_snapshot(root, manifest, policy, 20); ledger = EvidenceIndexLedger(policy)
            authority = {"model_output_is_authority": False, "evidence_receipt_is_production_authority": False, "production_approval": False}
            ledger.record(snapshot, "nonce-1", 1, 20, authority)
            with self.assertRaises(EvidenceIndexError): ledger.record(snapshot, "nonce-2", 2, 20, authority)
            with self.assertRaises(EvidenceIndexError): EvidenceIndexLedger(policy).record(snapshot, "nonce-3", 1, 20, {**authority, "production_approval": True})

    def test_snapshot_digest_and_production_claim_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work); manifest, policy, _ = fixture(root); snapshot = build_snapshot(root, manifest, policy, 20)
            snapshot["state"]["production_approval"] = True
            with self.assertRaises(EvidenceIndexError): verify_snapshot(snapshot, policy, 20)
            snapshot = build_snapshot(root, manifest, policy, 20); snapshot["snapshot_digest"] = digest({"wrong": True})
            with self.assertRaises(EvidenceIndexError): verify_snapshot(snapshot, policy, 20)


if __name__ == "__main__":
    unittest.main(verbosity=2)
