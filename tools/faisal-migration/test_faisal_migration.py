#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_migration import MigrationError, MigrationLedger, MigrationPolicy, MigrationRequest, ReadinessEvidence, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "source_agent_card_is_authority": False,
    "destination_agent_card_is_authority": False,
    "readiness_evidence_is_hardware_qualification": False,
    "migration_receipt_is_execution_authority": False,
    "state_manifest_is_trust_root": False,
}


def request(migration_id: str = "m-1", *, generation: int = 4, destination: str = "node-b", destination_capabilities=frozenset({"cpu", "memory"}), expires: int = 300, readiness: ReadinessEvidence | None = None) -> MigrationRequest:
    readiness = readiness or ReadinessEvidence(True, True, False, True, True, digest({"readiness": migration_id}))
    return MigrationRequest(
        migration_id, "node-a", destination, "objective-1", "task-1", generation,
        digest({"lifecycle": migration_id}), digest({"checkpoint": migration_id}), digest({"trace": migration_id}),
        digest({"state": migration_id}), digest({"artifact": migration_id}), 7,
        frozenset({"cpu", "memory", "network"}), frozenset(destination_capabilities), readiness,
        f"idem-{migration_id}", digest({"rollback": migration_id}), 100, expires,
    )


def ledger() -> MigrationLedger:
    policy = MigrationPolicy(frozenset({"node-b", "node-c"}), frozenset({"cpu", "memory"}), frozenset({"network_path_ready", "storage_ready", "sandbox_ready", "observability_ready"}), 300)
    return MigrationLedger(generation=4, policy=policy)


class MigrationTests(unittest.TestCase):
    def test_prepare_commit_valid_and_non_execution(self) -> None:
        l = ledger()
        req = request()
        prepared = l.prepare(req, now=110, authority_boundary=AUTHORITY)
        self.assertTrue(prepared["admitted"])
        self.assertFalse(prepared["migration_executed"])
        committed = l.commit("m-1", destination_state_digest=digest({"dest": "state"}), destination_checkpoint_digest=digest({"dest": "checkpoint"}), destination_trace_digest=digest({"dest": "trace"}), now=120, authority_boundary=AUTHORITY)
        self.assertEqual(committed["phase"], "committed")
        self.assertFalse(committed["migration_executed"])

    def test_capability_attenuation_and_readiness(self) -> None:
        l = ledger()
        with self.assertRaises(MigrationError):
            l.prepare(request("bad-cap", destination_capabilities=frozenset({"cpu", "memory", "admin"})), now=110, authority_boundary=AUTHORITY)
        bad_readiness = ReadinessEvidence(False, True, False, True, True, digest({"bad": True}))
        with self.assertRaises(MigrationError):
            l.prepare(request("bad-ready", readiness=bad_readiness), now=110, authority_boundary=AUTHORITY)

    def test_destination_and_source_fences(self) -> None:
        l = ledger()
        with self.assertRaises(MigrationError):
            l.prepare(request("bad-destination", destination="node-z"), now=110, authority_boundary=AUTHORITY)
        with self.assertRaises(MigrationError):
            l.prepare(request("same", destination="node-a"), now=110, authority_boundary=AUTHORITY)

    def test_generation_expiry_and_rollback_fences(self) -> None:
        l = ledger()
        with self.assertRaises(MigrationError):
            l.prepare(request("stale", generation=5), now=110, authority_boundary=AUTHORITY)
        with self.assertRaises(MigrationError):
            l.prepare(request("expired", expires=100), now=110, authority_boundary=AUTHORITY)
        req = request("late", expires=300)
        l.prepare(req, now=110, authority_boundary=AUTHORITY)
        with self.assertRaises(MigrationError):
            l.commit("late", destination_state_digest=digest({"dest": "state"}), destination_checkpoint_digest=digest({"dest": "checkpoint"}), destination_trace_digest=digest({"dest": "trace"}), now=301, authority_boundary=AUTHORITY)

    def test_replay_idempotency_and_unknown_commit(self) -> None:
        l = ledger()
        req = request()
        l.prepare(req, now=110, authority_boundary=AUTHORITY)
        with self.assertRaises(MigrationError):
            l.prepare(req, now=111, authority_boundary=AUTHORITY)
        l.commit("m-1", destination_state_digest=digest({"dest": "state"}), destination_checkpoint_digest=digest({"dest": "checkpoint"}), destination_trace_digest=digest({"dest": "trace"}), now=120, authority_boundary=AUTHORITY)
        with self.assertRaises(MigrationError):
            l.commit("m-1", destination_state_digest=digest({"dest": "state2"}), destination_checkpoint_digest=digest({"dest": "checkpoint2"}), destination_trace_digest=digest({"dest": "trace2"}), now=121, authority_boundary=AUTHORITY)

    def test_request_and_receipt_tamper_detection_and_authority(self) -> None:
        req = request()
        original_digest = req.request_digest
        altered = copy.copy(req)
        object.__setattr__(altered, "artifact_digest", digest({"artifact": "tampered"}))
        self.assertNotEqual(original_digest, altered.request_digest)
        bad_authority = dict(AUTHORITY, migration_receipt_is_execution_authority=True)
        with self.assertRaises(MigrationError):
            ledger().prepare(req, now=110, authority_boundary=bad_authority)


if __name__ == "__main__":
    unittest.main(verbosity=2)
