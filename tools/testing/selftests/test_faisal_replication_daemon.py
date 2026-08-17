#!/usr/bin/env python3
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "faisal-replication"))

import faisal_replication_daemon as daemon
import faisal_replication_pb2 as pb


class Context:
    def __init__(self, replica_id):
        self.replica_id = replica_id
        self.code = None
        self.details = None

    def auth_context(self):
        return {"x509_common_name": [f"replica-{self.replica_id}".encode()]}

    def set_code(self, code):
        self.code = code

    def set_details(self, details):
        self.details = details


class ReplicationDaemonTest(unittest.TestCase):
    def make_service(self, root, verify_attestation=True, verify_record=True):
        config = daemon.ReplicaConfig(7, 1, 3, 2, root / "state.json")
        state = daemon.DurableState(config.state_path, config.replica_count)
        service = daemon.JournalReplicationService(
            config,
            state,
            lambda _identity: verify_attestation,
            lambda _identity, _record: verify_record,
        )
        return service

    def identity(self, replica_id=2, term=1, sequence=0, digest=b"\x00" * 32):
        return pb.JournalIdentity(
            cluster_id=7,
            replica_id=replica_id,
            term=term,
            last_sequence=sequence,
            chain_digest=digest,
            attestation_signature=b"attested",
            key_id="test-key",
            key_generation=1,
        )

    def record(self, sequence, previous, payload):
        digest = hashlib.sha256(previous + payload).digest()
        return pb.JournalRecord(
            sequence=sequence,
            previous_digest=previous,
            record_digest=digest,
            payload=payload,
            record_signature=b"signed-record",
        )

    def test_vote_persists_and_restores(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = self.make_service(root)
            response = service.RequestVote(pb.VoteRequest(candidate=self.identity()), Context(2))
            self.assertTrue(response.granted)
            restored = daemon.DurableState(root / "state.json", 3)
            restored.load()
            self.assertEqual(restored.term, 1)
            self.assertEqual(restored.voted_for, 2)
            self.assertEqual(restored.generation, 2)

    def test_certificate_identity_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.make_service(Path(directory))
            response = service.RequestVote(pb.VoteRequest(candidate=self.identity()), Context(3))
            self.assertFalse(response.granted)
            self.assertEqual(response.denial_reason, "tls-replica-identity-mismatch")

    def test_valid_append_is_durable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = self.make_service(root)
            request = pb.AppendRequest(
                leader=self.identity(),
                records=[self.record(1, b"\x00" * 32, b"journal-event")],
                leader_commit=1,
            )
            response = service.AppendEntries(request, Context(2))
            self.assertTrue(response.accepted)
            self.assertEqual(response.match_sequence, 1)
            restored = daemon.DurableState(root / "state.json", 3)
            restored.load()
            self.assertEqual(restored.last_sequence, 1)
            self.assertEqual(restored.commit_sequence, 1)

    def test_invalid_chain_is_denied_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.make_service(Path(directory))
            invalid = pb.JournalRecord(
                sequence=1,
                previous_digest=b"bad",
                record_digest=b"x" * 32,
                payload=b"event",
                record_signature=b"signed-record",
            )
            response = service.AppendEntries(
                pb.AppendRequest(leader=self.identity(), records=[invalid]), Context(2)
            )
            self.assertFalse(response.accepted)
            self.assertEqual(response.denial_reason, "previous-digest-mismatch")
            self.assertEqual(service.state.last_sequence, 0)

    def test_corrupt_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text('{"state":{},"checksum":"wrong"}')
            state = daemon.DurableState(path, 3)
            with self.assertRaises(daemon.ReplicationError):
                state.load()

    def test_missing_verification_callback_denies_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            service = self.make_service(Path(directory), verify_attestation=False)
            response = service.RequestVote(pb.VoteRequest(candidate=self.identity()), Context(2))
            self.assertFalse(response.granted)
            self.assertEqual(response.denial_reason, "attestation-verification-failed")


if __name__ == "__main__":
    unittest.main()
