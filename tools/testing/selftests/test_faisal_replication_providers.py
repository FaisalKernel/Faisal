#!/usr/bin/env python3
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "faisal-replication"))

import faisal_replication_pb2 as pb
import faisal_replication_daemon as daemon
from faisal_replication_providers import (
    Ed25519AttestationVerifier,
    Ed25519QuorumCertificateVerifier,
    Ed25519RecordSignatureVerifier,
    Ed25519Signer,
    Ed25519TrustStore,
)


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


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519Signer.generate(7, 2, "replica-2-key", 4)
        self.voter = Ed25519Signer.generate(7, 1, "replica-1-key", 4)
        self.store = Ed25519TrustStore({
            (7, 2, "replica-2-key", 4): self.signer.public_key_bytes(),
            (7, 1, "replica-1-key", 4): self.voter.public_key_bytes(),
        })
        self.attestation = Ed25519AttestationVerifier(self.store)
        self.records = Ed25519RecordSignatureVerifier(self.store)

    def identity(self):
        return self.signer.identity(3, 0, b"\x00" * 32)

    def record(self, identity):
        payload = b"trusted-event"
        digest = hashlib.sha256(b"\x00" * 32 + payload).digest()
        unsigned = pb.JournalRecord(
            sequence=1,
            previous_digest=b"\x00" * 32,
            record_digest=digest,
            payload=payload,
        )
        return pb.JournalRecord(
            sequence=unsigned.sequence,
            previous_digest=unsigned.previous_digest,
            record_digest=unsigned.record_digest,
            payload=unsigned.payload,
            record_signature=self.signer.sign_record(identity, unsigned),
        )

    def test_valid_attestation_and_record(self):
        identity = self.identity()
        record = self.record(identity)
        self.assertTrue(self.attestation.verify(identity))
        self.assertTrue(self.records.verify(identity, record))

    def test_tampered_identity_and_record_denied(self):
        identity = self.identity()
        record = self.record(identity)
        identity.term = 4
        self.assertFalse(self.attestation.verify(identity))
        record.payload = b"tampered"
        self.assertFalse(self.records.verify(self.identity(), record))

    def test_unknown_key_and_generation_denied(self):
        identity = self.identity()
        identity.key_generation = 5
        self.assertFalse(self.attestation.verify(identity))
        unknown = pb.JournalIdentity()
        unknown.CopyFrom(self.identity())
        unknown.key_id = "unknown"
        self.assertFalse(self.attestation.verify(unknown))

    def test_daemon_accepts_only_trusted_provider_signatures(self):
        identity = self.identity()
        record = self.record(identity)
        with tempfile.TemporaryDirectory() as directory:
            config = daemon.ReplicaConfig(7, 1, 3, 2, Path(directory) / "state.json")
            service = daemon.JournalReplicationService(
                config,
                daemon.DurableState(config.state_path, 3),
                self.attestation.verify,
                self.records.verify,
                quorum_verifier=Ed25519QuorumCertificateVerifier(self.store, 2, 3).verify,
            )
            vote = service.RequestVote(pb.VoteRequest(candidate=identity), Context(2))
            self.assertTrue(vote.granted)
            append_identity = self.signer.identity(3, 1, record.record_digest)
            certificate = pb.QuorumCertificate(
                cluster_id=7,
                leader_replica_id=2,
                term=3,
                commit_sequence=1,
                commit_digest=record.record_digest,
                votes=[],
            )
            certificate.votes.extend([
                self.signer.sign_quorum_vote(2, 3, 1, record.record_digest),
                self.voter.sign_quorum_vote(2, 3, 1, record.record_digest),
            ])
            response = service.AppendEntries(
                pb.AppendRequest(leader=append_identity, records=[record], leader_commit=1, quorum_certificate=certificate),
                Context(2),
            )
            self.assertTrue(response.accepted)

    def test_malformed_signature_length_denied(self):
        identity = self.identity()
        identity.attestation_signature = b"short"
        self.assertFalse(self.attestation.verify(identity))


if __name__ == "__main__":
    unittest.main()
