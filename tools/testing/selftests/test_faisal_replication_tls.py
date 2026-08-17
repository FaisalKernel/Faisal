#!/usr/bin/env python3
import hashlib
import sys
import os
import tempfile
import unittest
from concurrent import futures
from pathlib import Path

import grpc

sys.path.insert(0, str(Path(__file__).parents[2] / "faisal-replication"))
import faisal_replication_daemon as daemon
import faisal_replication_pb2 as pb
import faisal_replication_pb2_grpc as pb_grpc
from faisal_replication_providers import (
    Ed25519AttestationVerifier,
    Ed25519RecordSignatureVerifier,
    Ed25519Signer,
    Ed25519TrustStore,
)


class ReplicationTlsIntegrationTest(unittest.TestCase):
    def test_authenticated_vote_and_append_round_trip(self):
        root = Path(os.environ.get("FAISAL_TLS_FIXTURE_DIR", ""))
        required = [root / name for name in ("ca.crt", "server.crt", "server.key", "client.crt", "client.key")]
        if not all(path.exists() for path in required):
            self.skipTest("TLS fixture certificates not generated")
        with tempfile.TemporaryDirectory() as directory:
            config = daemon.ReplicaConfig(7, 1, 3, 2, Path(directory) / "state.json")
            state = daemon.DurableState(config.state_path, 3)
            signer = Ed25519Signer.generate(7, 2, "replica-2-key", 1)
            trust_store = Ed25519TrustStore({(7, 2, "replica-2-key", 1): signer.public_key_bytes()})
            service = daemon.JournalReplicationService(
                config,
                state,
                Ed25519AttestationVerifier(trust_store).verify,
                Ed25519RecordSignatureVerifier(trust_store).verify,
            )
            server, port = daemon.build_server(
                service,
                "127.0.0.1:0",
                (root / "server.key").read_bytes(),
                (root / "server.crt").read_bytes(),
                (root / "ca.crt").read_bytes(),
            )
            server.start()
            try:
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=(root / "ca.crt").read_bytes(),
                    private_key=(root / "client.key").read_bytes(),
                    certificate_chain=(root / "client.crt").read_bytes(),
                )
                channel = grpc.secure_channel(
                    f"127.0.0.1:{port}",
                    credentials,
                    (("grpc.ssl_target_name_override", "replica-1"),),
                )
                stub = pb_grpc.JournalReplicationStub(channel)
                identity = signer.identity(1, 0, b"\x00" * 32)
                vote = stub.RequestVote(pb.VoteRequest(candidate=identity), timeout=3)
                self.assertTrue(vote.granted)
                payload = b"tls-journal-event"
                digest = hashlib.sha256(b"\x00" * 32 + payload).digest()
                unsigned_record = pb.JournalRecord(
                    sequence=1,
                    previous_digest=b"\x00" * 32,
                    record_digest=digest,
                    payload=payload,
                )
                signed_record = pb.JournalRecord(
                    sequence=unsigned_record.sequence,
                    previous_digest=unsigned_record.previous_digest,
                    record_digest=unsigned_record.record_digest,
                    payload=unsigned_record.payload,
                    record_signature=signer.sign_record(identity, unsigned_record),
                )
                append = stub.AppendEntries(
                    pb.AppendRequest(
                        leader=identity,
                        records=[signed_record],
                        leader_commit=1,
                    ),
                    timeout=3,
                )
                self.assertTrue(append.accepted)
                self.assertEqual(append.match_sequence, 1)
                channel.close()
            finally:
                server.stop(0).wait()


if __name__ == "__main__":
    unittest.main()
