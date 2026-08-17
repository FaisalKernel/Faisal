#!/usr/bin/env python3
"""Fail-closed gRPC/TLS runtime for FAISAL journal replication.

This service is deliberately a transport and enforcement boundary. It does not
interpret model output, generate authority, or silently accept unsigned state.
Signature and attestation verification callbacks are mandatory for accepting
votes or journal records.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import threading
from concurrent import futures
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import grpc

import faisal_replication_pb2 as pb
import faisal_replication_pb2_grpc as pb_grpc
from faisal_replication_providers import (
    Ed25519AttestationVerifier,
    Ed25519QuorumCertificateVerifier,
    Ed25519RecordSignatureVerifier,
    Ed25519TrustStore,
    KmsTrustKeyRotationController,
    load_public_key_bytes,
)


MAX_RECORDS_PER_APPEND = 1024
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_CHAIN_DIGEST_BYTES = 32
_REPLICA_CN = re.compile(r"^replica-([1-9][0-9]*)$")


class ReplicationError(RuntimeError):
    """Raised for fail-closed state or persistence failures."""


@dataclass(frozen=True)
class ReplicaConfig:
    cluster_id: int
    replica_id: int
    replica_count: int
    quorum_size: int
    state_path: Path

    def validate(self) -> None:
        if self.cluster_id <= 0 or self.replica_id <= 0:
            raise ValueError("cluster and replica IDs must be positive")
        if not 1 <= self.replica_id <= self.replica_count <= 64:
            raise ValueError("replica ID/count outside bounded range")
        if not self.replica_count // 2 < self.quorum_size <= self.replica_count:
            raise ValueError("quorum must be a strict majority")


class DurableState:
    """Atomic, checksummed local state for term/vote/journal commit metadata."""

    def __init__(self, path: Path, replica_count: int):
        self.path = Path(path)
        self.replica_count = replica_count
        self.lock = threading.RLock()
        self.term = 0
        self.voted_for = 0
        self.generation = 0
        self.last_sequence = 0
        self.chain_digest = b"\x00" * 32
        self.commit_sequence = 0
        self.commit_digest = b"\x00" * 32
        self.records: list[dict[str, str | int]] = []

    @staticmethod
    def _checksum(state: dict) -> str:
        body = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(body).hexdigest()

    def _payload(self) -> dict:
        return {
            "version": 1,
            "term": self.term,
            "voted_for": self.voted_for,
            "generation": self.generation,
            "last_sequence": self.last_sequence,
            "chain_digest": self.chain_digest.hex(),
            "commit_sequence": self.commit_sequence,
            "commit_digest": self.commit_digest.hex(),
            "records": self.records,
        }

    def _validate(self, payload: dict) -> None:
        if payload.get("version") != 1:
            raise ReplicationError("unsupported durable state version")
        if int(payload["term"]) < 0 or int(payload["generation"]) < 0:
            raise ReplicationError("negative durable state value")
        voted_for = int(payload["voted_for"])
        if voted_for and not 1 <= voted_for <= self.replica_count:
            raise ReplicationError("durable votedFor outside replica set")
        for name in ("chain_digest", "commit_digest"):
            digest = bytes.fromhex(str(payload[name]))
            if len(digest) != 32:
                raise ReplicationError("durable digest has invalid length")
        records = payload.get("records", [])
        if not isinstance(records, list) or len(records) > MAX_RECORDS_PER_APPEND * 1024:
            raise ReplicationError("durable record count outside bound")

    def load(self) -> None:
        with self.lock:
            if not self.path.exists():
                return
            try:
                envelope = json.loads(self.path.read_text())
                payload = envelope["state"]
                if envelope["checksum"] != self._checksum(payload):
                    raise ReplicationError("durable state checksum mismatch")
                self._validate(payload)
                self.term = int(payload["term"])
                self.voted_for = int(payload["voted_for"])
                self.generation = int(payload["generation"])
                self.last_sequence = int(payload["last_sequence"])
                self.chain_digest = bytes.fromhex(payload["chain_digest"])
                self.commit_sequence = int(payload["commit_sequence"])
                self.commit_digest = bytes.fromhex(payload["commit_digest"])
                self.records = list(payload["records"])
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ReplicationError("durable state could not be decoded") from exc

    def persist(self) -> None:
        with self.lock:
            payload = self._payload()
            envelope = {"state": payload, "checksum": self._checksum(payload)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".tmp.", dir=self.path.parent, text=True)
            try:
                os.fchmod(fd, 0o600)
                data = (json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n").encode()
                os.write(fd, data)
                os.fsync(fd)
                os.close(fd)
                os.replace(temporary, self.path)
                directory_fd = os.open(self.path.parent, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as exc:
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
                raise ReplicationError("durable state commit failed") from exc


class JournalReplicationService(pb_grpc.JournalReplicationServicer):
    def __init__(
        self,
        config: ReplicaConfig,
        state: DurableState,
        attestation_verifier: Callable[[pb.JournalIdentity], bool],
        record_verifier: Callable[[pb.JournalIdentity, pb.JournalRecord], bool],
        certificate_identity_verifier: Optional[Callable[[object, int], bool]] = None,
        quorum_verifier: Optional[Callable[[pb.JournalIdentity, pb.QuorumCertificate], bool]] = None,
        rotation_controller: Optional[KmsTrustKeyRotationController] = None,
    ):
        config.validate()
        self.config = config
        self.state = state
        self.attestation_verifier = attestation_verifier
        self.record_verifier = record_verifier
        self.certificate_identity_verifier = certificate_identity_verifier or self._verify_certificate_identity
        self.quorum_verifier = quorum_verifier or (lambda _leader, _certificate: False)
        self.rotation_controller = rotation_controller
        self.peer_votes: dict[int, int] = {}
        self.state.load()

    def start_live_rotation(self) -> None:
        if self.rotation_controller is not None:
            self.rotation_controller.start()

    def stop_live_rotation(self) -> None:
        if self.rotation_controller is not None:
            self.rotation_controller.stop()

    @staticmethod
    def _verify_certificate_identity(context: object, replica_id: int) -> bool:
        try:
            auth = context.auth_context()
            common_names = auth.get("x509_common_name", [])
            expected = f"replica-{replica_id}".encode()
            return expected in common_names
        except (AttributeError, TypeError):
            return False

    def _identity(self, term: Optional[int] = None) -> pb.JournalIdentity:
        with self.state.lock:
            return pb.JournalIdentity(
                cluster_id=self.config.cluster_id,
                replica_id=self.config.replica_id,
                term=self.state.term if term is None else term,
                last_sequence=self.state.last_sequence,
                chain_digest=self.state.chain_digest,
            )

    def _deny_vote(self, context, reason: str) -> pb.VoteResponse:
        context.set_code(grpc.StatusCode.PERMISSION_DENIED)
        context.set_details(reason)
        return pb.VoteResponse(voter=self._identity(), granted=False, denial_reason=reason)

    def RequestVote(self, request, context):
        candidate = request.candidate
        if candidate.cluster_id != self.config.cluster_id or not candidate.replica_id:
            return self._deny_vote(context, "cluster-or-replica-identity-invalid")
        if candidate.replica_id == self.config.replica_id:
            return self._deny_vote(context, "self-vote-over-rpc-denied")
        if not self.certificate_identity_verifier(context, candidate.replica_id):
            return self._deny_vote(context, "tls-replica-identity-mismatch")
        if not self.attestation_verifier(candidate):
            return self._deny_vote(context, "attestation-verification-failed")
        with self.state.lock:
            if candidate.term < self.state.term:
                return self._deny_vote(context, "stale-term")
            if candidate.term > self.state.term:
                self.state.term = candidate.term
                self.state.voted_for = 0
                self.state.generation += 1
                self.state.persist()
            if self.state.voted_for and self.state.voted_for != candidate.replica_id:
                return self._deny_vote(context, "already-voted-in-term")
            if candidate.last_sequence < self.state.last_sequence:
                return self._deny_vote(context, "candidate-journal-behind")
            if candidate.last_sequence == self.state.last_sequence and candidate.chain_digest != self.state.chain_digest:
                return self._deny_vote(context, "candidate-chain-digest-conflict")
            self.state.voted_for = candidate.replica_id
            self.state.generation += 1
            self.state.persist()
            return pb.VoteResponse(voter=self._identity(), granted=True)

    @staticmethod
    def _record_digest(previous_digest: bytes, payload: bytes) -> bytes:
        return hashlib.sha256(previous_digest + payload).digest()

    def _deny_append(self, context, reason: str) -> pb.AppendResponse:
        context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
        context.set_details(reason)
        return pb.AppendResponse(follower=self._identity(), accepted=False, denial_reason=reason)

    def AppendEntries(self, request, context):
        leader = request.leader
        records = list(request.records)
        if leader.cluster_id != self.config.cluster_id or not leader.replica_id:
            return self._deny_append(context, "cluster-or-leader-identity-invalid")
        if not self.certificate_identity_verifier(context, leader.replica_id):
            return self._deny_append(context, "tls-replica-identity-mismatch")
        if not self.attestation_verifier(leader):
            return self._deny_append(context, "attestation-verification-failed")
        if len(records) > MAX_RECORDS_PER_APPEND:
            return self._deny_append(context, "append-record-count-limit")
        with self.state.lock:
            if leader.term < self.state.term:
                return self._deny_append(context, "stale-term")
            if leader.term > self.state.term:
                self.state.term = leader.term
                self.state.voted_for = 0
                self.state.generation += 1
            previous = self.state.chain_digest
            expected_sequence = self.state.last_sequence + 1
            staged: list[dict[str, str | int]] = []
            for record in records:
                if record.sequence != expected_sequence:
                    return self._deny_append(context, "non-contiguous-sequence")
                if bytes(record.previous_digest) != previous:
                    return self._deny_append(context, "previous-digest-mismatch")
                if len(record.payload) > MAX_PAYLOAD_BYTES or len(record.record_digest) != 32:
                    return self._deny_append(context, "record-size-or-digest-invalid")
                if self._record_digest(previous, bytes(record.payload)) != bytes(record.record_digest):
                    return self._deny_append(context, "record-digest-invalid")
                if not self.record_verifier(leader, record):
                    return self._deny_append(context, "record-signature-verification-failed")
                previous = bytes(record.record_digest)
                staged.append({
                    "sequence": int(record.sequence),
                    "previous_digest": bytes(record.previous_digest).hex(),
                    "record_digest": bytes(record.record_digest).hex(),
                    "payload": base64.b64encode(bytes(record.payload)).decode(),
                    "record_signature": base64.b64encode(bytes(record.record_signature)).decode(),
                })
                expected_sequence += 1
            proposed_sequence = self.state.last_sequence
            proposed_digest = self.state.chain_digest
            if staged:
                proposed_sequence = int(staged[-1]["sequence"])
                proposed_digest = bytes.fromhex(str(staged[-1]["record_digest"]))
            if request.quorum_certificate.votes and not request.leader_commit:
                return self._deny_append(context, "quorum-certificate-without-commit-sequence")
            if request.leader_commit:
                certificate = request.quorum_certificate
                if certificate.commit_sequence != request.leader_commit:
                    return self._deny_append(context, "quorum-certificate-sequence-mismatch")
                if certificate.commit_sequence != proposed_sequence or certificate.commit_digest != proposed_digest:
                    return self._deny_append(context, "quorum-certificate-digest-mismatch")
                if not self.quorum_verifier(leader, certificate):
                    return self._deny_append(context, "quorum-certificate-verification-failed")
            self.state.records.extend(staged)
            self.state.last_sequence = proposed_sequence
            self.state.chain_digest = proposed_digest
            if request.leader_commit > self.state.commit_sequence:
                self.state.commit_sequence = request.leader_commit
                self.state.commit_digest = self.state.chain_digest
            self.state.generation += 1
            self.state.persist()
            return pb.AppendResponse(follower=self._identity(), accepted=True, match_sequence=self.state.last_sequence)

    def AppendJournal(self, request, context):
        return self.AppendEntries(request, context)

    def InstallSnapshot(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("snapshot-installation-requires-verified-snapshot-store")
        return pb.SnapshotResponse(follower=self._identity(), accepted=False, denial_reason="snapshot-installation-requires-verified-snapshot-store")

    def ReadCommit(self, request, context):
        requester = request.requester
        if requester.cluster_id != self.config.cluster_id or not self.certificate_identity_verifier(context, requester.replica_id):
            context.set_code(grpc.StatusCode.PERMISSION_DENIED)
            context.set_details("requester-identity-invalid")
            return pb.ReadCommitResponse(authority=self._identity(), committed_sequence=0)
        with self.state.lock:
            return pb.ReadCommitResponse(
                authority=self._identity(),
                committed_sequence=self.state.commit_sequence,
                committed_digest=self.state.commit_digest,
            )


def build_server(service: JournalReplicationService, bind: str, server_key: bytes, server_cert: bytes, client_ca: bytes) -> tuple[grpc.Server, int]:
    credentials = grpc.ssl_server_credentials(
        [(server_key, server_cert)],
        root_certificates=client_ca,
        require_client_auth=True,
    )
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    pb_grpc.add_JournalReplicationServicer_to_server(service, server)
    bound_port = server.add_secure_port(bind, credentials)
    if not bound_port:
        raise ReplicationError("failed to bind authenticated replication endpoint")
    return server, bound_port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    parser.add_argument("--cluster-id", type=int, required=True)
    parser.add_argument("--replica-id", type=int, required=True)
    parser.add_argument("--replica-count", type=int, required=True)
    parser.add_argument("--quorum-size", type=int, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--server-key", type=Path, required=True)
    parser.add_argument("--server-cert", type=Path, required=True)
    parser.add_argument("--client-ca", type=Path, required=True)
    parser.add_argument(
        "--trusted-key",
        action="append",
        required=True,
        metavar="CLUSTER,REPLICA,KEY_ID,GENERATION,PUBLIC_KEY_FILE",
        help="explicit Ed25519 trust entry; may be repeated",
    )
    args = parser.parse_args()
    config = ReplicaConfig(args.cluster_id, args.replica_id, args.replica_count, args.quorum_size, args.state)
    trusted_keys = {}
    for specification in args.trusted_key:
        fields = specification.split(",", 4)
        if len(fields) != 5:
            raise SystemExit("trusted-key must be CLUSTER,REPLICA,KEY_ID,GENERATION,PUBLIC_KEY_FILE")
        cluster_id, replica_id, key_id, generation, public_key_file = fields
        trusted_keys[(int(cluster_id), int(replica_id), key_id, int(generation))] = load_public_key_bytes(public_key_file)
    trust_store = Ed25519TrustStore(trusted_keys)
    service = JournalReplicationService(
        config,
        DurableState(args.state, args.replica_count),
        Ed25519AttestationVerifier(trust_store).verify,
        Ed25519RecordSignatureVerifier(trust_store).verify,
        quorum_verifier=Ed25519QuorumCertificateVerifier(trust_store, config.quorum_size, config.replica_count).verify,
    )
    server, _bound_port = build_server(service, args.bind, args.server_key.read_bytes(), args.server_cert.read_bytes(), args.client_ca.read_bytes())
    service.start_live_rotation()
    server.start()
    try:
        server.wait_for_termination()
    finally:
        service.stop_live_rotation()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
