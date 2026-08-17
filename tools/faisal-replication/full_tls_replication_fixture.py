#!/usr/bin/env python3
"""End-to-end software qualification fixture for FAISAL gRPC replication.

This is a real three-node localhost gRPC/mTLS fixture, not physical or
production PKI evidence. It exercises the actual daemon, protobuf bindings,
TLS certificate identity, signed identities/records/quorum certificates,
durable state, minority non-commit, recovery, and negative paths.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import grpc

import faisal_replication_daemon as daemon
import faisal_replication_pb2 as pb
import faisal_replication_pb2_grpc as pb_grpc
from faisal_replication_providers import (
    Ed25519AttestationVerifier,
    Ed25519QuorumCertificateVerifier,
    Ed25519RecordSignatureVerifier,
    Ed25519Signer,
    Ed25519TrustStore,
)

CLUSTER_ID = 71
REPLICA_COUNT = 3
QUORUM = 2
ZERO = b"\x00" * 32


def run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_ca_and_certificates(directory: Path) -> tuple[Path, dict[int, tuple[Path, Path]]]:
    ca_key = directory / "ca.key"
    ca_crt = directory / "ca.crt"
    run(["openssl", "genrsa", "-out", str(ca_key), "2048"])
    run(["openssl", "req", "-x509", "-new", "-nodes", "-key", str(ca_key), "-sha256", "-days", "2", "-out", str(ca_crt), "-subj", "/CN=FAISAL-fixture-CA"])
    certs: dict[int, tuple[Path, Path]] = {}
    for replica in range(1, REPLICA_COUNT + 1):
        key = directory / f"replica-{replica}.key"
        csr = directory / f"replica-{replica}.csr"
        crt = directory / f"replica-{replica}.crt"
        ext = directory / f"replica-{replica}.ext"
        ext.write_text(f"subjectAltName=DNS:replica-{replica}\nextendedKeyUsage=serverAuth,clientAuth\n")
        run(["openssl", "genrsa", "-out", str(key), "2048"])
        run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr), "-subj", f"/CN=replica-{replica}"])
        run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt), "-days", "2", "-sha256", "-extfile", str(ext)])
        certs[replica] = (crt, key)
    return ca_crt, certs


def make_channel(ca: Path, certs: dict[int, tuple[Path, Path]], ports: dict[int, int], client: int, target: int):
    cert, key = certs[client]
    credentials = grpc.ssl_channel_credentials(
        root_certificates=ca.read_bytes(),
        private_key=key.read_bytes(),
        certificate_chain=cert.read_bytes(),
    )
    return grpc.secure_channel(
        f"127.0.0.1:{ports[target]}",
        credentials,
        (("grpc.ssl_target_name_override", f"replica-{target}"),),
    )


def make_signers() -> dict[int, Ed25519Signer]:
    return {i: Ed25519Signer.generate(CLUSTER_ID, i, f"replica-{i}-key", 1) for i in range(1, REPLICA_COUNT + 1)}


def make_trust_store(signers: dict[int, Ed25519Signer]) -> Ed25519TrustStore:
    return Ed25519TrustStore({
        (CLUSTER_ID, i, signer.key_id, signer.key_generation): signer.public_key_bytes()
        for i, signer in signers.items()
    })


def identity(signer: Ed25519Signer, term: int, sequence: int, digest: bytes) -> pb.JournalIdentity:
    return signer.identity(term, sequence, digest)


def record(signer: Ed25519Signer, leader: pb.JournalIdentity, sequence: int, previous: bytes, payload: bytes) -> pb.JournalRecord:
    digest = hashlib.sha256(previous + payload).digest()
    unsigned = pb.JournalRecord(sequence=sequence, previous_digest=previous, record_digest=digest, payload=payload)
    return pb.JournalRecord(
        sequence=sequence,
        previous_digest=previous,
        record_digest=digest,
        payload=payload,
        record_signature=signer.sign_record(leader, unsigned),
    )


def certificate(signers: dict[int, Ed25519Signer], leader: pb.JournalIdentity, sequence: int, digest: bytes, voters: list[int]) -> pb.QuorumCertificate:
    cert = pb.QuorumCertificate(
        cluster_id=CLUSTER_ID,
        leader_replica_id=leader.replica_id,
        term=leader.term,
        commit_sequence=sequence,
        commit_digest=digest,
    )
    cert.votes.extend(signers[voter].sign_quorum_vote(leader.replica_id, leader.term, sequence, digest) for voter in voters)
    return cert


def append(stubs: dict[tuple[int, int], object], client: int, target: int, leader: pb.JournalIdentity, records: list[pb.JournalRecord], commit: int = 0, cert: pb.QuorumCertificate | None = None):
    channel, stub = stubs[(client, target)]
    try:
        return stub.AppendEntries(pb.AppendRequest(
            leader=leader,
            records=records,
            leader_commit=commit,
            quorum_certificate=cert or pb.QuorumCertificate(),
        ), timeout=4)
    except grpc.RpcError as exc:
        return exc


def read_commit(stubs: dict[tuple[int, int], object], client: int, target: int, requester: pb.JournalIdentity):
    return stubs[(client, target)][1].ReadCommit(pb.ReadCommitRequest(requester=requester), timeout=4)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, default=Path(os.environ.get("FAISAL_REPLICATION_FIXTURE_RESULT", "/tmp/faisal-full-tls-replication-result.json")))
    args = parser.parse_args()
    result_json: dict | None = None
    with tempfile.TemporaryDirectory(prefix="faisal-full-tls-replication-") as raw:
        root = Path(raw)
        ca, certs = make_ca_and_certificates(root)
        rogue_dir = root / "rogue"
        rogue_dir.mkdir()
        rogue_key = rogue_dir / "rogue.key"
        rogue_crt = rogue_dir / "rogue.crt"
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(rogue_key), "-out", str(rogue_crt), "-days", "2", "-subj", "/CN=rogue"])
        signers = make_signers()
        trust_store = make_trust_store(signers)
        services: dict[int, daemon.JournalReplicationService] = {}
        servers: dict[int, grpc.Server] = {}
        ports: dict[int, int] = {}
        channels: dict[tuple[int, int], grpc.Channel] = {}
        stubs: dict[tuple[int, int], object] = {}
        for replica in range(1, REPLICA_COUNT + 1):
            config = daemon.ReplicaConfig(CLUSTER_ID, replica, REPLICA_COUNT, QUORUM, root / f"state-{replica}.json")
            service = daemon.JournalReplicationService(
                config,
                daemon.DurableState(config.state_path, REPLICA_COUNT),
                Ed25519AttestationVerifier(trust_store).verify,
                Ed25519RecordSignatureVerifier(trust_store).verify,
                quorum_verifier=Ed25519QuorumCertificateVerifier(trust_store, QUORUM, REPLICA_COUNT).verify,
            )
            crt, key = certs[replica]
            server, port = daemon.build_server(service, "127.0.0.1:0", key.read_bytes(), crt.read_bytes(), ca.read_bytes())
            server.start()
            services[replica] = service
            servers[replica] = server
            ports[replica] = port
        for client in range(1, REPLICA_COUNT + 1):
            for target in range(1, REPLICA_COUNT + 1):
                channel = make_channel(ca, certs, ports, client, target)
                channels[(client, target)] = channel
                stubs[(client, target)] = (channel, pb_grpc.JournalReplicationStub(channel))
        markers: list[str] = []
        try:
            leader1 = identity(signers[1], 1, 0, ZERO)
            votes = []
            for target in (2, 3):
                vote = stubs[(1, target)][1].RequestVote(pb.VoteRequest(candidate=leader1), timeout=4)
                assert vote.granted, vote.denial_reason
                votes.append(target)
            markers.append("TLS_GRPC_MTLS_CERT_IDENTITY_OK")
            markers.append("QUORUM_ELECTION_TERM1_OK")

            first = record(signers[1], leader1, 1, ZERO, b"replication-fixture-record-1")
            for target in (1, 2, 3):
                response = append(stubs, 1, target, leader1, [first])
                assert response.accepted, response.denial_reason
            first_cert = certificate(signers, identity(signers[1], 1, 1, first.record_digest), 1, first.record_digest, [1, 2, 3])
            committed_leader1 = identity(signers[1], 1, 1, first.record_digest)
            for target in (1, 2, 3):
                response = append(stubs, 1, target, committed_leader1, [], 1, first_cert)
                assert response.accepted, response.denial_reason
            for target in (1, 2, 3):
                commit = read_commit(stubs, 1, target, committed_leader1)
                assert commit.committed_sequence == 1 and bytes(commit.committed_digest) == first.record_digest
            markers.append("APPEND_ENTRIES_DURABLE_AND_QUORUM_COMMIT_OK")

            # Simulate a live partition by stopping the minority endpoint. The two remaining nodes can commit; the minority cannot.
            servers[3].stop(0).wait()
            channels[(1, 3)].close()
            channels[(2, 3)].close()
            markers.append("MINORITY_PARTITION_INJECTED_OK")
            second = record(signers[1], committed_leader1, 2, first.record_digest, b"replication-fixture-record-2")
            for target in (1, 2):
                response = append(stubs, 1, target, committed_leader1, [second])
                assert response.accepted, response.denial_reason
            second_leader = identity(signers[1], 1, 2, second.record_digest)
            second_cert = certificate(signers, second_leader, 2, second.record_digest, [1, 2])
            for target in (1, 2):
                response = append(stubs, 1, target, second_leader, [], 2, second_cert)
                assert response.accepted, response.denial_reason
            markers.append("MAJORITY_PARTITION_COMMIT_OK")

            # Restart the minority from durable state and prove a one-vote certificate cannot commit.
            services[3] = daemon.JournalReplicationService(
                daemon.ReplicaConfig(CLUSTER_ID, 3, REPLICA_COUNT, QUORUM, root / "state-3.json"),
                daemon.DurableState(root / "state-3.json", REPLICA_COUNT),
                Ed25519AttestationVerifier(trust_store).verify,
                Ed25519RecordSignatureVerifier(trust_store).verify,
                quorum_verifier=Ed25519QuorumCertificateVerifier(trust_store, QUORUM, REPLICA_COUNT).verify,
            )
            crt3, key3 = certs[3]
            servers[3], ports[3] = daemon.build_server(services[3], "127.0.0.1:0", key3.read_bytes(), crt3.read_bytes(), ca.read_bytes())
            servers[3].start()
            channels[(1, 3)] = make_channel(ca, certs, ports, 1, 3)
            stubs[(1, 3)] = (channels[(1, 3)], pb_grpc.JournalReplicationStub(channels[(1, 3)]))
            minority_leader = identity(signers[1], 1, 1, first.record_digest)
            minority_response = append(stubs, 1, 3, minority_leader, [second], 2, certificate(signers, identity(signers[1], 1, 2, second.record_digest), 2, second.record_digest, [1]))
            assert isinstance(minority_response, grpc.RpcError) and "quorum-certificate-verification-failed" in minority_response.details()
            assert services[3].state.last_sequence == 1 and services[3].state.commit_sequence == 1
            markers.append("MINORITY_ONE_VOTE_COMMIT_DENIED_OK")

            # Heal the partition and repair the lagging node using the verified majority certificate.
            healed = append(stubs, 1, 3, minority_leader, [second])
            assert healed.accepted, healed.denial_reason
            healed_commit = append(stubs, 1, 3, second_leader, [], 2, second_cert)
            assert healed_commit.accepted, healed_commit.denial_reason
            assert services[3].state.commit_sequence == 2
            markers.append("PARTITION_HEAL_AND_CHAIN_REPAIR_OK")

            # Certificate and record tampering must not mutate state.
            bad_record = pb.JournalRecord(
                sequence=3,
                previous_digest=second.record_digest,
                record_digest=hashlib.sha256(second.record_digest + b"bad").digest(),
                payload=b"bad",
                record_signature=b"tampered-signature",
            )
            before = services[3].state.last_sequence
            bad_response = append(stubs, 1, 3, second_leader, [bad_record])
            assert isinstance(bad_response, grpc.RpcError) and "record-signature-verification-failed" in bad_response.details() and services[3].state.last_sequence == before
            bad_cert = certificate(signers, identity(signers[1], 1, 3, bad_record.record_digest), 3, bad_record.record_digest, [1])
            bad_commit = append(stubs, 1, 3, second_leader, [bad_record], 3, bad_cert)
            assert isinstance(bad_commit, grpc.RpcError) and services[3].state.last_sequence == before
            markers.append("TAMPERED_RECORD_AND_UNDERQUORUM_CERT_DENIED_OK")

            wrong_identity = identity(signers[1], 1, 0, ZERO)
            try:
                response = stubs[(3, 2)][1].RequestVote(pb.VoteRequest(candidate=wrong_identity), timeout=4)
                assert not response.granted and response.denial_reason == "tls-replica-identity-mismatch"
            except grpc.RpcError as exc:
                assert "tls-replica-identity-mismatch" in exc.details()
            except AssertionError:
                raise
            markers.append("TLS_CLIENT_CERT_IDENTITY_MISMATCH_DENIED_OK")

            rogue_credentials = grpc.ssl_channel_credentials(
                root_certificates=ca.read_bytes(),
                private_key=rogue_key.read_bytes(),
                certificate_chain=rogue_crt.read_bytes(),
            )
            rogue_channel = grpc.secure_channel(f"127.0.0.1:{ports[2]}", rogue_credentials, (("grpc.ssl_target_name_override", "replica-2"),))
            try:
                rogue_stub = pb_grpc.JournalReplicationStub(rogue_channel)
                try:
                    rogue_stub.RequestVote(pb.VoteRequest(candidate=leader1), timeout=2)
                except grpc.RpcError:
                    markers.append("UNTRUSTED_CA_CLIENT_DENIED_OK")
                else:
                    raise AssertionError("rogue certificate was accepted")
            finally:
                rogue_channel.close()

            restored = daemon.DurableState(root / "state-3.json", REPLICA_COUNT)
            restored.load()
            assert restored.commit_sequence == 2 and restored.last_sequence == 2
            markers.append("DURABLE_REBOOT_RESTORE_OK")
            print("FAISAL_FULL_TLS_REPLICATION_FIXTURE_OK")
            for marker in markers:
                print(marker)
            result = {
                "schema": "org.faisal.full-tls-replication-fixture.v1",
                "source_revision": os.environ.get("FAISAL_REPLICATION_SOURCE_REV", ""),
                "reviewed_epoch": int(os.environ.get("FAISAL_REPLICATION_REVIEWED_EPOCH", str(int(time.time())))),
                "model_output_is_authority": False,
                "status": "pass_software_fixture_physical_and_production_pkI_pending",
                "cluster_id": CLUSTER_ID,
                "replica_count": REPLICA_COUNT,
                "quorum_size": QUORUM,
                "markers": markers,
                "transport": "gRPC_TLS_mutual_authentication",
                "certificate_identity": "distinct_CN_replica_1_to_3",
                "signed_identity_and_record_verification": True,
                "authenticated_quorum_certificate": True,
                "minority_partition_commit_denied": True,
                "partition_repair": True,
                "durable_state_reload": True,
                "negative_paths": ["wrong_client_certificate_identity", "untrusted_client_CA", "tampered_record", "underquorum_certificate"],
                "limitations": [
                    "software-generated fixture CA and Ed25519 keys only",
                    "localhost in-process nodes, not independent hosts",
                    "no production PKI or external KMS/Vault credentials",
                    "no physical TPM/secure-enclave evidence",
                    "application-level endpoint stop used for partition; live iptables fixture remains separate"
                ],
            }
            result_json = result
        finally:
            for channel in channels.values():
                channel.close()
            for server in servers.values():
                server.stop(0).wait()
    if result_json is None:
        raise RuntimeError("fixture did not produce a result")
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(result_json, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
