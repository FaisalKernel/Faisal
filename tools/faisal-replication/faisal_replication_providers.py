#!/usr/bin/env python3
"""Trusted Ed25519 verification providers for FAISAL replication.

The providers verify signatures only against an explicitly provisioned trust
store. They never derive trust from model output, key IDs alone, or transport
metadata. Canonical encodings are versioned and domain-separated to prevent
cross-protocol signature reuse.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import faisal_replication_pb2 as pb


ATTESTATION_DOMAIN = b"FAISAL-REPLICATION-ATTESTATION-v1\x00"
RECORD_DOMAIN = b"FAISAL-REPLICATION-RECORD-v1\x00"
ED25519_SIGNATURE_BYTES = 64
ED25519_PUBLIC_KEY_BYTES = 32
MAX_KEY_ID_BYTES = 256


class ProviderConfigurationError(ValueError):
    """Raised when trusted key material or a signed object is malformed."""


@dataclass(frozen=True)
class TrustKey:
    cluster_id: int
    replica_id: int
    key_id: str
    key_generation: int
    public_key: Ed25519PublicKey


def load_public_key_bytes(path: str) -> bytes:
    with open(path, "rb") as key_file:
        data = key_file.read()
    if len(data) == ED25519_PUBLIC_KEY_BYTES:
        return data
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ProviderConfigurationError("trusted key file is not an Ed25519 public key")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Ed25519TrustStore:
    """Explicit in-memory trust store; callers must provision every key."""

    def __init__(self, keys: Mapping[tuple[int, int, str, int], bytes] | None = None):
        self._lock = RLock()
        self._keys: dict[tuple[int, int, str, int], TrustKey] = {}
        for identity, public_key in (keys or {}).items():
            self.provision(*identity, public_key)

    def provision(self, cluster_id: int, replica_id: int, key_id: str, key_generation: int, public_key: bytes) -> None:
        if cluster_id <= 0 or replica_id <= 0 or key_generation <= 0:
            raise ProviderConfigurationError("trust key identity values must be positive")
        key_bytes = bytes(public_key)
        if len(key_bytes) != ED25519_PUBLIC_KEY_BYTES:
            raise ProviderConfigurationError("Ed25519 public key must be 32 bytes")
        if not key_id or len(key_id.encode()) > MAX_KEY_ID_BYTES:
            raise ProviderConfigurationError("key ID is empty or oversized")
        key = Ed25519PublicKey.from_public_bytes(key_bytes)
        with self._lock:
            self._keys[(cluster_id, replica_id, key_id, key_generation)] = TrustKey(
                cluster_id, replica_id, key_id, key_generation, key
            )

    def resolve(self, cluster_id: int, replica_id: int, key_id: str, key_generation: int) -> TrustKey | None:
        with self._lock:
            return self._keys.get((cluster_id, replica_id, key_id, key_generation))


def _u64(value: int) -> bytes:
    if value < 0 or value >= 1 << 64:
        raise ProviderConfigurationError("unsigned 64-bit field outside bounds")
    return value.to_bytes(8, "big")


def _identity_message(identity: pb.JournalIdentity) -> bytes:
    key_id = identity.key_id.encode()
    if len(key_id) > MAX_KEY_ID_BYTES or len(identity.chain_digest) != 32:
        raise ProviderConfigurationError("identity field outside canonical bounds")
    return b"".join((
        ATTESTATION_DOMAIN,
        _u64(identity.cluster_id),
        _u64(identity.replica_id),
        _u64(identity.term),
        _u64(identity.last_sequence),
        identity.chain_digest,
        _u64(len(key_id)),
        key_id,
        _u64(identity.key_generation),
    ))


def _record_message(identity: pb.JournalIdentity, record: pb.JournalRecord) -> bytes:
    key_id = identity.key_id.encode()
    if len(key_id) > MAX_KEY_ID_BYTES or len(identity.chain_digest) != 32:
        raise ProviderConfigurationError("leader identity outside canonical bounds")
    if len(record.previous_digest) != 32 or len(record.record_digest) != 32:
        raise ProviderConfigurationError("record digest outside canonical bounds")
    if len(record.payload) > 1024 * 1024:
        raise ProviderConfigurationError("record payload exceeds provider bound")
    return b"".join((
        RECORD_DOMAIN,
        _u64(identity.cluster_id),
        _u64(identity.replica_id),
        _u64(identity.term),
        _u64(identity.key_generation),
        _u64(len(key_id)),
        key_id,
        _u64(record.sequence),
        record.previous_digest,
        record.record_digest,
        _u64(len(record.payload)),
        bytes(record.payload),
    ))


class Ed25519AttestationVerifier:
    def __init__(self, trust_store: Ed25519TrustStore):
        self.trust_store = trust_store

    def verify(self, identity: pb.JournalIdentity) -> bool:
        try:
            key = self.trust_store.resolve(identity.cluster_id, identity.replica_id, identity.key_id, identity.key_generation)
            if key is None or len(identity.attestation_signature) != ED25519_SIGNATURE_BYTES:
                return False
            key.public_key.verify(bytes(identity.attestation_signature), _identity_message(identity))
            return True
        except (InvalidSignature, ProviderConfigurationError, TypeError, ValueError):
            return False


class Ed25519RecordSignatureVerifier:
    def __init__(self, trust_store: Ed25519TrustStore):
        self.trust_store = trust_store

    def verify(self, identity: pb.JournalIdentity, record: pb.JournalRecord) -> bool:
        try:
            key = self.trust_store.resolve(identity.cluster_id, identity.replica_id, identity.key_id, identity.key_generation)
            if key is None or len(record.record_signature) != ED25519_SIGNATURE_BYTES:
                return False
            key.public_key.verify(bytes(record.record_signature), _record_message(identity, record))
            return True
        except (InvalidSignature, ProviderConfigurationError, TypeError, ValueError):
            return False


class Ed25519Signer:
    """Test/deployment-side signer; private keys never belong in the daemon trust store."""

    def __init__(self, private_key: Ed25519PrivateKey, cluster_id: int, replica_id: int, key_id: str, key_generation: int):
        self.private_key = private_key
        self.cluster_id = cluster_id
        self.replica_id = replica_id
        self.key_id = key_id
        self.key_generation = key_generation

    @classmethod
    def generate(cls, cluster_id: int, replica_id: int, key_id: str, key_generation: int) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate(), cluster_id, replica_id, key_id, key_generation)

    def public_key_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def identity(self, term: int, last_sequence: int, chain_digest: bytes) -> pb.JournalIdentity:
        identity = pb.JournalIdentity(
            cluster_id=self.cluster_id,
            replica_id=self.replica_id,
            term=term,
            last_sequence=last_sequence,
            chain_digest=chain_digest,
            key_id=self.key_id,
            key_generation=self.key_generation,
        )
        return identity.__class__(**{
            "cluster_id": identity.cluster_id,
            "replica_id": identity.replica_id,
            "term": identity.term,
            "last_sequence": identity.last_sequence,
            "chain_digest": identity.chain_digest,
            "key_id": identity.key_id,
            "key_generation": identity.key_generation,
            "attestation_signature": self.private_key.sign(_identity_message(identity)),
        })

    def sign_record(self, identity: pb.JournalIdentity, record: pb.JournalRecord) -> bytes:
        return self.private_key.sign(_record_message(identity, record))
