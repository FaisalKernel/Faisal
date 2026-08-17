#!/usr/bin/env python3
"""Trusted Ed25519 providers and live trust-key rotation for FAISAL.

The module never fabricates hardware evidence. TPM2 and secure-enclave loaders
invoke an explicitly configured external provider and fail closed when the
provider, expected public-key digest, or hardware-backed integration is absent.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from threading import Event, RLock, Thread
from typing import Callable, Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import faisal_replication_pb2 as pb


ATTESTATION_DOMAIN = b"FAISAL-REPLICATION-ATTESTATION-v1\x00"
RECORD_DOMAIN = b"FAISAL-REPLICATION-RECORD-v1\x00"
ROTATION_DOMAIN = b"FAISAL-REPLICATION-KEY-ROTATION-v1\x00"
ED25519_SIGNATURE_BYTES = 64
ED25519_PUBLIC_KEY_BYTES = 32
MAX_KEY_ID_BYTES = 256
MAX_PROVIDER_OUTPUT_BYTES = 16 * 1024


class ProviderConfigurationError(ValueError):
    """Raised when trusted key material or a signed object is malformed."""


class ProviderUnavailable(RuntimeError):
    """Raised when a required physical/provider-backed key source is absent."""


@dataclass(frozen=True)
class TrustKey:
    cluster_id: int
    replica_id: int
    key_id: str
    key_generation: int
    public_key: Ed25519PublicKey


@dataclass(frozen=True)
class RotationProposal:
    cluster_id: int
    replica_id: int
    previous_key_id: str
    previous_generation: int
    key_id: str
    key_generation: int
    public_key: bytes
    authorization_signature: bytes


def _validate_digest(expected_sha256: str) -> str:
    value = expected_sha256.lower()
    if len(value) != 64:
        raise ProviderConfigurationError("expected public-key SHA-256 must be 64 hex characters")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ProviderConfigurationError("expected public-key SHA-256 is not hexadecimal") from exc
    return value


def _public_key_from_data(data: bytes) -> bytes:
    if len(data) == ED25519_PUBLIC_KEY_BYTES:
        Ed25519PublicKey.from_public_bytes(data)
        return data
    if len(data) > MAX_PROVIDER_OUTPUT_BYTES:
        raise ProviderConfigurationError("provider public-key output exceeds bound")
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise ProviderConfigurationError("provider key is not Ed25519")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_public_key_bytes(path: str) -> bytes:
    with open(path, "rb") as key_file:
        return _public_key_from_data(key_file.read())


class HardwarePublicKeyProvider(Protocol):
    def load_public_key(self) -> bytes:
        """Return a verified Ed25519 public key or raise ProviderUnavailable."""


class TPM2PublicKeyProvider:
    """Load a TPM persistent object's public key through tpm2-tools.

    This reads only the public area. The caller must provision an expected
    digest, and the TPM object context/handle must be established by an
    operator on a real TPM. A software TPM or missing tpm2-tools is not treated
    as physical qualification.
    """

    def __init__(self, object_context: str, expected_public_key_sha256: str, timeout_seconds: float = 5.0, tool: str = "tpm2_readpublic"):
        if not object_context:
            raise ProviderConfigurationError("TPM object context is required")
        self.object_context = object_context
        self.expected_sha256 = _validate_digest(expected_public_key_sha256)
        self.timeout_seconds = timeout_seconds
        self.tool = tool

    def load_public_key(self) -> bytes:
        executable = shutil.which(self.tool)
        if not executable:
            raise ProviderUnavailable("tpm2_readpublic is unavailable")
        with tempfile.TemporaryDirectory(prefix="faisal-tpm-") as directory:
            output = os.path.join(directory, "public.pem")
            command = [executable, "-c", self.object_context, "-o", output, "-f", "pem"]
            try:
                result = subprocess.run(command, capture_output=True, timeout=self.timeout_seconds, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ProviderUnavailable("TPM public-key provider failed") from exc
            if result.returncode != 0:
                raise ProviderUnavailable("TPM public-key provider rejected object")
            try:
                key = load_public_key_bytes(output)
            except (OSError, ValueError, TypeError) as exc:
                raise ProviderUnavailable("TPM provider returned invalid public key") from exc
        if hashlib.sha256(key).hexdigest() != self.expected_sha256:
            raise ProviderConfigurationError("TPM public-key digest mismatch")
        return key


class SecureEnclavePublicKeyProvider:
    """Load a public key from an explicitly configured platform secure provider.

    Linux has no universal Secure Enclave API. The command must therefore be a
    vendor/TEE integration supplied by the deployment. Its stdout must contain
    a raw 32-byte Ed25519 key or PEM public key, and the expected digest is
    mandatory. Missing command/provider is an unavailable hardware source.
    """

    def __init__(self, command: Sequence[str], expected_public_key_sha256: str, timeout_seconds: float = 5.0):
        if not command or any(not part for part in command):
            raise ProviderConfigurationError("secure-enclave provider command is required")
        self.command = tuple(command)
        self.expected_sha256 = _validate_digest(expected_public_key_sha256)
        self.timeout_seconds = timeout_seconds

    def load_public_key(self) -> bytes:
        executable = shutil.which(self.command[0]) or (self.command[0] if os.path.isabs(self.command[0]) else None)
        if not executable:
            raise ProviderUnavailable("secure-enclave provider is unavailable")
        try:
            result = subprocess.run(
                [executable, *self.command[1:]],
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderUnavailable("secure-enclave provider failed") from exc
        if result.returncode != 0 or len(result.stdout) > MAX_PROVIDER_OUTPUT_BYTES:
            raise ProviderUnavailable("secure-enclave provider rejected request")
        try:
            key = _public_key_from_data(result.stdout)
        except (ValueError, TypeError) as exc:
            raise ProviderUnavailable("secure-enclave provider returned invalid key") from exc
        if hashlib.sha256(key).hexdigest() != self.expected_sha256:
            raise ProviderConfigurationError("secure-enclave public-key digest mismatch")
        return key


class Ed25519TrustStore:
    """Thread-safe trust store with one active key generation per replica."""

    def __init__(self, keys: Mapping[tuple[int, int, str, int], bytes] | None = None):
        self._lock = RLock()
        self._keys: dict[tuple[int, int, str, int], TrustKey] = {}
        self._active: dict[tuple[int, int], tuple[str, int]] = {}
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
            active = self._active.get((cluster_id, replica_id))
            if active is not None and key_generation < active[1]:
                raise ProviderConfigurationError("cannot provision an older active generation")
            self._keys[(cluster_id, replica_id, key_id, key_generation)] = TrustKey(
                cluster_id, replica_id, key_id, key_generation, key
            )
            if active is None or key_generation >= active[1]:
                self._active[(cluster_id, replica_id)] = (key_id, key_generation)

    def resolve(self, cluster_id: int, replica_id: int, key_id: str, key_generation: int) -> TrustKey | None:
        with self._lock:
            if self._active.get((cluster_id, replica_id)) != (key_id, key_generation):
                return None
            return self._keys.get((cluster_id, replica_id, key_id, key_generation))

    def rotate(self, proposal: RotationProposal) -> None:
        with self._lock:
            active_id = self._active.get((proposal.cluster_id, proposal.replica_id))
            if active_id != (proposal.previous_key_id, proposal.previous_generation):
                raise ProviderConfigurationError("rotation previous generation is not active")
            current = self._keys.get((proposal.cluster_id, proposal.replica_id, *active_id))
            if current is None:
                raise ProviderConfigurationError("active rotation key is missing")
            if proposal.key_generation != proposal.previous_generation + 1:
                raise ProviderConfigurationError("rotation generation must increment by one")
            new_key = _public_key_from_data(bytes(proposal.public_key))
            current.public_key.verify(bytes(proposal.authorization_signature), _rotation_message(proposal))
            self._keys[(proposal.cluster_id, proposal.replica_id, proposal.key_id, proposal.key_generation)] = TrustKey(
                proposal.cluster_id,
                proposal.replica_id,
                proposal.key_id,
                proposal.key_generation,
                Ed25519PublicKey.from_public_bytes(new_key),
            )
            self._active[(proposal.cluster_id, proposal.replica_id)] = (proposal.key_id, proposal.key_generation)

    def active_generation(self, cluster_id: int, replica_id: int) -> tuple[str, int] | None:
        with self._lock:
            return self._active.get((cluster_id, replica_id))


def _u64(value: int) -> bytes:
    if value < 0 or value >= 1 << 64:
        raise ProviderConfigurationError("unsigned 64-bit field outside bounds")
    return value.to_bytes(8, "big")


def _identity_message(identity: pb.JournalIdentity) -> bytes:
    key_id = identity.key_id.encode()
    if len(key_id) > MAX_KEY_ID_BYTES or len(identity.chain_digest) != 32:
        raise ProviderConfigurationError("identity field outside canonical bounds")
    return b"".join((ATTESTATION_DOMAIN, _u64(identity.cluster_id), _u64(identity.replica_id), _u64(identity.term), _u64(identity.last_sequence), identity.chain_digest, _u64(len(key_id)), key_id, _u64(identity.key_generation)))


def _record_message(identity: pb.JournalIdentity, record: pb.JournalRecord) -> bytes:
    key_id = identity.key_id.encode()
    if len(key_id) > MAX_KEY_ID_BYTES or len(identity.chain_digest) != 32:
        raise ProviderConfigurationError("leader identity outside canonical bounds")
    if len(record.previous_digest) != 32 or len(record.record_digest) != 32:
        raise ProviderConfigurationError("record digest outside canonical bounds")
    if len(record.payload) > 1024 * 1024:
        raise ProviderConfigurationError("record payload exceeds provider bound")
    return b"".join((RECORD_DOMAIN, _u64(identity.cluster_id), _u64(identity.replica_id), _u64(identity.term), _u64(identity.key_generation), _u64(len(key_id)), key_id, _u64(record.sequence), record.previous_digest, record.record_digest, _u64(len(record.payload)), bytes(record.payload)))


def _rotation_message(proposal: RotationProposal) -> bytes:
    old_id = proposal.previous_key_id.encode()
    new_id = proposal.key_id.encode()
    if not old_id or not new_id or len(old_id) > MAX_KEY_ID_BYTES or len(new_id) > MAX_KEY_ID_BYTES:
        raise ProviderConfigurationError("rotation key ID outside bounds")
    key = _public_key_from_data(bytes(proposal.public_key))
    return b"".join((ROTATION_DOMAIN, _u64(proposal.cluster_id), _u64(proposal.replica_id), _u64(proposal.previous_generation), _u64(len(old_id)), old_id, _u64(proposal.key_generation), _u64(len(new_id)), new_id, key))


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


class KmsTrustKeyRotationController:
    """Poll a trusted KMS-backed fetcher and atomically activate key generations."""

    def __init__(self, trust_store: Ed25519TrustStore, fetch_proposal: Callable[[], RotationProposal], interval_seconds: float = 30.0):
        if interval_seconds <= 0:
            raise ProviderConfigurationError("rotation interval must be positive")
        self.trust_store = trust_store
        self.fetch_proposal = fetch_proposal
        self.interval_seconds = interval_seconds
        self._stop = Event()
        self._thread: Thread | None = None
        self._lock = RLock()
        self.last_error: str | None = None
        self.last_generation: tuple[int, int, str, int] | None = None

    def rotate_once(self) -> bool:
        try:
            proposal = self.fetch_proposal()
            self.trust_store.rotate(proposal)
        except (ProviderConfigurationError, InvalidSignature, ProviderUnavailable, OSError, ValueError) as exc:
            with self._lock:
                self.last_error = str(exc)
            return False
        with self._lock:
            self.last_error = None
            self.last_generation = (proposal.cluster_id, proposal.replica_id, proposal.key_id, proposal.key_generation)
        return True

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.rotate_once()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = Thread(target=self._run, name="faisal-kms-key-rotation", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join(timeout=max(1.0, self.interval_seconds + 1.0))


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
        identity = pb.JournalIdentity(cluster_id=self.cluster_id, replica_id=self.replica_id, term=term, last_sequence=last_sequence, chain_digest=chain_digest, key_id=self.key_id, key_generation=self.key_generation)
        return pb.JournalIdentity(cluster_id=identity.cluster_id, replica_id=identity.replica_id, term=identity.term, last_sequence=identity.last_sequence, chain_digest=identity.chain_digest, key_id=identity.key_id, key_generation=identity.key_generation, attestation_signature=self.private_key.sign(_identity_message(identity)))

    def sign_record(self, identity: pb.JournalIdentity, record: pb.JournalRecord) -> bytes:
        return self.private_key.sign(_record_message(identity, record))

    def sign_rotation(self, new_key: "Ed25519Signer") -> RotationProposal:
        proposal = RotationProposal(self.cluster_id, self.replica_id, self.key_id, self.key_generation, new_key.key_id, new_key.key_generation, new_key.public_key_bytes(), b"")
        return RotationProposal(proposal.cluster_id, proposal.replica_id, proposal.previous_key_id, proposal.previous_generation, proposal.key_id, proposal.key_generation, proposal.public_key, self.private_key.sign(_rotation_message(proposal)))
