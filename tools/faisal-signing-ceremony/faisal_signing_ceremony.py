from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.signing-ceremony.v1"
MAX_TTL = 31_536_000
MAX_ROSTER = 128
MAX_EVENTS = 4096
PHASES = ("witness", "sign", "transparency")

class SigningCeremonyError(ValueError):
    pass

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()

def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise SigningCeremonyError(f"{name} is invalid")
    return value

def optional_text(value: Any, name: str, limit: int = 512) -> str:
    if value == "":
        return ""
    return text(value, name, limit)

def sha(value: Any, name: str, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    value = text(value, name, 71)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise SigningCeremonyError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise SigningCeremonyError(f"{name} is not a SHA-256 digest") from exc
    return value

def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise SigningCeremonyError(f"{name} is outside bounds")
    return value

def names(value: Any, name: str, maximum: int = MAX_ROSTER, minimum: int = 0) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) < minimum or len(value) > maximum:
        raise SigningCeremonyError(f"{name} is outside bounds")
    result = tuple(text(item, f"{name} item", 256) for item in value)
    if tuple(sorted(set(result))) != result:
        raise SigningCeremonyError(f"{name} must be sorted and unique")
    return result

def authority_boundary(value: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "operator_claim_is_authority", "signature_receipt_is_production_authority", "production_approval")
    if not isinstance(value, Mapping) or any(value.get(field) is not False for field in required):
        raise SigningCeremonyError("signing ceremony authority boundary violation")

@dataclass(frozen=True)
class CeremonyPolicy:
    ceremony_id: str
    release_tag: str
    release_head: str
    artifact_digest: str
    role_id: str
    key_ids: tuple[str, ...]
    operator_ids: tuple[str, ...]
    witness_ids: tuple[str, ...]
    key_threshold: int
    witness_threshold: int
    generation: int
    issued_at: int
    expires_at: int
    trusted_root_id: str

    def __post_init__(self) -> None:
        text(self.ceremony_id, "ceremony_id"); text(self.release_tag, "release_tag"); text(self.release_head, "release_head", 40)
        if len(self.release_head) != 40: raise SigningCeremonyError("release_head must be a full commit hash")
        sha(self.artifact_digest, "artifact_digest"); text(self.role_id, "role_id"); text(self.trusted_root_id, "trusted_root_id")
        keys = names(self.key_ids, "key_ids", minimum=2); operators = names(self.operator_ids, "operator_ids", minimum=2); witnesses = names(self.witness_ids, "witness_ids", minimum=2)
        if len(keys) != len(operators): raise SigningCeremonyError("key and operator roster lengths must match")
        if set(operators) & set(witnesses): raise SigningCeremonyError("operator and witness roles must be separated")
        integer(self.key_threshold, "key_threshold", 2, len(keys)); integer(self.witness_threshold, "witness_threshold", 2, len(witnesses)); integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL: raise SigningCeremonyError("ceremony TTL exceeds bound")

    @property
    def manifest_digest(self) -> str:
        return digest({"schema": SCHEMA, "ceremony_id": self.ceremony_id, "release_tag": self.release_tag, "release_head": self.release_head, "artifact_digest": self.artifact_digest, "role_id": self.role_id, "key_ids": self.key_ids, "operator_ids": self.operator_ids, "witness_ids": self.witness_ids, "key_threshold": self.key_threshold, "witness_threshold": self.witness_threshold, "generation": self.generation, "issued_at": self.issued_at, "expires_at": self.expires_at, "trusted_root_id": self.trusted_root_id})

@dataclass(frozen=True)
class CeremonyEvent:
    event_id: str
    phase: str
    origin: str
    actor_id: str
    actor_role: str
    manifest_digest: str
    event_digest: str
    recorded_at: int
    key_id: str = ""
    signature_digest: str = ""
    transparency_log_entry: str = ""
    trusted_root_id: str = ""
    verification_reference: str = ""
    independence_group: str = ""

    def __post_init__(self) -> None:
        text(self.event_id, "event_id"); text(self.phase, "phase")
        if self.phase not in PHASES: raise SigningCeremonyError("unsupported ceremony phase")
        if self.origin not in {"local", "external_reference"}: raise SigningCeremonyError("unsupported event origin")
        text(self.actor_id, "actor_id"); text(self.actor_role, "actor_role"); sha(self.manifest_digest, "manifest_digest"); sha(self.event_digest, "event_digest"); integer(self.recorded_at, "recorded_at", 0, 2**63 - 1)
        optional_text(self.key_id, "key_id"); sha(self.signature_digest, "signature_digest", optional=True); optional_text(self.transparency_log_entry, "transparency_log_entry"); optional_text(self.trusted_root_id, "trusted_root_id"); optional_text(self.verification_reference, "verification_reference"); optional_text(self.independence_group, "independence_group")

    @property
    def record_digest(self) -> str:
        return digest({"schema": SCHEMA, "event_id": self.event_id, "phase": self.phase, "origin": self.origin, "actor_id": self.actor_id, "actor_role": self.actor_role, "manifest_digest": self.manifest_digest, "event_digest": self.event_digest, "recorded_at": self.recorded_at, "key_id": self.key_id, "signature_digest": self.signature_digest, "transparency_log_entry": self.transparency_log_entry, "trusted_root_id": self.trusted_root_id, "verification_reference": self.verification_reference, "independence_group": self.independence_group})

class CeremonyLedger:
    def __init__(self, policy: CeremonyPolicy) -> None:
        self.policy = policy
        self._events: dict[str, CeremonyEvent] = {}
        self._nonces: set[str] = set()
        self._next_sequence = 1

    def _validate(self, event: CeremonyEvent, *, now: int) -> None:
        if event.manifest_digest != self.policy.manifest_digest: raise SigningCeremonyError("event manifest mismatch")
        if now < self.policy.issued_at or now >= self.policy.expires_at or now < event.recorded_at: raise SigningCeremonyError("ceremony event is stale or future-dated")
        if event.phase == "witness":
            if event.actor_role != "witness" or event.actor_id not in self.policy.witness_ids or not event.independence_group: raise SigningCeremonyError("witness event lacks approved independent witness")
        elif event.phase == "sign":
            if event.actor_role != "operator" or event.actor_id not in self.policy.operator_ids or event.key_id not in self.policy.key_ids or not event.signature_digest: raise SigningCeremonyError("sign event lacks approved operator, key, or signature digest")
        elif event.phase == "transparency":
            if event.actor_role != "transparency" or not event.key_id or event.key_id not in self.policy.key_ids or not event.signature_digest or not event.transparency_log_entry or event.trusted_root_id != self.policy.trusted_root_id or not event.verification_reference: raise SigningCeremonyError("transparency event lacks signature, log, root, or verification reference")

    def record(self, event: CeremonyEvent, *, sequence: int, nonce: str, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        authority_boundary(authority); integer(sequence, "sequence", 1, MAX_EVENTS); text(nonce, "nonce"); integer(now, "now", 0, 2**63 - 1)
        if sequence != self._next_sequence: raise SigningCeremonyError("ceremony sequence is not monotonic")
        if event.record_digest in self._events or nonce in self._nonces: raise SigningCeremonyError("ceremony event or nonce replay")
        if len(self._events) >= MAX_EVENTS: raise SigningCeremonyError("ceremony event capacity exceeded")
        self._validate(event, now=now)
        self._events[event.record_digest] = event; self._nonces.add(nonce); self._next_sequence += 1
        return {"schema": SCHEMA, "status": "event_recorded", "phase": event.phase, "event_digest": event.record_digest, "manifest_digest": self.policy.manifest_digest, "sequence": sequence, "origin": event.origin, "signature_created": False, "signature_cryptographically_verified": False, "transparency_log_verified": False, "operator_ceremony_completed": False, "production_approval": False, "authority": dict(authority)}

    def status(self, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        authority_boundary(authority); integer(now, "now", 0, 2**63 - 1)
        events = list(self._events.values()); witnesses = {e.actor_id for e in events if e.phase == "witness"}; signatures = {e.key_id: e for e in events if e.phase == "sign"}; transparency = {e.key_id: e for e in events if e.phase == "transparency"}
        structural = len(witnesses) >= self.policy.witness_threshold and len(signatures) >= self.policy.key_threshold and set(signatures).issubset(transparency) and all(e.manifest_digest == self.policy.manifest_digest for e in events)
        external = structural and all(e.origin == "external_reference" for e in events) and all(e.verification_reference for e in transparency.values()) and all(e.trusted_root_id == self.policy.trusted_root_id for e in transparency.values())
        blockers = []
        if len(witnesses) < self.policy.witness_threshold: blockers.append("witness_threshold")
        if len(signatures) < self.policy.key_threshold: blockers.append("signature_threshold")
        if not set(signatures).issubset(transparency): blockers.append("transparency_records")
        if not external: blockers.append("external_ceremony_verification")
        blockers.append("production_authority_not_issued")
        return {"schema": SCHEMA, "status": "blocked" if blockers else "external_ceremony_evidence_structurally_complete", "manifest_digest": self.policy.manifest_digest, "witness_count": len(witnesses), "signature_key_count": len(signatures), "transparency_key_count": len(transparency), "structurally_complete": structural, "external_ceremony_evidence_structurally_complete": external, "operator_ceremony_completed": False, "signature_cryptographically_verified": False, "transparency_log_verified": False, "production_approval": False, "blockers": blockers, "authority": dict(authority)}

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "manifest_digest": self.policy.manifest_digest, "events": sorted(self._events), "nonces": sorted(self._nonces), "next_sequence": self._next_sequence})
