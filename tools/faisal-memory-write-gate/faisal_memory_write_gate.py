#!/usr/bin/env python3
"""FAISAL memory-write admission and provenance quarantine contract.

The gate prevents untrusted observations, tool output, model output, and retrieved
content from silently becoming durable agent memory. It is a control-plane
contract: it does not persist to a database, execute tools, contact providers, or
turn model output into authority.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "org.faisal.memory-write-admission.v1"
VERIFICATION_SCHEMA = "org.faisal.memory-verification-receipt.v1"
MAX_ENTRIES = 4096
MAX_SCOPE_ITEMS = 32
MAX_AGE_SECONDS = 86_400

TRUST_ORDER = {"quarantined": 0, "untrusted": 1, "bounded": 2, "trusted": 3}
VERIFICATION_ORDER = {"unverified": 0, "verified": 1, "operator_verified": 2}
MEMORY_CLASSES = {"working", "episodic", "semantic", "procedural", "temporal", "entity", "task", "organizational", "system", "operational", "failure", "decision", "provenance"}
SOURCE_KINDS = {"direct_user", "operator", "verified_tool", "browser_observation", "visual_observation", "media_observation", "sensor", "retrieved_memory", "model_output", "tool_metadata", "unknown"}


class MemoryWriteError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MemoryWriteError(f"{name}: invalid")
    return value


def _digest(value: Any, name: str) -> str:
    value = _text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise MemoryWriteError(f"{name}: invalid digest")
    return value


def _u64(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or value < minimum or value > (1 << 63) - 1:
        raise MemoryWriteError(f"{name}: invalid")
    return value


def _scope(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)) or not value or len(value) > MAX_SCOPE_ITEMS:
        raise MemoryWriteError(f"{name}: invalid")
    normalized = tuple(sorted({_text(item, name, 128) for item in value}))
    if not normalized:
        raise MemoryWriteError(f"{name}: empty")
    return normalized


@dataclass(frozen=True)
class MemoryCandidate:
    memory_id: str
    memory_class: str
    source_kind: str
    source_id: str
    source_digest: str
    content_digest: str
    provenance_digest: str
    scope: tuple[str, ...]
    trust: str
    verification: str
    generation: int
    created_at: int
    expires_at: int
    injection_signaled: bool = False

    def canonical(self) -> dict[str, Any]:
        memory_class = _text(self.memory_class, "memory_class")
        source_kind = _text(self.source_kind, "source_kind")
        trust = _text(self.trust, "trust")
        verification = _text(self.verification, "verification")
        if memory_class not in MEMORY_CLASSES:
            raise MemoryWriteError("memory_class: unsupported")
        if source_kind not in SOURCE_KINDS:
            raise MemoryWriteError("source_kind: unsupported")
        if trust not in TRUST_ORDER:
            raise MemoryWriteError("trust: unsupported")
        if verification not in VERIFICATION_ORDER:
            raise MemoryWriteError("verification: unsupported")
        created_at = _u64(self.created_at, "created_at")
        expires_at = _u64(self.expires_at, "expires_at")
        if expires_at <= created_at:
            raise MemoryWriteError("expiry must be after creation")
        if self.injection_signaled and trust == "trusted":
            raise MemoryWriteError("injection-signaled content cannot be trusted")
        return {
            "memory_id": _text(self.memory_id, "memory_id"),
            "memory_class": memory_class,
            "source_kind": source_kind,
            "source_id": _text(self.source_id, "source_id"),
            "source_digest": _digest(self.source_digest, "source_digest"),
            "content_digest": _digest(self.content_digest, "content_digest"),
            "provenance_digest": _digest(self.provenance_digest, "provenance_digest"),
            "scope": list(_scope(self.scope, "scope")),
            "trust": trust,
            "verification": verification,
            "generation": _u64(self.generation, "generation", minimum=1),
            "created_at": created_at,
            "expires_at": expires_at,
            "injection_signaled": bool(self.injection_signaled),
        }


@dataclass(frozen=True)
class MemoryWritePolicy:
    allowed_scope: tuple[str, ...]
    minimum_trust: str = "bounded"
    minimum_verification: str = "verified"
    allow_quarantine: bool = True
    require_verification_for_durable: bool = True
    max_age_seconds: int = MAX_AGE_SECONDS

    def canonical(self) -> dict[str, Any]:
        minimum_trust = _text(self.minimum_trust, "minimum_trust")
        minimum_verification = _text(self.minimum_verification, "minimum_verification")
        if minimum_trust not in TRUST_ORDER or minimum_verification not in VERIFICATION_ORDER:
            raise MemoryWriteError("policy threshold unsupported")
        max_age = _u64(self.max_age_seconds, "max_age_seconds", minimum=1)
        if max_age > MAX_AGE_SECONDS:
            raise MemoryWriteError("policy age bound exceeded")
        return {"allowed_scope": list(_scope(self.allowed_scope, "allowed_scope")), "minimum_trust": minimum_trust, "minimum_verification": minimum_verification, "allow_quarantine": bool(self.allow_quarantine), "require_verification_for_durable": bool(self.require_verification_for_durable), "max_age_seconds": max_age}


@dataclass(frozen=True)
class VerificationReceipt:
    candidate_digest: str
    verifier_id: str
    evidence_digest: str
    generation: int
    verified_at: int
    decision: str = "verified"

    def canonical(self) -> dict[str, Any]:
        if self.decision not in {"verified", "operator_verified"}:
            raise MemoryWriteError("verification decision unsupported")
        return {"schema": VERIFICATION_SCHEMA, "candidate_digest": _digest(self.candidate_digest, "candidate_digest"), "verifier_id": _text(self.verifier_id, "verifier_id"), "evidence_digest": _digest(self.evidence_digest, "evidence_digest"), "generation": _u64(self.generation, "generation", minimum=1), "verified_at": _u64(self.verified_at, "verified_at"), "decision": self.decision, "model_output_is_authority": False, "provider_metadata_is_authority": False}


class MemoryWriteGate:
    def __init__(self, *, max_entries: int = MAX_ENTRIES) -> None:
        if not 1 <= max_entries <= MAX_ENTRIES:
            raise MemoryWriteError("max_entries outside bound")
        self.max_entries = max_entries
        self._admitted: dict[str, dict[str, Any]] = {}
        self._quarantined: dict[str, dict[str, Any]] = {}
        self._replay: set[str] = set()
        self._version = 0

    @property
    def version(self) -> int:
        return self._version

    def _candidate_digest(self, candidate: MemoryCandidate) -> tuple[dict[str, Any], str]:
        body = candidate.canonical()
        return body, digest({"schema": SCHEMA, "candidate": body})

    @staticmethod
    def _scope_allowed(candidate_scope: list[str], allowed_scope: list[str]) -> bool:
        allowed = set(allowed_scope)
        return set(candidate_scope).issubset(allowed)

    def _base_record(self, body: dict[str, Any], candidate_digest: str, status: str, reason: str, policy: dict[str, Any]) -> dict[str, Any]:
        return {"schema": SCHEMA, "candidate": body, "candidate_digest": candidate_digest, "status": status, "reason": reason, "policy": policy, "authority": {"model_output_is_authority": False, "provider_metadata_is_authority": False, "memory_is_execution": False, "memory_is_policy_authority": False, "production_approval": False}}

    def admit(self, candidate: MemoryCandidate, *, policy: MemoryWritePolicy, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        body, candidate_digest = self._candidate_digest(candidate)
        policy_body = policy.canonical()
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", minimum=1)
        nonce = _text(nonce, "nonce", 256)
        if candidate_digest in self._admitted or candidate_digest in self._quarantined:
            raise MemoryWriteError("candidate replay detected")
        if len(self._admitted) + len(self._quarantined) >= self.max_entries:
            raise MemoryWriteError("memory admission bound exceeded")
        if body["generation"] != current_generation:
            raise MemoryWriteError("generation fence mismatch")
        if body["created_at"] > now or now - body["created_at"] > policy_body["max_age_seconds"] or body["expires_at"] <= now:
            raise MemoryWriteError("candidate freshness or expiry violated")
        if not self._scope_allowed(body["scope"], policy_body["allowed_scope"]):
            raise MemoryWriteError("memory scope exceeds policy")
        tainted = body["injection_signaled"] or body["source_kind"] in {"model_output", "browser_observation", "visual_observation", "media_observation", "tool_metadata", "retrieved_memory", "unknown"} or TRUST_ORDER[body["trust"]] < TRUST_ORDER[policy_body["minimum_trust"]] or VERIFICATION_ORDER[body["verification"]] < VERIFICATION_ORDER[policy_body["minimum_verification"]]
        durable_class = body["memory_class"] in {"semantic", "procedural", "system", "organizational", "operational", "decision"}
        if durable_class and policy_body["require_verification_for_durable"] and body["verification"] == "unverified":
            tainted = True
        status = "quarantined" if tainted else "admitted"
        reason = "untrusted_or_unverified_provenance" if tainted else "verified_bounded_memory_write"
        record = self._base_record(body, candidate_digest, status, reason, policy_body)
        record["nonce_digest"] = digest({"candidate_digest": candidate_digest, "nonce": nonce})
        if status == "quarantined":
            if not policy_body["allow_quarantine"]:
                raise MemoryWriteError("quarantine is disabled by policy")
            self._quarantined[candidate_digest] = record
        else:
            self._admitted[candidate_digest] = record
        self._version += 1
        return {**record, "admitted": status == "admitted", "quarantined": status == "quarantined"}

    def promote(self, record: Mapping[str, Any], *, verification: VerificationReceipt, policy: MemoryWritePolicy, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        if not isinstance(record, Mapping) or record.get("schema") != SCHEMA or record.get("status") != "quarantined":
            raise MemoryWriteError("only quarantined records can be promoted")
        candidate_digest = _digest(record.get("candidate_digest"), "candidate_digest")
        stored = self._quarantined.get(candidate_digest)
        supplied = {key: value for key, value in dict(record).items() if key not in {"admitted", "quarantined"}}
        if stored is None or {key: stored.get(key) for key in stored if key != "nonce_digest"} != {key: supplied.get(key) for key in supplied if key != "nonce_digest"}:
            raise MemoryWriteError("quarantine record not found or tampered")
        verification_body = verification.canonical()
        if verification_body["candidate_digest"] != candidate_digest:
            raise MemoryWriteError("verification candidate mismatch")
        if verification_body["generation"] != _u64(current_generation, "current_generation", minimum=1):
            raise MemoryWriteError("verification generation mismatch")
        now = _u64(now, "now")
        if verification_body["verified_at"] > now or now - verification_body["verified_at"] > policy.canonical()["max_age_seconds"]:
            raise MemoryWriteError("verification freshness violated")
        _text(nonce, "nonce", 256)
        body = dict(stored["candidate"])
        body["verification"] = verification_body["decision"]
        body["trust"] = max((body["trust"], "bounded"), key=lambda item: TRUST_ORDER[item])
        body["injection_signaled"] = False
        promoted = self._base_record(body, candidate_digest, "admitted", "explicit_verified_promotion", policy.canonical())
        promoted["verification_receipt_digest"] = digest(verification_body)
        replay_key = digest({"candidate_digest": candidate_digest, "verification": promoted["verification_receipt_digest"], "nonce": nonce})
        if replay_key in self._replay:
            raise MemoryWriteError("promotion replay detected")
        self._replay.add(replay_key)
        del self._quarantined[candidate_digest]
        self._admitted[candidate_digest] = promoted
        self._version += 1
        return {**promoted, "admitted": True, "quarantined": False}

    def digest(self) -> str:
        return digest({"version": self._version, "admitted": sorted(self._admitted), "quarantined": sorted(self._quarantined), "replay": sorted(self._replay)})
