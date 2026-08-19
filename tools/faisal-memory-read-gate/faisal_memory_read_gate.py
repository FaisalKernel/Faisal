#!/usr/bin/env python3
"""FAISAL memory-read trust and data-only context projection contract.

The read gate is complementary to the memory-write gate. It prevents stored
entries that are quarantined, expired, stale, out of scope, or below policy trust
from entering execution/tool contexts. Audit contexts may inspect excluded
entries as data-only evidence. No raw memory text is treated as instructions and
no model/provider output can authorize retrieval.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.memory-read-projection.v1"
MAX_ENTRIES = 4096
MAX_SCOPE_ITEMS = 32
MAX_CONTEXT_ENTRIES = 256
MAX_CONTEXT_BYTES = 1_000_000
MAX_AGE_SECONDS = 86_400
TRUST_ORDER = {"quarantined": 0, "untrusted": 1, "bounded": 2, "trusted": 3}
VERIFICATION_ORDER = {"unverified": 0, "verified": 1, "operator_verified": 2}
MEMORY_CLASSES = {"working", "episodic", "semantic", "procedural", "temporal", "entity", "task", "organizational", "system", "operational", "failure", "decision", "provenance"}
SOURCE_KINDS = {"direct_user", "operator", "verified_tool", "browser_observation", "visual_observation", "media_observation", "sensor", "retrieved_memory", "model_output", "tool_metadata", "unknown"}
CONTEXTS = {"execution", "planning", "audit", "research"}


class MemoryReadError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MemoryReadError(f"{name}: invalid")
    return value


def _digest(value: Any, name: str) -> str:
    value = _text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise MemoryReadError(f"{name}: invalid digest")
    return value


def _u64(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or value < minimum or value > (1 << 63) - 1:
        raise MemoryReadError(f"{name}: invalid")
    return value


def _scope(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)) or not value or len(value) > MAX_SCOPE_ITEMS:
        raise MemoryReadError(f"{name}: invalid")
    values = tuple(sorted({_text(item, name, 128) for item in value}))
    if not values:
        raise MemoryReadError(f"{name}: empty")
    return values


@dataclass(frozen=True)
class MemoryEntry:
    memory_id: str
    candidate_digest: str
    memory_class: str
    source_kind: str
    source_id: str
    content_digest: str
    provenance_digest: str
    scope: tuple[str, ...]
    trust: str
    verification: str
    generation: int
    created_at: int
    expires_at: int
    injection_signaled: bool = False
    quarantined: bool = False
    estimated_bytes: int = 0

    def canonical(self) -> dict[str, Any]:
        memory_class = _text(self.memory_class, "memory_class")
        source_kind = _text(self.source_kind, "source_kind")
        trust = _text(self.trust, "trust")
        verification = _text(self.verification, "verification")
        if memory_class not in MEMORY_CLASSES:
            raise MemoryReadError("memory_class: unsupported")
        if source_kind not in SOURCE_KINDS:
            raise MemoryReadError("source_kind: unsupported")
        if trust not in TRUST_ORDER or verification not in VERIFICATION_ORDER:
            raise MemoryReadError("trust or verification unsupported")
        created_at = _u64(self.created_at, "created_at")
        expires_at = _u64(self.expires_at, "expires_at")
        if expires_at <= created_at:
            raise MemoryReadError("expiry must be after creation")
        estimated_bytes = _u64(self.estimated_bytes, "estimated_bytes")
        if estimated_bytes > MAX_CONTEXT_BYTES:
            raise MemoryReadError("entry size exceeds bound")
        return {
            "memory_id": _text(self.memory_id, "memory_id"),
            "candidate_digest": _digest(self.candidate_digest, "candidate_digest"),
            "memory_class": memory_class,
            "source_kind": source_kind,
            "source_id": _text(self.source_id, "source_id"),
            "content_digest": _digest(self.content_digest, "content_digest"),
            "provenance_digest": _digest(self.provenance_digest, "provenance_digest"),
            "scope": list(_scope(self.scope, "scope")),
            "trust": trust,
            "verification": verification,
            "generation": _u64(self.generation, "generation", minimum=1),
            "created_at": created_at,
            "expires_at": expires_at,
            "injection_signaled": bool(self.injection_signaled),
            "quarantined": bool(self.quarantined),
            "estimated_bytes": estimated_bytes,
        }


@dataclass(frozen=True)
class ReadPolicy:
    context: str
    allowed_scope: tuple[str, ...]
    minimum_trust: str = "bounded"
    minimum_verification: str = "verified"
    max_entries: int = 32
    max_bytes: int = 64_000
    max_age_seconds: int = MAX_AGE_SECONDS
    allow_quarantined_in_audit: bool = True

    def canonical(self) -> dict[str, Any]:
        context = _text(self.context, "context")
        if context not in CONTEXTS:
            raise MemoryReadError("context unsupported")
        minimum_trust = _text(self.minimum_trust, "minimum_trust")
        minimum_verification = _text(self.minimum_verification, "minimum_verification")
        if minimum_trust not in TRUST_ORDER or minimum_verification not in VERIFICATION_ORDER:
            raise MemoryReadError("policy threshold unsupported")
        max_entries = _u64(self.max_entries, "max_entries", minimum=1)
        max_bytes = _u64(self.max_bytes, "max_bytes", minimum=1)
        max_age = _u64(self.max_age_seconds, "max_age_seconds", minimum=1)
        if max_entries > MAX_CONTEXT_ENTRIES or max_bytes > MAX_CONTEXT_BYTES or max_age > MAX_AGE_SECONDS:
            raise MemoryReadError("policy bound exceeded")
        return {"context": context, "allowed_scope": list(_scope(self.allowed_scope, "allowed_scope")), "minimum_trust": minimum_trust, "minimum_verification": minimum_verification, "max_entries": max_entries, "max_bytes": max_bytes, "max_age_seconds": max_age, "allow_quarantined_in_audit": bool(self.allow_quarantined_in_audit)}


class MemoryReadGate:
    def __init__(self, *, max_entries: int = MAX_ENTRIES) -> None:
        if not 1 <= max_entries <= MAX_ENTRIES:
            raise MemoryReadError("max_entries outside bound")
        self.max_entries = max_entries
        self._projection_digests: set[str] = set()
        self._version = 0

    @staticmethod
    def _scope_allowed(entry_scope: list[str], allowed_scope: list[str]) -> bool:
        return set(entry_scope).issubset(set(allowed_scope))

    def project(self, entries: Iterable[MemoryEntry], *, policy: ReadPolicy, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        policy_body = policy.canonical()
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", minimum=1)
        nonce = _text(nonce, "nonce", 256)
        if self._version >= self.max_entries:
            raise MemoryReadError("projection bound exceeded")
        accepted: list[dict[str, Any]] = []
        excluded: list[dict[str, str]] = []
        seen: set[str] = set()
        total_bytes = 0
        raw_entries = list(entries)
        if len(raw_entries) > MAX_ENTRIES:
            raise MemoryReadError("input entry bound exceeded")
        for entry in raw_entries:
            body = entry.canonical()
            candidate_digest = body["candidate_digest"]
            if candidate_digest in seen:
                excluded.append({"candidate_digest": candidate_digest, "reason": "duplicate"})
                continue
            seen.add(candidate_digest)
            reason = None
            if body["generation"] != current_generation:
                reason = "generation_fence"
            elif body["created_at"] > now or now - body["created_at"] > policy_body["max_age_seconds"] or body["expires_at"] <= now:
                reason = "stale_or_expired"
            elif not self._scope_allowed(body["scope"], policy_body["allowed_scope"]):
                reason = "scope_exceeds_policy"
            elif body["quarantined"] or body["injection_signaled"] or body["trust"] in {"quarantined", "untrusted"} or body["verification"] == "unverified":
                reason = "quarantined_or_unverified"
            elif TRUST_ORDER[body["trust"]] < TRUST_ORDER[policy_body["minimum_trust"]] or VERIFICATION_ORDER[body["verification"]] < VERIFICATION_ORDER[policy_body["minimum_verification"]]:
                reason = "below_policy_threshold"
            if reason is not None:
                if policy_body["context"] == "audit" and policy_body["allow_quarantined_in_audit"]:
                    excluded.append({"candidate_digest": candidate_digest, "reason": reason})
                    accepted.append({"memory_id": body["memory_id"], "candidate_digest": candidate_digest, "content_digest": body["content_digest"], "provenance_digest": body["provenance_digest"], "source_kind": body["source_kind"], "trust": body["trust"], "verification": body["verification"], "classification": "quarantined_evidence", "data_only": True, "instruction_authority": False})
                else:
                    excluded.append({"candidate_digest": candidate_digest, "reason": reason})
                continue
            estimated = body["estimated_bytes"] or 1
            if len(accepted) >= policy_body["max_entries"]:
                excluded.append({"candidate_digest": candidate_digest, "reason": "entry_budget"})
                continue
            if total_bytes + estimated > policy_body["max_bytes"]:
                excluded.append({"candidate_digest": candidate_digest, "reason": "byte_budget"})
                continue
            total_bytes += estimated
            accepted.append({"memory_id": body["memory_id"], "candidate_digest": candidate_digest, "content_digest": body["content_digest"], "provenance_digest": body["provenance_digest"], "source_kind": body["source_kind"], "memory_class": body["memory_class"], "trust": body["trust"], "verification": body["verification"], "classification": "verified_data", "data_only": True, "instruction_authority": False})
        projection = {"schema": SCHEMA, "policy": policy_body, "generation": current_generation, "entries": accepted, "excluded": excluded, "total_bytes": total_bytes, "authority": {"model_output_is_authority": False, "provider_metadata_is_authority": False, "memory_is_execution": False, "memory_is_instruction_authority": False, "projection_is_tool_permission": False, "production_approval": False}}
        projection_digest = digest({"projection": projection, "nonce": nonce})
        if projection_digest in self._projection_digests:
            raise MemoryReadError("projection replay detected")
        self._projection_digests.add(projection_digest)
        self._version += 1
        return {**projection, "projection_digest": projection_digest, "verified": True}

    def verify(self, projection: Mapping[str, Any], *, expected_context: str, expected_generation: int) -> dict[str, Any]:
        if not isinstance(projection, Mapping) or projection.get("schema") != SCHEMA:
            raise MemoryReadError("projection schema unsupported")
        authority = projection.get("authority")
        if not isinstance(authority, Mapping) or any(authority.get(key) is not False for key in ("model_output_is_authority", "provider_metadata_is_authority", "memory_is_execution", "memory_is_instruction_authority", "projection_is_tool_permission")):
            raise MemoryReadError("projection authority boundary missing")
        if projection.get("verified") is not True:
            raise MemoryReadError("projection is not verified")
        policy = projection.get("policy")
        if not isinstance(policy, Mapping) or policy.get("context") != _text(expected_context, "expected_context"):
            raise MemoryReadError("projection context mismatch")
        if projection.get("generation") != _u64(expected_generation, "expected_generation", minimum=1):
            raise MemoryReadError("projection generation mismatch")
        for entry in projection.get("entries", []):
            if entry.get("data_only") is not True or entry.get("instruction_authority") is not False:
                raise MemoryReadError("projection entry is not data-only")
        return {"verified": True, "projection_digest": _digest(projection.get("projection_digest"), "projection_digest"), "entry_count": len(projection.get("entries", [])), "excluded_count": len(projection.get("excluded", [])), "data_only": True, "memory_is_instruction_authority": False}

    def digest(self) -> str:
        return digest({"version": self._version, "projection_digests": sorted(self._projection_digests)})
