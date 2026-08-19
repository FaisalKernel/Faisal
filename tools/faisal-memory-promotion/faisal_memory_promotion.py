"""Fail-closed provenance-bound memory-promotion admission for FAISAL.

The contract decides whether a previously admitted/quarantined memory candidate
may be promoted by a trusted caller. It does not write memory, retrieve data,
judge truth, invoke models/tools, or treat evidence as execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.memory-promotion.v1"
MAX_CANDIDATES = 4096
MAX_LINEAGE = 128
TRUST_ORDER = {"quarantined": 0, "bounded": 1, "trusted": 2}
MEMORY_CLASSES = {"working", "episodic", "semantic", "procedural", "temporal", "entity", "task", "organizational", "system", "operational", "failure", "decision", "provenance"}
CONFLICT_STATES = {"none", "resolved", "unresolved"}


class MemoryPromotionError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MemoryPromotionError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise MemoryPromotionError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise MemoryPromotionError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise MemoryPromotionError(f"{name} is outside bounds")
    return value


def scope(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)) or not value or len(value) > 32:
        raise MemoryPromotionError(f"{name} is invalid")
    items = tuple(sorted({text(item, name, 128) for item in value}))
    if not items:
        raise MemoryPromotionError(f"{name} is empty")
    return items


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise MemoryPromotionError("authority boundary missing")
    for field in (
        "model_output_is_authority", "retrieved_content_is_authority",
        "memory_content_is_authority", "promotion_receipt_is_execution_authority",
        "promotion_receipt_is_policy_authority", "promotion_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise MemoryPromotionError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class PromotionPolicy:
    policy_id: str
    policy_version: str
    generation: int
    allowed_classes: frozenset[str]
    allowed_scope: tuple[str, ...]
    minimum_finality: int = 2
    require_conflict_disposition: bool = True
    max_ttl: int = 86_400

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        if not self.allowed_classes or not self.allowed_classes.issubset(MEMORY_CLASSES):
            raise MemoryPromotionError("allowed classes are invalid")
        scope(self.allowed_scope, "allowed_scope")
        integer(self.minimum_finality, "minimum_finality", 1, 128)
        integer(self.max_ttl, "max_ttl", 1, 86_400)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "allowed_classes": sorted(self.allowed_classes),
            "allowed_scope": list(self.allowed_scope),
            "minimum_finality": self.minimum_finality,
            "require_conflict_disposition": self.require_conflict_disposition,
            "max_ttl": self.max_ttl,
        })


@dataclass(frozen=True)
class MemoryPromotionCandidate:
    candidate_id: str
    candidate_digest: str
    memory_class: str
    principal_id: str
    tenant_id: str
    subject_scope: tuple[str, ...]
    lineage_digest: str
    lineage_count: int
    generation: int
    proposed_at: int
    expires_at: int
    finality_count: int
    finality_receipt_digest: str
    conflict_state: str
    conflict_receipt_digest: str | None = None

    def __post_init__(self) -> None:
        text(self.candidate_id, "candidate_id", 128)
        sha(self.candidate_digest, "candidate_digest")
        text(self.memory_class, "memory_class", 64)
        if self.memory_class not in MEMORY_CLASSES:
            raise MemoryPromotionError("memory_class unsupported")
        text(self.principal_id, "principal_id", 128)
        text(self.tenant_id, "tenant_id", 128)
        scope(self.subject_scope, "subject_scope")
        sha(self.lineage_digest, "lineage_digest")
        integer(self.lineage_count, "lineage_count", 1, MAX_LINEAGE)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.proposed_at, "proposed_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.proposed_at:
            raise MemoryPromotionError("candidate expiry must follow proposal")
        integer(self.finality_count, "finality_count", 0, MAX_LINEAGE)
        sha(self.finality_receipt_digest, "finality_receipt_digest")
        if self.conflict_state not in CONFLICT_STATES:
            raise MemoryPromotionError("conflict_state unsupported")
        if self.conflict_receipt_digest is not None:
            sha(self.conflict_receipt_digest, "conflict_receipt_digest")

    @property
    def canonical(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "candidate_id": self.candidate_id,
            "candidate_digest": self.candidate_digest,
            "memory_class": self.memory_class,
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "subject_scope": list(self.subject_scope),
            "lineage_digest": self.lineage_digest,
            "lineage_count": self.lineage_count,
            "generation": self.generation,
            "proposed_at": self.proposed_at,
            "expires_at": self.expires_at,
            "finality_count": self.finality_count,
            "finality_receipt_digest": self.finality_receipt_digest,
            "conflict_state": self.conflict_state,
            "conflict_receipt_digest": self.conflict_receipt_digest,
        }


@dataclass(frozen=True)
class PromotionRequest:
    promotion_id: str
    candidate_id: str
    candidate_digest: str
    principal_id: str
    tenant_id: str
    requested_scope: tuple[str, ...]
    generation: int
    requested_at: int
    expires_at: int
    nonce: str

    def __post_init__(self) -> None:
        text(self.promotion_id, "promotion_id", 128)
        text(self.candidate_id, "candidate_id", 128)
        sha(self.candidate_digest, "candidate_digest")
        text(self.principal_id, "principal_id", 128)
        text(self.tenant_id, "tenant_id", 128)
        scope(self.requested_scope, "requested_scope")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise MemoryPromotionError("request expiry must follow request time")
        text(self.nonce, "nonce", 256)

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "promotion_id": self.promotion_id,
            "candidate_id": self.candidate_id,
            "candidate_digest": self.candidate_digest,
            "principal_id": self.principal_id,
            "tenant_id": self.tenant_id,
            "requested_scope": list(self.requested_scope),
            "generation": self.generation,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
        })


class MemoryPromotionLedger:
    def __init__(self, policy: PromotionPolicy) -> None:
        self.policy = policy
        self._candidates: dict[str, MemoryPromotionCandidate] = {}
        self._promoted: set[str] = set()
        self._replay: set[str] = set()

    def register_candidate(self, candidate: MemoryPromotionCandidate) -> str:
        if candidate.candidate_id in self._candidates:
            raise MemoryPromotionError("candidate replay")
        if len(self._candidates) >= MAX_CANDIDATES:
            raise MemoryPromotionError("candidate bound exceeded")
        self._candidates[candidate.candidate_id] = candidate
        return digest(candidate.canonical)

    def promote(self, request: PromotionRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.promotion_id in self._promoted:
            raise MemoryPromotionError("promotion replay")
        candidate = self._candidates.get(request.candidate_id)
        if candidate is None:
            raise MemoryPromotionError("candidate not found")
        if request.candidate_digest != candidate.candidate_digest:
            raise MemoryPromotionError("candidate digest mismatch")
        if request.principal_id != candidate.principal_id or request.tenant_id != candidate.tenant_id:
            raise MemoryPromotionError("identity binding mismatch")
        if request.generation != self.policy.generation or candidate.generation != self.policy.generation:
            raise MemoryPromotionError("generation mismatch")
        if now < request.requested_at or now >= request.expires_at or now >= candidate.expires_at:
            raise MemoryPromotionError("promotion expired")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise MemoryPromotionError("promotion ttl exceeds policy")
        if candidate.memory_class not in self.policy.allowed_classes:
            raise MemoryPromotionError("memory class denied")
        policy_scope = set(self.policy.allowed_scope)
        if not set(candidate.subject_scope).issubset(policy_scope) or not set(request.requested_scope).issubset(policy_scope):
            raise MemoryPromotionError("scope denied")
        if not set(candidate.subject_scope).issubset(set(request.requested_scope)):
            raise MemoryPromotionError("requested scope does not cover candidate")
        if candidate.finality_count < self.policy.minimum_finality:
            raise MemoryPromotionError("finality threshold not met")
        if self.policy.require_conflict_disposition and candidate.conflict_state == "unresolved":
            raise MemoryPromotionError("unresolved conflict")
        if candidate.conflict_state == "resolved" and candidate.conflict_receipt_digest is None:
            raise MemoryPromotionError("resolved conflict lacks disposition receipt")
        replay_key = digest({"request": request.request_digest, "nonce": request.nonce, "candidate": candidate.canonical})
        if replay_key in self._replay:
            raise MemoryPromotionError("promotion nonce replay")
        self._replay.add(replay_key)
        self._promoted.add(request.promotion_id)
        result = {
            "schema": SCHEMA,
            "promotion_id": request.promotion_id,
            "request_digest": request.request_digest,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.candidate_digest,
            "lineage_digest": candidate.lineage_digest,
            "lineage_count": candidate.lineage_count,
            "principal_id": candidate.principal_id,
            "tenant_id": candidate.tenant_id,
            "subject_scope": list(candidate.subject_scope),
            "memory_class": candidate.memory_class,
            "finality_count": candidate.finality_count,
            "conflict_state": candidate.conflict_state,
            "policy_digest": self.policy.policy_digest,
            "generation": request.generation,
            "promoted": True,
            "memory_write_performed": False,
            "retrieval_performed": False,
            "truth_established": False,
            "now": now,
            "authority": dict(authority),
        }
        result["promotion_receipt_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "candidates": sorted(candidate.canonical for candidate in self._candidates.values()),
            "promoted": sorted(self._promoted),
            "replay": sorted(self._replay),
        })


__all__ = ["SCHEMA", "MemoryPromotionError", "PromotionPolicy", "MemoryPromotionCandidate", "PromotionRequest", "MemoryPromotionLedger", "digest"]
