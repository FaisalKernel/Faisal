"""Fail-closed workload migration admission receipts for FAISAL.

This module admits evidence for a two-phase migration handoff. It does not
move processes, copy memory/KV cache, contact nodes, invoke agents, or claim
hardware qualification. All remote and model-derived inputs are data only.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, FrozenSet

SCHEMA = "org.faisal.migration.v1"
MAX_CAPABILITIES = 128
MAX_MIGRATIONS = 4096


class MigrationError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MigrationError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise MigrationError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise MigrationError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise MigrationError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise MigrationError(f"{name} must be boolean")
    return value


def capabilities(value: Any, name: str) -> FrozenSet[str]:
    if not isinstance(value, (set, frozenset, tuple, list)) or len(value) > MAX_CAPABILITIES:
        raise MigrationError(f"{name} is invalid")
    result = frozenset(text(item, f"{name}_item", 128) for item in value)
    if len(result) != len(value):
        raise MigrationError(f"{name} contains duplicates")
    return result


def authority(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise MigrationError("authority boundary missing")
    fields = (
        "model_output_is_authority",
        "source_agent_card_is_authority",
        "destination_agent_card_is_authority",
        "readiness_evidence_is_hardware_qualification",
        "migration_receipt_is_execution_authority",
        "state_manifest_is_trust_root",
    )
    for field in fields:
        if value.get(field) is not False:
            raise MigrationError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ReadinessEvidence:
    network_path_ready: bool
    storage_ready: bool
    accelerator_ready: bool
    sandbox_ready: bool
    observability_ready: bool
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("network_path_ready", "storage_ready", "accelerator_ready", "sandbox_ready", "observability_ready"):
            boolean(getattr(self, name), name)
        sha(self.evidence_digest, "evidence_digest")

    def as_dict(self) -> dict[str, Any]:
        return {
            "network_path_ready": self.network_path_ready,
            "storage_ready": self.storage_ready,
            "accelerator_ready": self.accelerator_ready,
            "sandbox_ready": self.sandbox_ready,
            "observability_ready": self.observability_ready,
            "evidence_digest": self.evidence_digest,
        }


@dataclass(frozen=True)
class MigrationPolicy:
    allowed_destinations: FrozenSet[str]
    required_capabilities: FrozenSet[str]
    required_readiness: FrozenSet[str]
    max_ttl: int
    require_rollback: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_destinations", capabilities(self.allowed_destinations, "allowed_destinations"))
        object.__setattr__(self, "required_capabilities", capabilities(self.required_capabilities, "required_capabilities"))
        object.__setattr__(self, "required_readiness", capabilities(self.required_readiness, "required_readiness"))
        integer(self.max_ttl, "max_ttl", 1, 86_400)
        boolean(self.require_rollback, "require_rollback")


@dataclass(frozen=True)
class MigrationRequest:
    migration_id: str
    source_node: str
    destination_node: str
    objective_id: str
    task_id: str
    generation: int
    lifecycle_digest: str
    checkpoint_digest: str
    trace_digest: str
    state_manifest_digest: str
    artifact_digest: str
    memory_generation: int
    source_capabilities: FrozenSet[str]
    destination_capabilities: FrozenSet[str]
    readiness: ReadinessEvidence
    idempotency_key: str
    rollback_checkpoint_digest: str
    requested_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for value, name in ((self.migration_id, "migration_id"), (self.source_node, "source_node"), (self.destination_node, "destination_node"), (self.objective_id, "objective_id"), (self.task_id, "task_id"), (self.idempotency_key, "idempotency_key")):
            text(value, name, 256)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.memory_generation, "memory_generation", 0, 2**63 - 1)
        for value, name in ((self.lifecycle_digest, "lifecycle_digest"), (self.checkpoint_digest, "checkpoint_digest"), (self.trace_digest, "trace_digest"), (self.state_manifest_digest, "state_manifest_digest"), (self.artifact_digest, "artifact_digest"), (self.rollback_checkpoint_digest, "rollback_checkpoint_digest")):
            sha(value, name)
        object.__setattr__(self, "source_capabilities", capabilities(self.source_capabilities, "source_capabilities"))
        object.__setattr__(self, "destination_capabilities", capabilities(self.destination_capabilities, "destination_capabilities"))
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise MigrationError("migration expiry must follow request time")

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "migration_id": self.migration_id,
            "source_node": self.source_node,
            "destination_node": self.destination_node,
            "objective_id": self.objective_id,
            "task_id": self.task_id,
            "generation": self.generation,
            "lifecycle_digest": self.lifecycle_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "trace_digest": self.trace_digest,
            "state_manifest_digest": self.state_manifest_digest,
            "artifact_digest": self.artifact_digest,
            "memory_generation": self.memory_generation,
            "source_capabilities": sorted(self.source_capabilities),
            "destination_capabilities": sorted(self.destination_capabilities),
            "readiness": self.readiness.as_dict(),
            "idempotency_key": self.idempotency_key,
            "rollback_checkpoint_digest": self.rollback_checkpoint_digest,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
        })


class MigrationLedger:
    def __init__(self, *, generation: int, policy: MigrationPolicy, max_migrations: int = MAX_MIGRATIONS) -> None:
        integer(generation, "generation", 0, 2**63 - 1)
        integer(max_migrations, "max_migrations", 1, MAX_MIGRATIONS)
        self.generation = generation
        self.policy = policy
        self.max_migrations = max_migrations
        self._prepared: dict[str, MigrationRequest] = {}
        self._committed: set[str] = set()
        self._idempotency: set[str] = set()

    def _check_common(self, request: MigrationRequest, now: int) -> None:
        integer(now, "now", 0, 2**63 - 1)
        if request.generation != self.generation:
            raise MigrationError("generation mismatch")
        if request.source_node == request.destination_node:
            raise MigrationError("source and destination must differ")
        if request.destination_node not in self.policy.allowed_destinations:
            raise MigrationError("destination not allowed")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise MigrationError("migration TTL exceeds policy")
        if now > request.expires_at:
            raise MigrationError("migration expired")
        if not self.policy.required_capabilities.issubset(request.source_capabilities):
            raise MigrationError("source lacks required capabilities")
        if not request.destination_capabilities.issubset(request.source_capabilities):
            raise MigrationError("destination capabilities are not attenuated")
        readiness = request.readiness.as_dict()
        for name in self.policy.required_readiness:
            if readiness.get(name) is not True:
                raise MigrationError(f"required readiness missing: {name}")
        if self.policy.require_rollback:
            sha(request.rollback_checkpoint_digest, "rollback_checkpoint_digest")

    def prepare(self, request: MigrationRequest, *, now: int, authority_boundary: Mapping[str, Any]) -> dict[str, Any]:
        authority(authority_boundary)
        self._check_common(request, now)
        if request.migration_id in self._prepared or request.migration_id in self._committed:
            raise MigrationError("migration replay")
        if request.idempotency_key in self._idempotency:
            raise MigrationError("idempotency replay")
        if len(self._prepared) + len(self._committed) >= self.max_migrations:
            raise MigrationError("migration bound exceeded")
        self._prepared[request.migration_id] = request
        self._idempotency.add(request.idempotency_key)
        receipt = {
            "schema": SCHEMA,
            "phase": "prepared",
            "migration_id": request.migration_id,
            "request_digest": request.request_digest,
            "source_node": request.source_node,
            "destination_node": request.destination_node,
            "objective_id": request.objective_id,
            "task_id": request.task_id,
            "generation": request.generation,
            "checkpoint_digest": request.checkpoint_digest,
            "trace_digest": request.trace_digest,
            "state_manifest_digest": request.state_manifest_digest,
            "artifact_digest": request.artifact_digest,
            "memory_generation": request.memory_generation,
            "destination_capabilities": sorted(request.destination_capabilities),
            "readiness_evidence_digest": request.readiness.evidence_digest,
            "rollback_checkpoint_digest": request.rollback_checkpoint_digest,
            "expires_at": request.expires_at,
            "admitted": True,
            "migration_executed": False,
            "authority": dict(authority_boundary),
        }
        receipt["receipt_digest"] = digest(receipt)
        return receipt

    def commit(self, migration_id: str, *, destination_state_digest: str, destination_checkpoint_digest: str, destination_trace_digest: str, now: int, authority_boundary: Mapping[str, Any]) -> dict[str, Any]:
        authority(authority_boundary)
        text(migration_id, "migration_id", 256)
        sha(destination_state_digest, "destination_state_digest")
        sha(destination_checkpoint_digest, "destination_checkpoint_digest")
        sha(destination_trace_digest, "destination_trace_digest")
        integer(now, "now", 0, 2**63 - 1)
        request = self._prepared.get(migration_id)
        if request is None:
            raise MigrationError("unknown or already committed migration")
        if now > request.expires_at:
            raise MigrationError("migration expired before commit")
        self._prepared.pop(migration_id)
        self._committed.add(migration_id)
        receipt = {
            "schema": SCHEMA,
            "phase": "committed",
            "migration_id": migration_id,
            "request_digest": request.request_digest,
            "source_node": request.source_node,
            "destination_node": request.destination_node,
            "destination_state_digest": destination_state_digest,
            "destination_checkpoint_digest": destination_checkpoint_digest,
            "destination_trace_digest": destination_trace_digest,
            "rollback_checkpoint_digest": request.rollback_checkpoint_digest,
            "generation": request.generation,
            "committed_at": now,
            "admitted": True,
            "migration_executed": False,
            "authority": dict(authority_boundary),
        }
        receipt["receipt_digest"] = digest(receipt)
        return receipt

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "generation": self.generation, "prepared": sorted(self._prepared), "committed": sorted(self._committed), "idempotency": sorted(self._idempotency)})


__all__ = ["SCHEMA", "MigrationError", "ReadinessEvidence", "MigrationPolicy", "MigrationRequest", "MigrationLedger", "digest"]
