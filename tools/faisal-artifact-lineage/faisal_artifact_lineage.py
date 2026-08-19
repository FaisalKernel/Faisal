"""Fail-closed immutable artifact lineage and refinement admission for FAISAL.

The contract records artifact/task lineage and admits a new refinement only when
it references an immutable prior artifact, remains within scope, and carries
explicit caller acceptance evidence. It never creates tasks, mutates artifacts,
invokes agents/tools, or treats model output as acceptance authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.artifact-lineage.v1"
MAX_ARTIFACTS = 8192
MAX_LINEAGE_DEPTH = 128
ARTIFACT_STATES = {"provisional", "accepted", "rejected", "superseded"}
TASK_STATES = {"active", "completed", "cancelled", "rejected", "failed"}


class ArtifactLineageError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ArtifactLineageError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise ArtifactLineageError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise ArtifactLineageError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise ArtifactLineageError(f"{name} is outside bounds")
    return value


def scope(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)) or not value or len(value) > 32:
        raise ArtifactLineageError(f"{name} is invalid")
    items = tuple(sorted({text(item, name, 128) for item in value}))
    if not items:
        raise ArtifactLineageError(f"{name} is empty")
    return items


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ArtifactLineageError("authority boundary missing")
    for field in (
        "model_output_is_authority", "artifact_content_is_authority",
        "agent_output_is_authority", "acceptance_evidence_is_execution_authority",
        "lineage_receipt_is_policy_authority", "lineage_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise ArtifactLineageError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class LineagePolicy:
    policy_id: str
    policy_version: str
    generation: int
    allowed_scope: tuple[str, ...]
    max_depth: int = MAX_LINEAGE_DEPTH
    max_ttl: int = 86_400
    require_acceptance: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        scope(self.allowed_scope, "allowed_scope")
        integer(self.max_depth, "max_depth", 1, MAX_LINEAGE_DEPTH)
        integer(self.max_ttl, "max_ttl", 1, 86_400)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "allowed_scope": list(self.allowed_scope),
            "max_depth": self.max_depth,
            "max_ttl": self.max_ttl,
            "require_acceptance": self.require_acceptance,
        })


@dataclass(frozen=True)
class TaskSnapshot:
    task_id: str
    context_id: str
    tenant_id: str
    task_state: str
    generation: int
    task_digest: str
    terminal_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.task_id, "task_id", 128)
        text(self.context_id, "context_id", 128)
        text(self.tenant_id, "tenant_id", 128)
        if self.task_state not in TASK_STATES:
            raise ArtifactLineageError("task_state unsupported")
        integer(self.generation, "generation", 1, 2**63 - 1)
        sha(self.task_digest, "task_digest")
        integer(self.terminal_at, "terminal_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.terminal_at:
            raise ArtifactLineageError("task expiry must follow terminal time")


@dataclass(frozen=True)
class ArtifactSnapshot:
    artifact_id: str
    artifact_name: str
    task_id: str
    context_id: str
    tenant_id: str
    artifact_digest: str
    predecessor_digest: str | None
    version: int
    lineage_depth: int
    state: str
    generation: int
    created_at: int
    expires_at: int
    scope: tuple[str, ...]

    def __post_init__(self) -> None:
        text(self.artifact_id, "artifact_id", 128)
        text(self.artifact_name, "artifact_name", 256)
        text(self.task_id, "task_id", 128)
        text(self.context_id, "context_id", 128)
        text(self.tenant_id, "tenant_id", 128)
        sha(self.artifact_digest, "artifact_digest")
        if self.predecessor_digest is not None:
            sha(self.predecessor_digest, "predecessor_digest")
        integer(self.version, "version", 1, MAX_LINEAGE_DEPTH)
        integer(self.lineage_depth, "lineage_depth", 1, MAX_LINEAGE_DEPTH)
        if self.state not in ARTIFACT_STATES:
            raise ArtifactLineageError("artifact state unsupported")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.created_at, "created_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.created_at:
            raise ArtifactLineageError("artifact expiry must follow creation")
        scope(self.scope, "scope")

    @property
    def snapshot_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "artifact_id": self.artifact_id,
            "artifact_name": self.artifact_name,
            "task_id": self.task_id,
            "context_id": self.context_id,
            "tenant_id": self.tenant_id,
            "artifact_digest": self.artifact_digest,
            "predecessor_digest": self.predecessor_digest,
            "version": self.version,
            "lineage_depth": self.lineage_depth,
            "state": self.state,
            "generation": self.generation,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "scope": list(self.scope),
        })


@dataclass(frozen=True)
class RefinementRequest:
    refinement_id: str
    parent_task_id: str
    parent_artifact_id: str
    parent_artifact_digest: str
    child_task_id: str
    child_context_id: str
    child_artifact_id: str
    child_artifact_digest: str
    child_artifact_name: str
    requested_version: int
    requested_scope: tuple[str, ...]
    generation: int
    requested_at: int
    expires_at: int
    acceptance_digest: str | None
    nonce: str

    def __post_init__(self) -> None:
        text(self.refinement_id, "refinement_id", 128)
        text(self.parent_task_id, "parent_task_id", 128)
        text(self.parent_artifact_id, "parent_artifact_id", 128)
        sha(self.parent_artifact_digest, "parent_artifact_digest")
        text(self.child_task_id, "child_task_id", 128)
        text(self.child_context_id, "child_context_id", 128)
        text(self.child_artifact_id, "child_artifact_id", 128)
        sha(self.child_artifact_digest, "child_artifact_digest")
        text(self.child_artifact_name, "child_artifact_name", 256)
        integer(self.requested_version, "requested_version", 2, MAX_LINEAGE_DEPTH)
        scope(self.requested_scope, "requested_scope")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise ArtifactLineageError("refinement expiry must follow request")
        if self.acceptance_digest is not None:
            sha(self.acceptance_digest, "acceptance_digest")
        text(self.nonce, "nonce", 256)

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "refinement_id": self.refinement_id,
            "parent_task_id": self.parent_task_id,
            "parent_artifact_id": self.parent_artifact_id,
            "parent_artifact_digest": self.parent_artifact_digest,
            "child_task_id": self.child_task_id,
            "child_context_id": self.child_context_id,
            "child_artifact_id": self.child_artifact_id,
            "child_artifact_digest": self.child_artifact_digest,
            "child_artifact_name": self.child_artifact_name,
            "requested_version": self.requested_version,
            "requested_scope": list(self.requested_scope),
            "generation": self.generation,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
            "acceptance_digest": self.acceptance_digest,
        })


class ArtifactLineageLedger:
    def __init__(self, policy: LineagePolicy) -> None:
        self.policy = policy
        self._tasks: dict[str, TaskSnapshot] = {}
        self._artifacts: dict[str, ArtifactSnapshot] = {}
        self._refinements: set[str] = set()
        self._replay: set[str] = set()

    def register_task(self, task: TaskSnapshot) -> None:
        if task.task_id in self._tasks:
            raise ArtifactLineageError("task replay")
        self._tasks[task.task_id] = task

    def register_artifact(self, artifact: ArtifactSnapshot) -> None:
        if artifact.artifact_id in self._artifacts or any(x.artifact_digest == artifact.artifact_digest for x in self._artifacts.values()):
            raise ArtifactLineageError("artifact replay or duplicate digest")
        if len(self._artifacts) >= MAX_ARTIFACTS:
            raise ArtifactLineageError("artifact bound exceeded")
        self._artifacts[artifact.artifact_id] = artifact

    def admit_refinement(self, request: RefinementRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.refinement_id in self._refinements:
            raise ArtifactLineageError("refinement replay")
        parent_task = self._tasks.get(request.parent_task_id)
        parent_artifact = self._artifacts.get(request.parent_artifact_id)
        if parent_task is None or parent_artifact is None:
            raise ArtifactLineageError("parent task or artifact not found")
        if parent_task.task_state not in {"completed", "cancelled", "rejected", "failed"}:
            raise ArtifactLineageError("parent task is not terminal")
        if parent_artifact.state not in {"accepted", "superseded"}:
            raise ArtifactLineageError("parent artifact is not immutable accepted state")
        if request.parent_artifact_digest != parent_artifact.artifact_digest:
            raise ArtifactLineageError("parent artifact digest mismatch")
        if request.child_context_id != parent_task.context_id:
            raise ArtifactLineageError("context continuity mismatch")
        if request.generation != self.policy.generation or parent_task.generation != self.policy.generation or parent_artifact.generation != self.policy.generation:
            raise ArtifactLineageError("generation mismatch")
        if now < request.requested_at or now >= request.expires_at or now >= parent_task.expires_at or now >= parent_artifact.expires_at:
            raise ArtifactLineageError("refinement expired")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise ArtifactLineageError("refinement ttl exceeds policy")
        if request.requested_version != parent_artifact.version + 1:
            raise ArtifactLineageError("artifact version is not monotonic")
        if request.child_artifact_name != parent_artifact.artifact_name:
            raise ArtifactLineageError("artifact name continuity mismatch")
        if not set(parent_artifact.scope).issubset(set(request.requested_scope)):
            raise ArtifactLineageError("requested scope does not cover parent")
        if not set(request.requested_scope).issubset(set(self.policy.allowed_scope)):
            raise ArtifactLineageError("scope exceeds policy")
        if self.policy.require_acceptance and request.acceptance_digest is None:
            raise ArtifactLineageError("explicit acceptance evidence required")
        replay_key = digest({"request": request.request_digest, "nonce": request.nonce, "parent": parent_artifact.snapshot_digest})
        if replay_key in self._replay:
            raise ArtifactLineageError("refinement nonce replay")
        self._replay.add(replay_key)
        self._refinements.add(request.refinement_id)
        result = {
            "schema": SCHEMA,
            "refinement_id": request.refinement_id,
            "request_digest": request.request_digest,
            "parent_task_id": parent_task.task_id,
            "parent_artifact_id": parent_artifact.artifact_id,
            "parent_artifact_digest": parent_artifact.artifact_digest,
            "child_task_id": request.child_task_id,
            "child_context_id": request.child_context_id,
            "child_artifact_id": request.child_artifact_id,
            "child_artifact_digest": request.child_artifact_digest,
            "child_artifact_name": request.child_artifact_name,
            "parent_version": parent_artifact.version,
            "child_version": request.requested_version,
            "lineage_depth": parent_artifact.lineage_depth + 1,
            "accepted": True,
            "task_created": False,
            "artifact_mutated": False,
            "agents_invoked": False,
            "tools_executed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["refinement_receipt_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "tasks": sorted(self._tasks),
            "artifacts": sorted(self._artifacts),
            "refinements": sorted(self._refinements),
            "replay": sorted(self._replay),
        })


__all__ = ["SCHEMA", "ArtifactLineageError", "LineagePolicy", "TaskSnapshot", "ArtifactSnapshot", "RefinementRequest", "ArtifactLineageLedger", "digest"]
