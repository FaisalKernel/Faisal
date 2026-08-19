"""Fail-closed task-consistent model-routing leases for FAISAL.

This contract binds one caller-selected endpoint to every turn of a task trace
and closes the task with delayed caller-observed outcome evidence. It is
provider-neutral and evidence-only: it never invokes models, changes routing
statistics, treats endpoint metadata as authority, or authorizes side effects.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.task-routing.v1"
MAX_TASKS = 4096
MAX_TURNS = 4096
MAX_ENDPOINTS = 256


class TaskRoutingError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise TaskRoutingError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise TaskRoutingError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise TaskRoutingError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise TaskRoutingError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TaskRoutingError(f"{name} must be boolean")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise TaskRoutingError("authority boundary missing")
    for field in (
        "model_output_is_authority",
        "endpoint_metadata_is_authority",
        "route_outcome_is_authority",
        "task_routing_receipt_is_execution_authority",
        "task_routing_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise TaskRoutingError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class TaskRoutingPolicy:
    policy_id: str
    policy_version: str
    generation: int
    max_tasks: int = MAX_TASKS
    max_turns: int = MAX_TURNS
    max_ttl: int = 3600

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.max_tasks, "max_tasks", 1, MAX_TASKS)
        integer(self.max_turns, "max_turns", 1, MAX_TURNS)
        integer(self.max_ttl, "max_ttl", 1, 86_400)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "max_tasks": self.max_tasks,
            "max_turns": self.max_turns,
            "max_ttl": self.max_ttl,
        })


@dataclass(frozen=True)
class TaskRouteLeaseRequest:
    lease_id: str
    task_id: str
    route_digest: str
    endpoint_ids: tuple[str, ...]
    selected_endpoint_id: str
    generation: int
    admitted_at: int
    expires_at: int
    task_context_digest: str
    route_evidence_digest: str
    max_turns: int

    def __post_init__(self) -> None:
        text(self.lease_id, "lease_id", 128)
        text(self.task_id, "task_id", 128)
        sha(self.route_digest, "route_digest")
        if not isinstance(self.endpoint_ids, tuple) or not self.endpoint_ids or len(self.endpoint_ids) > MAX_ENDPOINTS:
            raise TaskRoutingError("endpoint_ids are invalid")
        for endpoint in self.endpoint_ids:
            text(endpoint, "endpoint_id", 128)
        if len(set(self.endpoint_ids)) != len(self.endpoint_ids):
            raise TaskRoutingError("endpoint_ids contain duplicates")
        text(self.selected_endpoint_id, "selected_endpoint_id", 128)
        if self.selected_endpoint_id not in self.endpoint_ids:
            raise TaskRoutingError("selected endpoint is not in route evidence")
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.admitted_at, "admitted_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.admitted_at:
            raise TaskRoutingError("expires_at must follow admitted_at")
        sha(self.task_context_digest, "task_context_digest")
        sha(self.route_evidence_digest, "route_evidence_digest")
        integer(self.max_turns, "max_turns", 1, MAX_TURNS)

    @property
    def lease_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "lease_id": self.lease_id,
            "task_id": self.task_id,
            "route_digest": self.route_digest,
            "endpoint_ids": list(self.endpoint_ids),
            "selected_endpoint_id": self.selected_endpoint_id,
            "generation": self.generation,
            "admitted_at": self.admitted_at,
            "expires_at": self.expires_at,
            "task_context_digest": self.task_context_digest,
            "route_evidence_digest": self.route_evidence_digest,
            "max_turns": self.max_turns,
        })


@dataclass(frozen=True)
class TaskTurnRequest:
    turn_id: str
    lease_id: str
    task_id: str
    request_digest: str
    endpoint_id: str
    generation: int
    sequence: int
    observed_at: int

    def __post_init__(self) -> None:
        text(self.turn_id, "turn_id", 128)
        text(self.lease_id, "lease_id", 128)
        text(self.task_id, "task_id", 128)
        sha(self.request_digest, "request_digest")
        text(self.endpoint_id, "endpoint_id", 128)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.sequence, "sequence", 1, MAX_TURNS)
        integer(self.observed_at, "observed_at", 0, 2**63 - 1)

    @property
    def turn_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "turn_id": self.turn_id,
            "lease_id": self.lease_id,
            "task_id": self.task_id,
            "request_digest": self.request_digest,
            "endpoint_id": self.endpoint_id,
            "generation": self.generation,
            "sequence": self.sequence,
            "observed_at": self.observed_at,
        })


class TaskRoutingLedger:
    def __init__(self, policy: TaskRoutingPolicy) -> None:
        self.policy = policy
        self._leases: dict[str, TaskRouteLeaseRequest] = {}
        self._turns: dict[str, list[TaskTurnRequest]] = {}
        self._terminal: set[str] = set()

    def admit(self, request: TaskRouteLeaseRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.lease_id in self._leases or request.task_id in {item.task_id for item in self._leases.values()}:
            raise TaskRoutingError("task or lease replay")
        if len(self._leases) >= self.policy.max_tasks:
            raise TaskRoutingError("task limit exceeded")
        if request.generation != self.policy.generation:
            raise TaskRoutingError("generation mismatch")
        if now < request.admitted_at or now >= request.expires_at:
            raise TaskRoutingError("lease is expired or not yet admitted")
        if request.expires_at - request.admitted_at > self.policy.max_ttl:
            raise TaskRoutingError("lease ttl exceeds policy")
        if request.max_turns > self.policy.max_turns:
            raise TaskRoutingError("turn limit exceeds policy")
        self._leases[request.lease_id] = request
        self._turns[request.lease_id] = []
        result = {
            "schema": SCHEMA,
            "lease_id": request.lease_id,
            "task_id": request.task_id,
            "lease_digest": request.lease_digest,
            "policy_digest": self.policy.policy_digest,
            "generation": request.generation,
            "selected_endpoint_id": request.selected_endpoint_id,
            "pinned_for_task": True,
            "expires_at": request.expires_at,
            "verdict": "admit_task_route_lease",
            "execution_performed": False,
            "route_outcomes_are_authority": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def admit_turn(self, request: TaskTurnRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        lease = self._leases.get(request.lease_id)
        if lease is None:
            raise TaskRoutingError("unknown lease")
        if request.task_id != lease.task_id or request.generation != lease.generation:
            raise TaskRoutingError("turn identity or generation mismatch")
        if request.lease_id in self._terminal:
            raise TaskRoutingError("task is terminal")
        if now < lease.admitted_at or now >= lease.expires_at:
            raise TaskRoutingError("task lease expired")
        if request.endpoint_id != lease.selected_endpoint_id:
            raise TaskRoutingError("task backend pin violated")
        turns = self._turns[request.lease_id]
        if len(turns) >= lease.max_turns:
            raise TaskRoutingError("task turn limit exceeded")
        if not turns and request.sequence != 1:
            raise TaskRoutingError("first turn sequence must be one")
        if turns and request.sequence != turns[-1].sequence + 1:
            raise TaskRoutingError("turn sequence discontinuity")
        if any(turn.turn_id == request.turn_id for turn in turns):
            raise TaskRoutingError("turn replay")
        turns.append(request)
        result = {
            "schema": SCHEMA,
            "lease_id": lease.lease_id,
            "task_id": lease.task_id,
            "turn_id": request.turn_id,
            "sequence": request.sequence,
            "endpoint_id": request.endpoint_id,
            "pinned_for_task": True,
            "turn_digest": request.turn_digest,
            "execution_performed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def complete(self, *, lease_id: str, success: bool, quality_milli: int, latency_ms: int, evidence_digest: str, terminal_trace_digest: str, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if not isinstance(success, bool):
            raise TaskRoutingError("success must be boolean")
        integer(quality_milli, "quality_milli", 0, 1000)
        integer(latency_ms, "latency_ms", 0, 86_400_000)
        sha(evidence_digest, "evidence_digest")
        sha(terminal_trace_digest, "terminal_trace_digest")
        lease = self._leases.get(lease_id)
        if lease is None:
            raise TaskRoutingError("unknown lease")
        if lease_id in self._terminal:
            raise TaskRoutingError("terminal replay")
        if now < lease.admitted_at or now >= lease.expires_at:
            raise TaskRoutingError("completion after lease expiry")
        if not self._turns[lease_id]:
            raise TaskRoutingError("completion requires at least one turn")
        self._terminal.add(lease_id)
        result = {
            "schema": SCHEMA,
            "lease_id": lease_id,
            "task_id": lease.task_id,
            "selected_endpoint_id": lease.selected_endpoint_id,
            "turn_count": len(self._turns[lease_id]),
            "success": success,
            "quality_milli": quality_milli,
            "latency_ms": latency_ms,
            "evidence_digest": evidence_digest,
            "terminal_trace_digest": terminal_trace_digest,
            "terminal": True,
            "delayed_feedback": True,
            "routing_statistics_updated": False,
            "execution_performed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["completion_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "leases": sorted(request.lease_digest for request in self._leases.values()),
            "turns": sorted(turn.turn_digest for turns in self._turns.values() for turn in turns),
            "terminal": sorted(self._terminal),
        })


__all__ = [
    "SCHEMA", "TaskRoutingError", "TaskRoutingPolicy", "TaskRouteLeaseRequest",
    "TaskTurnRequest", "TaskRoutingLedger", "digest",
]
