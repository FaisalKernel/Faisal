"""Provider-neutral delegated-task lifecycle receipts for FAISAL.

This is a userspace/control-plane admission primitive.  It does not contact
remote agents, execute tasks, grant capabilities, or treat model/provider
metadata as authority.  It binds a long-running task lifecycle to an admitted
handoff, monotonically ordered trace events, generation, checkpoint lineage,
progress, cancellation, and terminal result evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.task-lifecycle.v1"
DIGEST_PREFIX = "sha256:"
MAX_TEXT = 512
MAX_EVENTS = 4096
STATUSES = {"admitted", "running", "paused", "cancel_requested", "cancelled", "completed", "failed"}
TERMINAL = {"cancelled", "completed", "failed"}
TRANSITIONS = {
    "admitted": {"running", "cancel_requested", "cancelled"},
    "running": {"running", "paused", "cancel_requested", "cancelled", "completed", "failed"},
    "paused": {"running", "cancel_requested", "cancelled", "failed"},
    "cancel_requested": {"cancelled"},
    "cancelled": set(),
    "completed": set(),
    "failed": set(),
}


class LifecycleError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: Any) -> str:
    return DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise LifecycleError(f"{name} must be a non-empty bounded string")
    return value


def _digest_text(value: Any, name: str) -> str:
    value = _text(value, name, 80)
    if not value.startswith(DIGEST_PREFIX) or len(value) != len(DIGEST_PREFIX) + 64:
        raise LifecycleError(f"{name} must be a SHA-256 digest")
    try:
        int(value[len(DIGEST_PREFIX):], 16)
    except ValueError as exc:
        raise LifecycleError(f"{name} must be a SHA-256 digest") from exc
    return value


def _u64(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > (2**64 - 1):
        raise LifecycleError(f"{name} must be an unsigned integer")
    return value


def _progress(value: Any) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0 or value > 1:
        raise LifecycleError("progress must be between 0 and 1")
    return float(value)


@dataclass(frozen=True)
class TaskPolicy:
    max_events: int = MAX_EVENTS
    max_ttl_seconds: int = 3600
    require_checkpoint_for_pause: bool = True
    require_result_for_completion: bool = True

    def __post_init__(self) -> None:
        if not 1 <= self.max_events <= MAX_EVENTS:
            raise LifecycleError("max_events is outside the bounded policy")
        _u64(self.max_ttl_seconds, "max_ttl_seconds", 1)

    def canonical(self) -> dict[str, Any]:
        return {
            "max_events": self.max_events,
            "max_ttl_seconds": self.max_ttl_seconds,
            "require_checkpoint_for_pause": self.require_checkpoint_for_pause,
            "require_result_for_completion": self.require_result_for_completion,
        }


@dataclass(frozen=True)
class TaskEvent:
    event_id: str
    status: str
    observed_at: int
    trace_position: int
    progress: float
    checkpoint_digest: str | None = None
    result_digest: str | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        _text(self.event_id, "event_id", 128)
        if self.status not in STATUSES:
            raise LifecycleError("unsupported task status")
        _u64(self.observed_at, "observed_at")
        _u64(self.trace_position, "trace_position")
        _progress(self.progress)
        if self.checkpoint_digest is not None:
            _digest_text(self.checkpoint_digest, "checkpoint_digest")
        if self.result_digest is not None:
            _digest_text(self.result_digest, "result_digest")
        if self.status == "completed" and self.result_digest is None:
            raise LifecycleError("completed event requires result_digest")
        if self.status == "failed" and self.error_code is None:
            raise LifecycleError("failed event requires error_code")
        if self.status == "cancelled" and self.error_code is None:
            raise LifecycleError("cancelled event requires error_code")
        if self.error_code is not None:
            _text(self.error_code, "error_code", 128)

    def canonical(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "status": self.status,
            "observed_at": self.observed_at,
            "trace_position": self.trace_position,
            "progress": self.progress,
            "checkpoint_digest": self.checkpoint_digest,
            "result_digest": self.result_digest,
            "error_code": self.error_code,
        }


class TaskLifecycleAdmission:
    """Admission and verification for a single delegated task lifecycle."""

    def __init__(self, *, max_tasks: int = 1024) -> None:
        if not 1 <= max_tasks <= 65536:
            raise LifecycleError("max_tasks is outside the bounded policy")
        self._max_tasks = max_tasks
        self._tasks: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    @staticmethod
    def _require_handoff(handoff_record: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]]:
        if not isinstance(handoff_record, Mapping) or handoff_record.get("status") != "admitted":
            raise LifecycleError("task requires an admitted handoff")
        digest = _digest_text(handoff_record.get("handoff_digest"), "handoff_digest")
        request = handoff_record.get("request")
        if not isinstance(request, Mapping):
            raise LifecycleError("handoff request is missing")
        if request.get("model_authority") is True or request.get("provider_authority") is True:
            raise LifecycleError("handoff authority flag is forbidden")
        return digest, handoff_record

    def admit(self, handoff_record: Mapping[str, Any], *, task_id: str, now: int,
              current_generation: int, expires_at: int, policy: TaskPolicy, nonce: str) -> dict[str, Any]:
        handoff_digest, handoff = self._require_handoff(handoff_record)
        task_id = _text(task_id, "task_id", 128)
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", 1)
        expires_at = _u64(expires_at, "expires_at")
        nonce = _text(nonce, "nonce", 128)
        if len(self._tasks) >= self._max_tasks:
            raise LifecycleError("task capacity exhausted")
        if task_id in self._tasks or nonce in self._nonces:
            raise LifecycleError("task admission replay")
        if expires_at <= now or expires_at - now > policy.max_ttl_seconds:
            raise LifecycleError("task expiry is stale or exceeds policy")
        request = handoff["request"]
        if request.get("generation") != current_generation:
            raise LifecycleError("handoff generation mismatch")
        record = {
            "schema": SCHEMA,
            "status": "admitted",
            "task_id": task_id,
            "handoff_digest": handoff_digest,
            "generation": current_generation,
            "issued_at": now,
            "expires_at": expires_at,
            "last_trace_position": 0,
            "progress": 0.0,
            "checkpoint_digest": None,
            "result_digest": None,
            "event_count": 0,
            "events": [],
            "authority": {
                "model_output_is_authority": False,
                "provider_metadata_is_authority": False,
                "task_is_execution": False,
                "executed_by_this_module": False,
                "production_approval": False,
            },
        }
        record["record_digest"] = _digest({k: v for k, v in record.items() if k != "record_digest"})
        self._tasks[task_id] = record
        self._nonces.add(nonce)
        return json.loads(json.dumps(record))

    def append(self, task_record: Mapping[str, Any], event: TaskEvent, *, now: int,
               current_generation: int, policy: TaskPolicy, nonce: str) -> dict[str, Any]:
        if not isinstance(task_record, Mapping) or task_record.get("schema") != SCHEMA:
            raise LifecycleError("invalid task record")
        task_id = _text(task_record.get("task_id"), "task_id", 128)
        stored = self._tasks.get(task_id)
        supplied_body = dict(task_record)
        supplied_digest = supplied_body.pop("record_digest", None)
        stored_body = dict(stored) if stored is not None else None
        if stored_body is not None:
            stored_body.pop("record_digest", None)
        if stored is None or supplied_digest != stored.get("record_digest") or supplied_body != stored_body:
            raise LifecycleError("task record missing or tampered")
        if task_record.get("authority", {}).get("task_is_execution") is not False:
            raise LifecycleError("task execution authority flag is forbidden")
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", 1)
        nonce = _text(nonce, "nonce", 128)
        if nonce in self._nonces:
            raise LifecycleError("event replay")
        if now > stored["expires_at"]:
            raise LifecycleError("task expired")
        if current_generation != stored["generation"]:
            raise LifecycleError("task generation mismatch")
        if len(stored["events"]) >= policy.max_events:
            raise LifecycleError("task event capacity exhausted")
        if event.observed_at < stored["issued_at"] or event.observed_at > now:
            raise LifecycleError("event time outside task window")
        if event.trace_position <= stored["last_trace_position"]:
            raise LifecycleError("trace position is not monotonic")
        previous_status = stored["status"]
        if event.status not in TRANSITIONS[previous_status]:
            raise LifecycleError("invalid task status transition")
        if event.progress < stored["progress"]:
            raise LifecycleError("progress regressed")
        if policy.require_checkpoint_for_pause and event.status == "paused" and event.checkpoint_digest is None:
            raise LifecycleError("pause requires checkpoint digest")
        if event.checkpoint_digest is not None and stored["checkpoint_digest"] is not None and event.checkpoint_digest == stored["checkpoint_digest"]:
            raise LifecycleError("checkpoint did not advance")
        if event.status == "completed" and policy.require_result_for_completion and event.result_digest is None:
            raise LifecycleError("completion requires result digest")
        stored["status"] = event.status
        stored["last_trace_position"] = event.trace_position
        stored["progress"] = event.progress
        if event.checkpoint_digest is not None:
            stored["checkpoint_digest"] = event.checkpoint_digest
        if event.result_digest is not None:
            stored["result_digest"] = event.result_digest
        stored["events"].append(event.canonical())
        stored["event_count"] = len(stored["events"])
        stored["record_digest"] = _digest({k: v for k, v in stored.items() if k != "record_digest"})
        self._nonces.add(nonce)
        return json.loads(json.dumps(stored))

    def verify(self, task_record: Mapping[str, Any], *, policy: TaskPolicy) -> bool:
        if not isinstance(task_record, Mapping) or task_record.get("schema") != SCHEMA:
            raise LifecycleError("invalid task record")
        task_id = _text(task_record.get("task_id"), "task_id", 128)
        stored = self._tasks.get(task_id)
        if stored is None:
            raise LifecycleError("task record not found")
        supplied = dict(task_record)
        claimed = supplied.pop("record_digest", None)
        if claimed != stored.get("record_digest") or claimed != _digest(supplied):
            raise LifecycleError("task record digest mismatch")
        if supplied.get("event_count") != len(supplied.get("events", [])):
            raise LifecycleError("event count mismatch")
        if supplied["event_count"] > policy.max_events:
            raise LifecycleError("event count exceeds policy")
        if supplied.get("status") in TERMINAL and supplied.get("events", [])[-1].get("status") != supplied.get("status"):
            raise LifecycleError("terminal status is not last event")
        return True

    def digest(self) -> str:
        return _digest({"tasks": self._tasks, "nonces": sorted(self._nonces)})


__all__ = ["SCHEMA", "LifecycleError", "TaskPolicy", "TaskEvent", "TaskLifecycleAdmission", "TERMINAL"]
