"""Fail-closed trace-segment checkpoint receipts for FAISAL.

The contract binds an ordered trace segment to a durable lifecycle checkpoint
without exporting traces or treating model/tool/trace data as authority. It
supports flush and cancellation boundaries, sensitive-data policy binding,
generation fencing, and replay-safe resume evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.trace-segment.v1"
MAX_SPANS = 4096


class TraceSegmentError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise TraceSegmentError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise TraceSegmentError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise TraceSegmentError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise TraceSegmentError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TraceSegmentError(f"{name} must be boolean")
    return value


def authority(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise TraceSegmentError("authority boundary missing")
    for field in ("model_output_is_authority", "tool_output_is_authority", "trace_is_authority", "checkpoint_is_production_authority"):
        if value.get(field) is not False:
            raise TraceSegmentError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class Span:
    span_id: str
    parent_span_id: str | None
    kind: str
    started_at: int
    ended_at: int
    payload_digest: str
    sensitive_data_captured: bool

    def __post_init__(self) -> None:
        text(self.span_id, "span_id", 128)
        if self.parent_span_id is not None:
            text(self.parent_span_id, "parent_span_id", 128)
        text(self.kind, "kind", 64)
        integer(self.started_at, "started_at", 0, 2**63 - 1)
        integer(self.ended_at, "ended_at", 0, 2**63 - 1)
        if self.ended_at < self.started_at:
            raise TraceSegmentError("span end precedes start")
        sha(self.payload_digest, "payload_digest")
        boolean(self.sensitive_data_captured, "sensitive_data_captured")

    @property
    def span_digest(self) -> str:
        return digest({
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "kind": self.kind,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "payload_digest": self.payload_digest,
            "sensitive_data_captured": self.sensitive_data_captured,
        })


@dataclass(frozen=True)
class TraceSegment:
    trace_id: str
    segment_id: str
    generation: int
    sequence_start: int
    sequence_end: int
    spans: tuple[Span, ...]
    previous_segment_digest: str | None
    flush_status: str
    cancellation_boundary: str
    sensitive_data_policy_digest: str

    def __post_init__(self) -> None:
        text(self.trace_id, "trace_id", 128)
        text(self.segment_id, "segment_id", 128)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.sequence_start, "sequence_start", 0, 2**63 - 1)
        integer(self.sequence_end, "sequence_end", 0, 2**63 - 1)
        if self.sequence_end < self.sequence_start:
            raise TraceSegmentError("segment sequence is reversed")
        if not self.spans or len(self.spans) > MAX_SPANS:
            raise TraceSegmentError("segment span count is invalid")
        if len({span.span_id for span in self.spans}) != len(self.spans):
            raise TraceSegmentError("duplicate span id")
        if self.previous_segment_digest is not None:
            sha(self.previous_segment_digest, "previous_segment_digest")
        if self.flush_status not in {"not_flushed", "flushed", "flush_failed"}:
            raise TraceSegmentError("invalid flush status")
        if self.cancellation_boundary not in {"none", "requested", "acknowledged", "completed"}:
            raise TraceSegmentError("invalid cancellation boundary")
        sha(self.sensitive_data_policy_digest, "sensitive_data_policy_digest")

    @property
    def segment_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "trace_id": self.trace_id,
            "segment_id": self.segment_id,
            "generation": self.generation,
            "sequence_start": self.sequence_start,
            "sequence_end": self.sequence_end,
            "spans": [span.span_digest for span in self.spans],
            "previous_segment_digest": self.previous_segment_digest,
            "flush_status": self.flush_status,
            "cancellation_boundary": self.cancellation_boundary,
            "sensitive_data_policy_digest": self.sensitive_data_policy_digest,
        })


@dataclass(frozen=True)
class SegmentCheckpointRequest:
    checkpoint_id: str
    objective_id: str
    trace_id: str
    generation: int
    segment_digest: str
    lifecycle_checkpoint_digest: str
    objective_state_digest: str
    required_flush: bool
    resume_nonce: str
    requested_at: int

    def __post_init__(self) -> None:
        text(self.checkpoint_id, "checkpoint_id", 128)
        text(self.objective_id, "objective_id", 128)
        text(self.trace_id, "trace_id", 128)
        integer(self.generation, "generation", 0, 2**63 - 1)
        sha(self.segment_digest, "segment_digest")
        sha(self.lifecycle_checkpoint_digest, "lifecycle_checkpoint_digest")
        sha(self.objective_state_digest, "objective_state_digest")
        boolean(self.required_flush, "required_flush")
        text(self.resume_nonce, "resume_nonce", 128)
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)


class TraceSegmentLedger:
    def __init__(self, *, generation: int, sensitive_data_policy_digest: str, max_checkpoints: int = 4096) -> None:
        integer(generation, "generation", 0, 2**63 - 1)
        sha(sensitive_data_policy_digest, "sensitive_data_policy_digest")
        integer(max_checkpoints, "max_checkpoints", 1, 4096)
        self.generation = generation
        self.sensitive_data_policy_digest = sensitive_data_policy_digest
        self.max_checkpoints = max_checkpoints
        self._segments: dict[str, TraceSegment] = {}
        self._checkpoints: set[str] = set()

    def admit(self, segment: TraceSegment, request: SegmentCheckpointRequest, *, authority_boundary: Mapping[str, Any]) -> dict[str, Any]:
        authority(authority_boundary)
        if segment.generation != self.generation or request.generation != self.generation:
            raise TraceSegmentError("generation mismatch")
        if segment.trace_id != request.trace_id:
            raise TraceSegmentError("trace mismatch")
        if segment.segment_digest != request.segment_digest:
            raise TraceSegmentError("segment tamper or linkage mismatch")
        if segment.sensitive_data_policy_digest != self.sensitive_data_policy_digest:
            raise TraceSegmentError("sensitive-data policy mismatch")
        if request.checkpoint_id in self._checkpoints:
            raise TraceSegmentError("checkpoint replay")
        if request.required_flush and segment.flush_status != "flushed":
            raise TraceSegmentError("required flush not complete")
        if segment.flush_status == "flush_failed":
            raise TraceSegmentError("trace flush failed")
        if segment.cancellation_boundary == "requested":
            raise TraceSegmentError("cancellation boundary not acknowledged")
        if len(self._checkpoints) >= self.max_checkpoints:
            raise TraceSegmentError("checkpoint bound exceeded")
        if self._segments:
            prior = max(self._segments.values(), key=lambda item: item.sequence_end)
            if segment.previous_segment_digest != prior.segment_digest:
                raise TraceSegmentError("segment continuity mismatch")
            if segment.sequence_start != prior.sequence_end + 1:
                raise TraceSegmentError("segment sequence gap")
        self._segments[segment.segment_id] = segment
        self._checkpoints.add(request.checkpoint_id)
        result = {
            "schema": SCHEMA,
            "checkpoint_id": request.checkpoint_id,
            "objective_id": request.objective_id,
            "trace_id": segment.trace_id,
            "segment_id": segment.segment_id,
            "segment_digest": segment.segment_digest,
            "lifecycle_checkpoint_digest": request.lifecycle_checkpoint_digest,
            "objective_state_digest": request.objective_state_digest,
            "generation": self.generation,
            "sequence_start": segment.sequence_start,
            "sequence_end": segment.sequence_end,
            "flush_status": segment.flush_status,
            "cancellation_boundary": segment.cancellation_boundary,
            "resume_nonce_digest": digest(request.resume_nonce),
            "admitted": True,
            "authority": dict(authority_boundary),
        }
        result["receipt_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "generation": self.generation, "segments": [segment.segment_digest for segment in self._segments.values()], "checkpoints": sorted(self._checkpoints)})


__all__ = ["SCHEMA", "TraceSegmentError", "Span", "TraceSegment", "SegmentCheckpointRequest", "TraceSegmentLedger", "digest"]
