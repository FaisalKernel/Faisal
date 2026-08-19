"""Fail-closed interaction-segment commitment ledger for FAISAL.

This contract verifies caller-supplied commitments and lineage. It does not
store raw prompts/outputs, ingest OTLP, sign records, replay models, execute
tools, or promote telemetry into truth or authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.interaction-ledger.v1"
MAX_SEGMENTS = 8192
MAX_SPANS = 4096


class InteractionLedgerError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise InteractionLedgerError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise InteractionLedgerError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise InteractionLedgerError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise InteractionLedgerError(f"{name} is outside bounds")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise InteractionLedgerError("authority boundary missing")
    for field in (
        "model_output_is_authority", "telemetry_is_kernel_ground_truth",
        "span_content_is_truth", "ledger_receipt_is_execution_authority",
        "ledger_receipt_is_policy_authority", "ledger_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise InteractionLedgerError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class LedgerPolicy:
    policy_id: str
    policy_version: str
    generation: int
    audience: str
    max_ttl: int = 86_400
    max_spans: int = MAX_SPANS
    require_terminal_verification: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        text(self.audience, "audience", 256)
        integer(self.max_ttl, "max_ttl", 1, 86_400)
        integer(self.max_spans, "max_spans", 1, MAX_SPANS)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "audience": self.audience,
            "max_ttl": self.max_ttl,
            "max_spans": self.max_spans,
            "require_terminal_verification": self.require_terminal_verification,
        })


@dataclass(frozen=True)
class SegmentAnchor:
    segment_id: str
    trace_id: str
    task_id: str
    artifact_id: str
    capability_manifest_digest: str
    delegation_chain_digest: str
    route_digest: str
    audience: str
    generation: int
    policy_digest: str
    sequence: int
    parent_segment_digest: str | None
    span_commitment: str
    started_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.segment_id, "segment_id", 128)
        text(self.trace_id, "trace_id", 128)
        text(self.task_id, "task_id", 128)
        text(self.artifact_id, "artifact_id", 128)
        sha(self.capability_manifest_digest, "capability_manifest_digest")
        sha(self.delegation_chain_digest, "delegation_chain_digest")
        sha(self.route_digest, "route_digest")
        text(self.audience, "audience", 256)
        integer(self.generation, "generation", 1, 2**63 - 1)
        sha(self.policy_digest, "policy_digest")
        integer(self.sequence, "sequence", 1, MAX_SPANS)
        if self.parent_segment_digest is not None:
            sha(self.parent_segment_digest, "parent_segment_digest")
        sha(self.span_commitment, "span_commitment")
        integer(self.started_at, "started_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.started_at:
            raise InteractionLedgerError("segment expiry must follow start")

    @property
    def segment_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "segment_id": self.segment_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "artifact_id": self.artifact_id,
            "capability_manifest_digest": self.capability_manifest_digest,
            "delegation_chain_digest": self.delegation_chain_digest,
            "route_digest": self.route_digest,
            "audience": self.audience,
            "generation": self.generation,
            "policy_digest": self.policy_digest,
            "sequence": self.sequence,
            "parent_segment_digest": self.parent_segment_digest,
            "span_commitment": self.span_commitment,
            "started_at": self.started_at,
            "expires_at": self.expires_at,
        })


@dataclass(frozen=True)
class TerminalVerification:
    terminal_id: str
    segment_id: str
    terminal_digest: str
    verified: bool
    verifier_id: str
    verified_at: int
    result_status: str
    replay_performed: bool = False

    def __post_init__(self) -> None:
        text(self.terminal_id, "terminal_id", 128)
        text(self.segment_id, "segment_id", 128)
        sha(self.terminal_digest, "terminal_digest")
        text(self.verifier_id, "verifier_id", 256)
        integer(self.verified_at, "verified_at", 0, 2**63 - 1)
        text(self.result_status, "result_status", 64)
        if not isinstance(self.verified, bool) or not isinstance(self.replay_performed, bool):
            raise InteractionLedgerError("verification flags invalid")

    @property
    def verification_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "terminal_id": self.terminal_id,
            "segment_id": self.segment_id,
            "terminal_digest": self.terminal_digest,
            "verified": self.verified,
            "verifier_id": self.verifier_id,
            "verified_at": self.verified_at,
            "result_status": self.result_status,
            "replay_performed": self.replay_performed,
        })


@dataclass(frozen=True)
class LedgerRequest:
    request_id: str
    trace_id: str
    task_id: str
    artifact_id: str
    capability_manifest_digest: str
    delegation_chain_digest: str
    route_digest: str
    audience: str
    generation: int
    policy_digest: str
    segment_id: str
    first_sequence: int
    last_sequence: int
    segment_digests: tuple[str, ...]
    terminal_verification: TerminalVerification | None
    requested_at: int
    expires_at: int
    nonce: str

    def __post_init__(self) -> None:
        text(self.request_id, "request_id", 128)
        text(self.trace_id, "trace_id", 128)
        text(self.task_id, "task_id", 128)
        text(self.artifact_id, "artifact_id", 128)
        sha(self.capability_manifest_digest, "capability_manifest_digest")
        sha(self.delegation_chain_digest, "delegation_chain_digest")
        sha(self.route_digest, "route_digest")
        text(self.audience, "audience", 256)
        integer(self.generation, "generation", 1, 2**63 - 1)
        sha(self.policy_digest, "policy_digest")
        text(self.segment_id, "segment_id", 128)
        integer(self.first_sequence, "first_sequence", 1, MAX_SPANS)
        integer(self.last_sequence, "last_sequence", self.first_sequence, MAX_SPANS)
        if not isinstance(self.segment_digests, (list, tuple)) or not self.segment_digests:
            raise InteractionLedgerError("segment_digests is invalid")
        if len(self.segment_digests) != self.last_sequence - self.first_sequence + 1:
            raise InteractionLedgerError("segment digest count does not match sequence")
        for value in self.segment_digests:
            sha(value, "segment_digest")
        if self.terminal_verification is not None and self.terminal_verification.segment_id != self.segment_id:
            raise InteractionLedgerError("terminal segment mismatch")
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise InteractionLedgerError("request expiry must follow request")
        text(self.nonce, "nonce", 256)

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "task_id": self.task_id,
            "artifact_id": self.artifact_id,
            "capability_manifest_digest": self.capability_manifest_digest,
            "delegation_chain_digest": self.delegation_chain_digest,
            "route_digest": self.route_digest,
            "audience": self.audience,
            "generation": self.generation,
            "policy_digest": self.policy_digest,
            "segment_id": self.segment_id,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "segment_digests": list(self.segment_digests),
            "terminal_verification": None if self.terminal_verification is None else self.terminal_verification.verification_digest,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
        })


class InteractionLedger:
    def __init__(self, policy: LedgerPolicy) -> None:
        self.policy = policy
        self._segments: dict[str, list[SegmentAnchor]] = {}
        self._segment_by_digest: dict[str, SegmentAnchor] = {}
        self._requests: set[str] = set()
        self._nonces: set[str] = set()
        self._terminals: set[str] = set()

    def append(self, segment: SegmentAnchor) -> str:
        if len(self._segment_by_digest) >= MAX_SEGMENTS:
            raise InteractionLedgerError("segment bound exceeded")
        if segment.segment_id in {s.segment_id for s in self._segment_by_digest.values()}:
            raise InteractionLedgerError("segment replay")
        if segment.audience != self.policy.audience:
            raise InteractionLedgerError("segment audience denied")
        if segment.generation != self.policy.generation or segment.policy_digest != self.policy.policy_digest:
            raise InteractionLedgerError("segment policy generation mismatch")
        if segment.expires_at - segment.started_at > self.policy.max_ttl:
            raise InteractionLedgerError("segment ttl exceeds policy")
        chain = self._segments.setdefault(segment.trace_id, [])
        if len(chain) >= self.policy.max_spans:
            raise InteractionLedgerError("trace span bound exceeded")
        if chain:
            prior = chain[-1]
            if segment.sequence != prior.sequence + 1:
                raise InteractionLedgerError("segment sequence gap")
            if segment.parent_segment_digest != prior.segment_digest:
                raise InteractionLedgerError("segment parent mismatch")
            for field in ("task_id", "artifact_id", "capability_manifest_digest", "delegation_chain_digest", "route_digest", "audience", "generation", "policy_digest", "segment_id"):
                if field == "segment_id":
                    continue
                if getattr(segment, field) != getattr(prior, field):
                    raise InteractionLedgerError(f"segment {field} continuity failure")
        elif segment.sequence != 1:
            raise InteractionLedgerError("trace must start at sequence 1")
        chain.append(segment)
        self._segment_by_digest[segment.segment_digest] = segment
        return segment.segment_digest

    def admit(self, request: LedgerRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.request_id in self._requests or request.nonce in self._nonces:
            raise InteractionLedgerError("request or nonce replay")
        if request.audience != self.policy.audience or request.generation != self.policy.generation or request.policy_digest != self.policy.policy_digest:
            raise InteractionLedgerError("request policy binding mismatch")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise InteractionLedgerError("request ttl exceeds policy")
        if now < request.requested_at or now >= request.expires_at:
            raise InteractionLedgerError("request expired")
        chain = self._segments.get(request.trace_id, [])
        if len(chain) != len(request.segment_digests):
            raise InteractionLedgerError("trace segment count mismatch")
        if not chain or chain[0].sequence != request.first_sequence or chain[-1].sequence != request.last_sequence:
            raise InteractionLedgerError("trace sequence bounds mismatch")
        for segment, expected_digest in zip(chain, request.segment_digests):
            if segment.segment_digest != expected_digest:
                raise InteractionLedgerError("segment digest mismatch")
            for field in ("task_id", "artifact_id", "capability_manifest_digest", "delegation_chain_digest", "route_digest", "audience", "generation", "policy_digest"):
                if getattr(segment, field) != getattr(request, field):
                    raise InteractionLedgerError(f"request {field} binding mismatch")
            if now < segment.started_at or now >= segment.expires_at:
                raise InteractionLedgerError("segment expired")
        terminal = request.terminal_verification
        if self.policy.require_terminal_verification:
            if terminal is None or not terminal.verified:
                raise InteractionLedgerError("terminal verification required")
            if terminal.terminal_id in self._terminals:
                raise InteractionLedgerError("terminal replay")
            if terminal.verified_at < chain[-1].started_at or terminal.verified_at >= request.expires_at:
                raise InteractionLedgerError("terminal verification outside request")
        self._requests.add(request.request_id)
        self._nonces.add(request.nonce)
        if terminal is not None:
            self._terminals.add(terminal.terminal_id)
        result = {
            "schema": SCHEMA,
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "trace_id": request.trace_id,
            "task_id": request.task_id,
            "artifact_id": request.artifact_id,
            "segment_count": len(chain),
            "first_sequence": request.first_sequence,
            "last_sequence": request.last_sequence,
            "capability_manifest_digest": request.capability_manifest_digest,
            "delegation_chain_digest": request.delegation_chain_digest,
            "route_digest": request.route_digest,
            "policy_digest": request.policy_digest,
            "terminal_verified": terminal is not None and terminal.verified,
            "replay_performed": False if terminal is None else terminal.replay_performed,
            "raw_content_stored": False,
            "telemetry_ingested": False,
            "models_replayed": False,
            "tools_executed": False,
            "external_services_contacted": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "segments": [s.segment_digest for trace in self._segments.values() for s in trace],
            "requests": sorted(self._requests),
            "nonces": sorted(self._nonces),
            "terminals": sorted(self._terminals),
        })


__all__ = ["SCHEMA", "InteractionLedgerError", "LedgerPolicy", "SegmentAnchor", "TerminalVerification", "LedgerRequest", "InteractionLedger", "digest"]
