"""Fail-closed session risk policy decisions for FAISAL.

This is a deterministic control-plane contract. It tracks session capabilities
and taint sources, evaluates combinations such as private-data access plus
untrusted content plus external communication, and emits an admission receipt.
It does not execute tools, inspect credentials, or replace sandbox/network
controls. All model, tool-description, and result data remain non-authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.session-risk.v1"
MAX_EVENTS = 4096
MAX_CAPABILITIES = 128


class SessionRiskError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise SessionRiskError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise SessionRiskError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise SessionRiskError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SessionRiskError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise SessionRiskError(f"{name} must be boolean")
    return value


def capability_set(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set, frozenset)) or len(value) > MAX_CAPABILITIES:
        raise SessionRiskError(f"{name} is invalid")
    values = frozenset(text(item, f"{name}.item", 128) for item in value)
    if len(values) != len(value):
        raise SessionRiskError(f"{name} contains duplicates")
    return values


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise SessionRiskError("authority boundary missing")
    required = ("model_output_is_authority", "tool_description_is_authority", "tool_result_is_authority", "policy_receipt_is_production_authority")
    for field in required:
        if value.get(field) is not False:
            raise SessionRiskError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class RiskEvent:
    event_id: str
    event_kind: str
    capabilities: frozenset[str]
    taints: frozenset[str]
    generation: int
    occurred_at: int
    source_digest: str
    context_digest: str

    def __post_init__(self) -> None:
        text(self.event_id, "event_id", 128)
        text(self.event_kind, "event_kind", 128)
        capability_set(self.capabilities, "capabilities")
        capability_set(self.taints, "taints")
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.occurred_at, "occurred_at", 0, 2**63 - 1)
        sha(self.source_digest, "source_digest")
        sha(self.context_digest, "context_digest")

    @property
    def event_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "capabilities": sorted(self.capabilities),
            "taints": sorted(self.taints),
            "generation": self.generation,
            "occurred_at": self.occurred_at,
            "source_digest": self.source_digest,
            "context_digest": self.context_digest,
        })


@dataclass(frozen=True)
class RiskPolicy:
    policy_id: str
    policy_version: str
    generation: int
    max_events: int = MAX_EVENTS
    require_blocking_approval_for_trifecta: bool = True
    require_blocking_approval_for_unknown: bool = True
    deny_critical_taint: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.max_events, "max_events", 1, MAX_EVENTS)
        boolean(self.require_blocking_approval_for_trifecta, "require_blocking_approval_for_trifecta")
        boolean(self.require_blocking_approval_for_unknown, "require_blocking_approval_for_unknown")
        boolean(self.deny_critical_taint, "deny_critical_taint")

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "max_events": self.max_events,
            "require_blocking_approval_for_trifecta": self.require_blocking_approval_for_trifecta,
            "require_blocking_approval_for_unknown": self.require_blocking_approval_for_unknown,
            "deny_critical_taint": self.deny_critical_taint,
        })


@dataclass(frozen=True)
class PolicyDecisionRequest:
    decision_id: str
    session_id: str
    generation: int
    requested_capabilities: frozenset[str]
    requested_taints: frozenset[str]
    context_digest: str
    authorization_digest: str
    blocking_approval_digest: str | None = None
    model_output_digest: str | None = None

    def __post_init__(self) -> None:
        text(self.decision_id, "decision_id", 128)
        text(self.session_id, "session_id", 128)
        integer(self.generation, "generation", 0, 2**63 - 1)
        capability_set(self.requested_capabilities, "requested_capabilities")
        capability_set(self.requested_taints, "requested_taints")
        sha(self.context_digest, "context_digest")
        sha(self.authorization_digest, "authorization_digest")
        if self.blocking_approval_digest is not None:
            sha(self.blocking_approval_digest, "blocking_approval_digest")
        if self.model_output_digest is not None:
            sha(self.model_output_digest, "model_output_digest")


class SessionRiskLedger:
    def __init__(self, policy: RiskPolicy) -> None:
        self.policy = policy
        self.events: list[RiskEvent] = []
        self._decisions: set[str] = set()

    def append(self, event: RiskEvent) -> None:
        if event.generation != self.policy.generation:
            raise SessionRiskError("event generation mismatch")
        if len(self.events) >= self.policy.max_events:
            raise SessionRiskError("event limit exceeded")
        if self.events and event.occurred_at < self.events[-1].occurred_at:
            raise SessionRiskError("event time is not monotonic")
        if any(previous.event_id == event.event_id for previous in self.events):
            raise SessionRiskError("event replay")
        self.events.append(event)

    def observed_capabilities(self) -> frozenset[str]:
        return frozenset(item for event in self.events for item in event.capabilities)

    def observed_taints(self) -> frozenset[str]:
        return frozenset(item for event in self.events for item in event.taints)

    def decide(self, request: PolicyDecisionRequest, *, now: int, nonce: str, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        text(nonce, "nonce", 128)
        authority_boundary(authority)
        if request.decision_id in self._decisions:
            raise SessionRiskError("decision replay")
        if request.generation != self.policy.generation:
            raise SessionRiskError("decision generation mismatch")
        if request.model_output_digest is not None:
            # The digest may be retained as provenance, but cannot satisfy any policy input.
            sha(request.model_output_digest, "model_output_digest")
        observed_caps = self.observed_capabilities()
        observed_taints = self.observed_taints()
        combined_caps = observed_caps | request.requested_capabilities
        combined_taints = observed_taints | request.requested_taints
        trifecta = {"private_data_access", "untrusted_content_exposure", "external_communication"}.issubset(combined_caps | combined_taints)
        critical = "critical_taint" in combined_taints
        unknown = "unknown_tool_behavior" in combined_taints
        if critical and self.policy.deny_critical_taint:
            verdict = "deny"
            reason = "critical_taint"
        elif trifecta and self.policy.require_blocking_approval_for_trifecta and request.blocking_approval_digest is None:
            verdict = "require_blocking_approval"
            reason = "lethal_trifecta"
        elif unknown and self.policy.require_blocking_approval_for_unknown and request.blocking_approval_digest is None:
            verdict = "require_blocking_approval"
            reason = "unknown_tool_behavior"
        else:
            verdict = "allow_with_policy"
            reason = "bounded_policy_match"
        self._decisions.add(request.decision_id)
        result = {
            "schema": SCHEMA,
            "decision_id": request.decision_id,
            "session_id": request.session_id,
            "policy_digest": self.policy.policy_digest,
            "generation": self.policy.generation,
            "observed_capabilities": sorted(observed_caps),
            "observed_taints": sorted(observed_taints),
            "combined_capabilities": sorted(combined_caps),
            "combined_taints": sorted(combined_taints),
            "lethal_trifecta": trifecta,
            "critical_taint": critical,
            "unknown_tool_behavior": unknown,
            "verdict": verdict,
            "reason": reason,
            "context_digest": request.context_digest,
            "authorization_digest": request.authorization_digest,
            "blocking_approval_linked": request.blocking_approval_digest is not None,
            "nonce_digest": digest(nonce),
            "now": now,
            "authority": dict(authority),
        }
        result["decision_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_digest": self.policy.policy_digest, "events": [event.event_digest for event in self.events], "decisions": sorted(self._decisions)})


__all__ = ["SCHEMA", "SessionRiskError", "RiskEvent", "RiskPolicy", "PolicyDecisionRequest", "SessionRiskLedger", "digest"]
