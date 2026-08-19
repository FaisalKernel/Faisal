from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.runtime-assurance.v1"
MAX_ID = 256
MAX_METRICS = 64
MAX_ACTIONS = 8

class RuntimeAssuranceError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_ID:
        raise RuntimeAssuranceError(f"{name} is invalid")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise RuntimeAssuranceError(f"{name} is outside bounds")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise RuntimeAssuranceError(f"{name} is not a digest")
    return value

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "observation_is_authority", "tool_result_is_authority", "assurance_receipt_is_execution_authority", "assurance_receipt_is_production_authority")
    if any(authority.get(key) is not False for key in required):
        raise RuntimeAssuranceError("authority boundary violation")

@dataclass(frozen=True)
class AssuranceEnvelope:
    envelope_id: str
    policy_id: str
    surface_digest: str
    generation: int
    issued_at: int
    expires_at: int
    max_observation_age: int
    decision_ttl: int
    soft_limits: tuple[tuple[str, int], ...]
    hard_limits: tuple[tuple[str, int], ...]
    allowed_actions: frozenset[str]

    def __post_init__(self) -> None:
        text(self.envelope_id, "envelope_id"); text(self.policy_id, "policy_id"); sha(self.surface_digest, "surface_digest")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_observation_age, "max_observation_age", 1, 86400); integer(self.decision_ttl, "decision_ttl", 1, 86400)
        if self.expires_at - self.issued_at > 86400: raise RuntimeAssuranceError("envelope TTL is outside bounds")
        for name, limits in (("soft_limits", self.soft_limits), ("hard_limits", self.hard_limits)):
            if not isinstance(limits, tuple) or len(limits) > MAX_METRICS: raise RuntimeAssuranceError(f"{name} is outside bounds")
            keys = []
            for key, limit in limits:
                keys.append(text(key, f"{name} key")); integer(limit, f"{name} limit", 0, 2**63 - 1)
            if tuple(sorted(set(keys))) != tuple(keys): raise RuntimeAssuranceError(f"{name} must be sorted and unique")
        soft = dict(self.soft_limits); hard = dict(self.hard_limits)
        if any(key not in hard for key in soft): raise RuntimeAssuranceError("soft limit missing hard limit")
        if any(soft[key] > hard[key] for key in soft): raise RuntimeAssuranceError("soft limit exceeds hard limit")
        if not isinstance(self.allowed_actions, frozenset) or not self.allowed_actions or len(self.allowed_actions) > MAX_ACTIONS:
            raise RuntimeAssuranceError("allowed_actions is invalid")
        if not self.allowed_actions <= frozenset(("continue", "restrict", "quarantine", "terminate")):
            raise RuntimeAssuranceError("unknown action")

@dataclass(frozen=True)
class RuntimeObservation:
    observation_id: str
    workload_id: str
    surface_digest: str
    sequence: int
    observed_at: int
    previous_digest: str
    metrics: tuple[tuple[str, int], ...]
    evidence_digest: str

    def __post_init__(self) -> None:
        text(self.observation_id, "observation_id"); text(self.workload_id, "workload_id"); sha(self.surface_digest, "surface_digest")
        integer(self.sequence, "sequence", 1, 2**63 - 1); integer(self.observed_at, "observed_at", 0, 2**63 - 1)
        if self.sequence == 1:
            if self.previous_digest != "genesis": raise RuntimeAssuranceError("first observation must use genesis")
        else: sha(self.previous_digest, "previous_digest")
        if not isinstance(self.metrics, tuple) or len(self.metrics) > MAX_METRICS: raise RuntimeAssuranceError("metrics are outside bounds")
        keys = []
        for key, value in self.metrics:
            keys.append(text(key, "metric key")); integer(value, "metric value", 0, 2**63 - 1)
        if tuple(sorted(set(keys))) != tuple(keys): raise RuntimeAssuranceError("metrics must be sorted and unique")
        sha(self.evidence_digest, "evidence_digest")

class RuntimeAssuranceLedger:
    def __init__(self, envelope: AssuranceEnvelope) -> None:
        self.envelope = envelope
        self._last_sequence = 0
        self._last_digest = "genesis"
        self._nonces: set[str] = set()
        self._decisions: list[dict[str, Any]] = []

    def decide(self, observation: RuntimeObservation, now: int, nonce: str, authority: Mapping[str, Any]) -> dict[str, Any]:
        authority_boundary(authority); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if nonce in self._nonces: raise RuntimeAssuranceError("nonce replay")
        if observation.surface_digest != self.envelope.surface_digest: raise RuntimeAssuranceError("surface mismatch")
        if observation.sequence != self._last_sequence + 1: raise RuntimeAssuranceError("sequence replay or gap")
        if observation.previous_digest != self._last_digest: raise RuntimeAssuranceError("observation chain mismatch")
        self._nonces.add(nonce)
        metrics = dict(observation.metrics); soft = dict(self.envelope.soft_limits); hard = dict(self.envelope.hard_limits)
        reasons: list[str] = []
        action = "continue"
        if now < self.envelope.issued_at or now >= self.envelope.expires_at:
            action = "quarantine"; reasons.append("envelope_expired_or_not_yet_valid")
        elif now - observation.observed_at > self.envelope.max_observation_age or observation.observed_at > now:
            action = "quarantine"; reasons.append("observation_stale_or_future")
        elif any(key not in metrics for key in hard):
            action = "quarantine"; reasons.append("required_metric_missing")
        elif any(metrics[key] > hard[key] for key in hard):
            action = "terminate" if "terminate" in self.envelope.allowed_actions else "quarantine"; reasons.append("hard_limit_exceeded")
        elif any(metrics[key] > soft[key] for key in soft):
            action = "restrict"; reasons.append("soft_limit_exceeded")
        if action not in self.envelope.allowed_actions: raise RuntimeAssuranceError("decision action is not allowed")
        result = {"schema": SCHEMA, "envelope_id": self.envelope.envelope_id, "observation_id": observation.observation_id, "sequence": observation.sequence, "action": action, "reasons": tuple(reasons), "decision_expires_at": min(self.envelope.expires_at, now + self.envelope.decision_ttl), "execution_performed": False, "production_approved": False, "authority": dict(authority)}
        result["decision_digest"] = digest(result)
        self._last_sequence = observation.sequence; self._last_digest = result["decision_digest"]; self._decisions.append(result)
        return result

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "envelope_id": self.envelope.envelope_id, "decisions": self._decisions})
