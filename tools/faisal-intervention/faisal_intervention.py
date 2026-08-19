"""Fail-closed execution-intervention admission for FAISAL.

This is a provider-neutral control-plane contract for authorizing a bounded
runtime intervention after a trusted supervisor observes a signal. It emits
admission evidence only. It never executes controls, kills processes, invokes
tools, contacts external services, inspects credentials, or treats model/tool
output as authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.execution-intervention.v1"
MAX_INTERVENTIONS = 128
MAX_COOLDOWN = 2**31 - 1

ALLOWED_INTERVENTIONS = frozenset({
    "pause", "checkpoint", "downgrade", "retry", "quarantine", "rollback", "terminate",
})
HIGH_IMPACT = frozenset({"rollback", "quarantine", "terminate"})


class InterventionError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise InterventionError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise InterventionError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise InterventionError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise InterventionError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise InterventionError(f"{name} must be boolean")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise InterventionError("authority boundary missing")
    for field in (
        "model_output_is_authority", "tool_description_is_authority",
        "tool_result_is_authority", "observation_is_authority",
        "intervention_receipt_is_execution_authority",
        "intervention_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise InterventionError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class InterventionPolicy:
    policy_id: str
    policy_version: str
    generation: int
    allowed_interventions: frozenset[str]
    max_interventions: int = MAX_INTERVENTIONS
    cooldown: int = 0
    approval_required: frozenset[str] = frozenset()
    max_attempts: int = 1

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 0, 2**63 - 1)
        if not self.allowed_interventions or not self.allowed_interventions.issubset(ALLOWED_INTERVENTIONS):
            raise InterventionError("allowed intervention set is invalid")
        if not self.approval_required.issubset(self.allowed_interventions):
            raise InterventionError("approval set exceeds allowed interventions")
        if not self.approval_required.issubset(HIGH_IMPACT):
            raise InterventionError("only high-impact interventions may require approval")
        integer(self.max_interventions, "max_interventions", 1, MAX_INTERVENTIONS)
        integer(self.cooldown, "cooldown", 0, MAX_COOLDOWN)
        integer(self.max_attempts, "max_attempts", 1, 8)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "allowed_interventions": sorted(self.allowed_interventions),
            "max_interventions": self.max_interventions,
            "cooldown": self.cooldown,
            "approval_required": sorted(self.approval_required),
            "max_attempts": self.max_attempts,
        })


@dataclass(frozen=True)
class InterventionRequest:
    intervention_id: str
    actor_id: str
    target_id: str
    intervention: str
    generation: int
    observed_at: int
    expires_at: int
    observation_digest: str
    target_state_digest: str
    recovery_checkpoint_digest: str
    proposed_state_digest: str
    reason_digest: str
    attempt: int = 1
    approval_digest: str | None = None

    def __post_init__(self) -> None:
        text(self.intervention_id, "intervention_id", 128)
        text(self.actor_id, "actor_id", 128)
        text(self.target_id, "target_id", 128)
        text(self.intervention, "intervention", 64)
        if self.intervention not in ALLOWED_INTERVENTIONS:
            raise InterventionError("intervention is not allowed")
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.observed_at, "observed_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.observed_at:
            raise InterventionError("expiry must follow observation")
        for value, name in (
            (self.observation_digest, "observation_digest"),
            (self.target_state_digest, "target_state_digest"),
            (self.recovery_checkpoint_digest, "recovery_checkpoint_digest"),
            (self.proposed_state_digest, "proposed_state_digest"),
            (self.reason_digest, "reason_digest"),
        ):
            sha(value, name)
        integer(self.attempt, "attempt", 1, 8)
        if self.approval_digest is not None:
            sha(self.approval_digest, "approval_digest")
        if self.intervention in {"checkpoint", "rollback", "terminate"} and self.recovery_checkpoint_digest is None:
            raise InterventionError("recovery checkpoint required")

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "intervention_id": self.intervention_id,
            "actor_id": self.actor_id,
            "target_id": self.target_id,
            "intervention": self.intervention,
            "generation": self.generation,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "observation_digest": self.observation_digest,
            "target_state_digest": self.target_state_digest,
            "recovery_checkpoint_digest": self.recovery_checkpoint_digest,
            "proposed_state_digest": self.proposed_state_digest,
            "reason_digest": self.reason_digest,
            "attempt": self.attempt,
            "approval_digest": self.approval_digest,
        })


class InterventionLedger:
    def __init__(self, policy: InterventionPolicy) -> None:
        self.policy = policy
        self._admitted: set[str] = set()
        self._targets: dict[str, int] = {}
        self._completed: set[str] = set()

    def admit(self, request: InterventionRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.intervention_id in self._admitted:
            raise InterventionError("intervention replay")
        if request.generation != self.policy.generation:
            raise InterventionError("generation mismatch")
        if now < request.observed_at or now >= request.expires_at:
            raise InterventionError("intervention expired or not yet observable")
        if len(self._admitted) >= self.policy.max_interventions:
            raise InterventionError("intervention limit exceeded")
        if request.intervention not in self.policy.allowed_interventions:
            raise InterventionError("policy denies intervention type")
        if request.attempt > self.policy.max_attempts:
            raise InterventionError("attempt limit exceeded")
        previous = self._targets.get(request.target_id)
        if previous is not None and now - previous < self.policy.cooldown:
            raise InterventionError("target cooldown active")
        if request.intervention in self.policy.approval_required and request.approval_digest is None:
            verdict, reason = "require_blocking_approval", "high_impact_approval_required"
        else:
            verdict, reason = "admit_bounded_intervention", "policy_and_observation_match"
        self._admitted.add(request.intervention_id)
        self._targets[request.target_id] = now
        result = {
            "schema": SCHEMA,
            "intervention_id": request.intervention_id,
            "request_digest": request.request_digest,
            "policy_digest": self.policy.policy_digest,
            "generation": self.policy.generation,
            "target_id": request.target_id,
            "intervention": request.intervention,
            "verdict": verdict,
            "reason": reason,
            "attempt": request.attempt,
            "expires_at": request.expires_at,
            "approval_linked": request.approval_digest is not None,
            "postcondition_required": True,
            "execution_performed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def complete(self, intervention_id: str, *, post_state_digest: str, post_trace_digest: str, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        sha(post_state_digest, "post_state_digest")
        sha(post_trace_digest, "post_trace_digest")
        if intervention_id not in self._admitted:
            raise InterventionError("unknown intervention")
        if intervention_id in self._completed:
            raise InterventionError("completion replay")
        self._completed.add(intervention_id)
        result = {
            "schema": SCHEMA,
            "intervention_id": intervention_id,
            "post_state_digest": post_state_digest,
            "post_trace_digest": post_trace_digest,
            "completed": True,
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
            "admitted": sorted(self._admitted),
            "completed": sorted(self._completed),
            "targets": sorted(self._targets.items()),
        })


__all__ = [
    "SCHEMA", "ALLOWED_INTERVENTIONS", "InterventionError", "InterventionPolicy",
    "InterventionRequest", "InterventionLedger", "digest",
]
