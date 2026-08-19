"""Fail-closed path-dependent runtime governance for FAISAL.

This control-plane contract evaluates a proposed agent action against the
ordered execution path already observed. It is deliberately provider-neutral:
model output, tool descriptions/results, observations, and policy receipts are
provenance only and never authority. It does not execute actions, inspect
credentials, contact services, or certify external compliance.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.path-governance.v1"
MAX_STEPS = 4096
MAX_RULES = 256
MAX_LABELS = 128
MAX_RISK = 1_000_000


class PathGovernanceError(ValueError):
    """Raised when a path or admission request violates a contract invariant."""


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise PathGovernanceError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise PathGovernanceError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise PathGovernanceError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise PathGovernanceError(f"{name} is outside bounds")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise PathGovernanceError(f"{name} must be boolean")
    return value


def labels(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set, frozenset)) or len(value) > MAX_LABELS:
        raise PathGovernanceError(f"{name} is invalid")
    result = frozenset(text(item, f"{name}.item", 128) for item in value)
    if len(result) != len(value):
        raise PathGovernanceError(f"{name} contains duplicates")
    return result


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise PathGovernanceError("authority boundary missing")
    required = (
        "model_output_is_authority",
        "tool_description_is_authority",
        "tool_result_is_authority",
        "observation_is_authority",
        "path_receipt_is_execution_authority",
        "path_receipt_is_production_authority",
    )
    for field in required:
        if value.get(field) is not False:
            raise PathGovernanceError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class PathStep:
    step_id: str
    actor_id: str
    action_kind: str
    labels: frozenset[str]
    generation: int
    occurred_at: int
    input_digest: str
    output_digest: str
    outcome: str = "observed"

    def __post_init__(self) -> None:
        text(self.step_id, "step_id", 128)
        text(self.actor_id, "actor_id", 128)
        text(self.action_kind, "action_kind", 128)
        labels(self.labels, "labels")
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.occurred_at, "occurred_at", 0, 2**63 - 1)
        sha(self.input_digest, "input_digest")
        sha(self.output_digest, "output_digest")
        text(self.outcome, "outcome", 64)

    @property
    def step_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "step_id": self.step_id,
            "actor_id": self.actor_id,
            "action_kind": self.action_kind,
            "labels": sorted(self.labels),
            "generation": self.generation,
            "occurred_at": self.occurred_at,
            "input_digest": self.input_digest,
            "output_digest": self.output_digest,
            "outcome": self.outcome,
        })


@dataclass(frozen=True)
class PathRule:
    rule_id: str
    rule_version: str
    forbidden_prior_labels: frozenset[str] = frozenset()
    forbidden_next_labels: frozenset[str] = frozenset()
    max_risk_cost: int = MAX_RISK
    require_approval: bool = False
    deny_on_match: bool = True

    def __post_init__(self) -> None:
        text(self.rule_id, "rule_id", 128)
        text(self.rule_version, "rule_version", 64)
        labels(self.forbidden_prior_labels, "forbidden_prior_labels")
        labels(self.forbidden_next_labels, "forbidden_next_labels")
        integer(self.max_risk_cost, "max_risk_cost", 0, MAX_RISK)
        boolean(self.require_approval, "require_approval")
        boolean(self.deny_on_match, "deny_on_match")

    @property
    def rule_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "forbidden_prior_labels": sorted(self.forbidden_prior_labels),
            "forbidden_next_labels": sorted(self.forbidden_next_labels),
            "max_risk_cost": self.max_risk_cost,
            "require_approval": self.require_approval,
            "deny_on_match": self.deny_on_match,
        })


@dataclass(frozen=True)
class PathPolicy:
    policy_id: str
    policy_version: str
    generation: int
    max_steps: int = MAX_STEPS
    max_risk_budget: int = MAX_RISK
    rules: tuple[PathRule, ...] = ()

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 0, 2**63 - 1)
        integer(self.max_steps, "max_steps", 1, MAX_STEPS)
        integer(self.max_risk_budget, "max_risk_budget", 0, MAX_RISK)
        if len(self.rules) > MAX_RULES:
            raise PathGovernanceError("rule limit exceeded")
        ids = [rule.rule_id for rule in self.rules]
        if len(set(ids)) != len(ids):
            raise PathGovernanceError("duplicate rule id")

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "max_steps": self.max_steps,
            "max_risk_budget": self.max_risk_budget,
            "rules": [rule.rule_digest for rule in self.rules],
        })


@dataclass(frozen=True)
class ActionRequest:
    decision_id: str
    actor_id: str
    action_kind: str
    next_labels: frozenset[str]
    generation: int
    input_digest: str
    proposed_output_digest: str
    risk_cost: int
    approval_digest: str | None = None
    terminal_result_digest: str | None = None
    terminal_trace_digest: str | None = None

    def __post_init__(self) -> None:
        text(self.decision_id, "decision_id", 128)
        text(self.actor_id, "actor_id", 128)
        text(self.action_kind, "action_kind", 128)
        labels(self.next_labels, "next_labels")
        integer(self.generation, "generation", 0, 2**63 - 1)
        sha(self.input_digest, "input_digest")
        sha(self.proposed_output_digest, "proposed_output_digest")
        integer(self.risk_cost, "risk_cost", 0, MAX_RISK)
        if self.approval_digest is not None:
            sha(self.approval_digest, "approval_digest")
        if (self.terminal_result_digest is None) != (self.terminal_trace_digest is None):
            raise PathGovernanceError("terminal linkage must be complete")
        if self.terminal_result_digest is not None:
            sha(self.terminal_result_digest, "terminal_result_digest")
            sha(self.terminal_trace_digest, "terminal_trace_digest")

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "decision_id": self.decision_id,
            "actor_id": self.actor_id,
            "action_kind": self.action_kind,
            "next_labels": sorted(self.next_labels),
            "generation": self.generation,
            "input_digest": self.input_digest,
            "proposed_output_digest": self.proposed_output_digest,
            "risk_cost": self.risk_cost,
            "approval_digest": self.approval_digest,
            "terminal_result_digest": self.terminal_result_digest,
            "terminal_trace_digest": self.terminal_trace_digest,
        })


class PathGovernanceLedger:
    def __init__(self, policy: PathPolicy) -> None:
        self.policy = policy
        self.steps: list[PathStep] = []
        self._decisions: set[str] = set()

    def append_observed(self, step: PathStep) -> None:
        if step.generation != self.policy.generation:
            raise PathGovernanceError("step generation mismatch")
        if len(self.steps) >= self.policy.max_steps:
            raise PathGovernanceError("path step limit exceeded")
        if self.steps and step.occurred_at < self.steps[-1].occurred_at:
            raise PathGovernanceError("path time is not monotonic")
        if any(item.step_id == step.step_id for item in self.steps):
            raise PathGovernanceError("step replay")
        self.steps.append(step)

    def _matched_rules(self, request: ActionRequest) -> list[PathRule]:
        prior = frozenset(label for step in self.steps for label in step.labels)
        matched = []
        for rule in self.policy.rules:
            if rule.forbidden_prior_labels.issubset(prior) and rule.forbidden_next_labels.issubset(request.next_labels):
                matched.append(rule)
        return matched

    def admit(self, request: ActionRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.decision_id in self._decisions:
            raise PathGovernanceError("decision replay")
        if request.generation != self.policy.generation:
            raise PathGovernanceError("decision generation mismatch")
        if self.steps and request.actor_id != self.steps[-1].actor_id:
            # Cross-agent continuation is allowed only when the caller has encoded
            # the handoff in the observed path; an unlinked actor switch fails closed.
            if "delegated_handoff" not in request.next_labels:
                raise PathGovernanceError("actor transition is not path-linked")
        prior_risk = sum(step_risk(step) for step in self.steps)
        projected_risk = prior_risk + request.risk_cost
        matched = self._matched_rules(request)
        exceeded_budget = projected_risk > self.policy.max_risk_budget or any(request.risk_cost > rule.max_risk_cost for rule in matched)
        denied_rule = next((rule for rule in matched if rule.deny_on_match), None)
        approval_rule = next((rule for rule in matched if rule.require_approval), None)
        if denied_rule is not None:
            verdict, reason = "deny", f"path_rule:{denied_rule.rule_id}"
        elif exceeded_budget:
            verdict, reason = "deny", "risk_budget_exceeded"
        elif approval_rule is not None and request.approval_digest is None:
            verdict, reason = "require_blocking_approval", f"path_rule_approval:{approval_rule.rule_id}"
        elif request.terminal_result_digest is not None and request.terminal_trace_digest is None:
            verdict, reason = "deny", "terminal_linkage_incomplete"
        else:
            verdict, reason = "allow_with_policy", "bounded_path_match"
        self._decisions.add(request.decision_id)
        result = {
            "schema": SCHEMA,
            "decision_id": request.decision_id,
            "policy_digest": self.policy.policy_digest,
            "request_digest": request.request_digest,
            "generation": self.policy.generation,
            "path_length": len(self.steps),
            "path_step_digests": [step.step_digest for step in self.steps],
            "prior_risk": prior_risk,
            "projected_risk": projected_risk,
            "matched_rule_ids": [rule.rule_id for rule in matched],
            "verdict": verdict,
            "reason": reason,
            "approval_linked": request.approval_digest is not None,
            "terminal_result_linked": request.terminal_result_digest is not None,
            "now": now,
            "authority": dict(authority),
        }
        result["decision_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "steps": [step.step_digest for step in self.steps],
            "decisions": sorted(self._decisions),
        })


def step_risk(step: PathStep) -> int:
    # Risk is supplied as a deterministic label mapping, never inferred from
    # model output. Unknown labels are intentionally zero-cost here; policy rules
    # must explicitly deny or require approval for them.
    return sum(1 for label in step.labels if label.startswith("risk:"))


__all__ = [
    "SCHEMA", "PathGovernanceError", "PathStep", "PathRule", "PathPolicy",
    "ActionRequest", "PathGovernanceLedger", "digest", "step_risk",
]
