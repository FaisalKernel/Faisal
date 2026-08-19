"""Fail-closed admission for bounded self-improvement candidates.

The ledger evaluates caller-supplied evidence for reversible scaffold changes.
It never edits source, model weights, privileged kernel code, production policy,
or executes a deployment.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.self-improvement.v1"
ALLOWED_COMPONENTS = frozenset({"prompt", "memory_policy", "tool_descriptor", "routing_policy", "control_logic"})
MAX_EVIDENCE = 4096


class SelfImprovementError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise SelfImprovementError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise SelfImprovementError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise SelfImprovementError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise SelfImprovementError(f"{name} is outside bounds")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise SelfImprovementError("authority boundary missing")
    for field in (
        "model_output_is_authority", "candidate_claim_is_authority",
        "evaluation_receipt_is_deployment_authority", "self_improvement_receipt_is_policy_authority",
        "self_improvement_receipt_is_production_authority", "autonomous_privileged_modification_allowed",
    ):
        if value.get(field) is not False:
            raise SelfImprovementError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ImprovementPolicy:
    policy_id: str
    policy_version: str
    generation: int
    platform_abi: int
    allowed_components: frozenset[str] = ALLOWED_COMPONENTS
    max_ttl: int = 86_400
    max_canary_per_mille: int = 100
    min_quality_delta_per_mille: int = 0
    max_safety_regression_per_mille: int = 0
    require_approval: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        if not self.allowed_components or not self.allowed_components.issubset(ALLOWED_COMPONENTS):
            raise SelfImprovementError("component policy exceeds bounded scaffold set")
        integer(self.max_ttl, "max_ttl", 1, 86_400)
        integer(self.max_canary_per_mille, "max_canary_per_mille", 1, 1000)
        integer(self.min_quality_delta_per_mille, "min_quality_delta_per_mille", -1000, 1000)
        integer(self.max_safety_regression_per_mille, "max_safety_regression_per_mille", 0, 1000)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "platform_abi": self.platform_abi,
            "allowed_components": sorted(self.allowed_components),
            "max_ttl": self.max_ttl,
            "max_canary_per_mille": self.max_canary_per_mille,
            "min_quality_delta_per_mille": self.min_quality_delta_per_mille,
            "max_safety_regression_per_mille": self.max_safety_regression_per_mille,
            "require_approval": self.require_approval,
        })


@dataclass(frozen=True)
class EvaluationEvidence:
    evidence_id: str
    baseline_digest: str
    candidate_digest: str
    task_set_digest: str
    trace_set_digest: str
    quality_delta_per_mille: int
    safety_delta_per_mille: int
    regressions: int
    trials: int
    recorded_at: int

    def __post_init__(self) -> None:
        text(self.evidence_id, "evidence_id", 128)
        for name, value in (("baseline_digest", self.baseline_digest), ("candidate_digest", self.candidate_digest), ("task_set_digest", self.task_set_digest), ("trace_set_digest", self.trace_set_digest)):
            sha(value, name)
        integer(self.quality_delta_per_mille, "quality_delta_per_mille", -1000, 1000)
        integer(self.safety_delta_per_mille, "safety_delta_per_mille", -1000, 1000)
        integer(self.regressions, "regressions", 0, MAX_EVIDENCE)
        integer(self.trials, "trials", 1, MAX_EVIDENCE)
        integer(self.recorded_at, "recorded_at", 0, 2**63 - 1)

    @property
    def evidence_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "evidence_id": self.evidence_id,
            "baseline_digest": self.baseline_digest,
            "candidate_digest": self.candidate_digest,
            "task_set_digest": self.task_set_digest,
            "trace_set_digest": self.trace_set_digest,
            "quality_delta_per_mille": self.quality_delta_per_mille,
            "safety_delta_per_mille": self.safety_delta_per_mille,
            "regressions": self.regressions,
            "trials": self.trials,
            "recorded_at": self.recorded_at,
        })


@dataclass(frozen=True)
class ImprovementCandidate:
    candidate_id: str
    component: str
    baseline_component_digest: str
    candidate_component_digest: str
    diff_digest: str
    policy_digest: str
    platform_abi: int
    generation: int
    submitted_at: int
    expires_at: int
    canary_per_mille: int
    rollback_checkpoint: str
    evidence: EvaluationEvidence
    approval_id: str | None = None

    def __post_init__(self) -> None:
        text(self.candidate_id, "candidate_id", 128)
        if self.component not in ALLOWED_COMPONENTS:
            raise SelfImprovementError("component is not bounded scaffold")
        for name, value in (("baseline_component_digest", self.baseline_component_digest), ("candidate_component_digest", self.candidate_component_digest), ("diff_digest", self.diff_digest), ("policy_digest", self.policy_digest)):
            sha(value, name)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.submitted_at, "submitted_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.submitted_at:
            raise SelfImprovementError("candidate expiry must follow submission")
        integer(self.canary_per_mille, "canary_per_mille", 1, 1000)
        text(self.rollback_checkpoint, "rollback_checkpoint", 128)
        if self.approval_id is not None:
            text(self.approval_id, "approval_id", 128)

    @property
    def candidate_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "candidate_id": self.candidate_id,
            "component": self.component,
            "baseline_component_digest": self.baseline_component_digest,
            "candidate_component_digest": self.candidate_component_digest,
            "diff_digest": self.diff_digest,
            "policy_digest": self.policy_digest,
            "platform_abi": self.platform_abi,
            "generation": self.generation,
            "submitted_at": self.submitted_at,
            "expires_at": self.expires_at,
            "canary_per_mille": self.canary_per_mille,
            "rollback_checkpoint": self.rollback_checkpoint,
            "evidence_digest": self.evidence.evidence_digest,
            "approval_id": self.approval_id,
        })


@dataclass(frozen=True)
class PromotionReceipt:
    receipt_id: str
    candidate_id: str
    candidate_digest: str
    canary_started_at: int
    canary_ended_at: int
    observed_quality_delta_per_mille: int
    observed_safety_delta_per_mille: int
    rollback_requested: bool
    verified_by: str

    def __post_init__(self) -> None:
        text(self.receipt_id, "receipt_id", 128)
        text(self.candidate_id, "candidate_id", 128)
        sha(self.candidate_digest, "candidate_digest")
        integer(self.canary_started_at, "canary_started_at", 0, 2**63 - 1)
        integer(self.canary_ended_at, "canary_ended_at", self.canary_started_at, 2**63 - 1)
        integer(self.observed_quality_delta_per_mille, "observed_quality_delta_per_mille", -1000, 1000)
        integer(self.observed_safety_delta_per_mille, "observed_safety_delta_per_mille", -1000, 1000)
        if not isinstance(self.rollback_requested, bool):
            raise SelfImprovementError("rollback_requested invalid")
        text(self.verified_by, "verified_by", 256)

    @property
    def receipt_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "receipt_id": self.receipt_id,
            "candidate_id": self.candidate_id,
            "candidate_digest": self.candidate_digest,
            "canary_started_at": self.canary_started_at,
            "canary_ended_at": self.canary_ended_at,
            "observed_quality_delta_per_mille": self.observed_quality_delta_per_mille,
            "observed_safety_delta_per_mille": self.observed_safety_delta_per_mille,
            "rollback_requested": self.rollback_requested,
            "verified_by": self.verified_by,
        })


class SelfImprovementLedger:
    def __init__(self, policy: ImprovementPolicy) -> None:
        self.policy = policy
        self._candidates: dict[str, ImprovementCandidate] = {}
        self._uses: set[str] = set()
        self._nonces: set[str] = set()
        self._promotions: set[str] = set()

    def admit_candidate(self, candidate: ImprovementCandidate, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if candidate.candidate_id in self._candidates:
            raise SelfImprovementError("candidate replay")
        if candidate.policy_digest != self.policy.policy_digest:
            raise SelfImprovementError("policy digest mismatch")
        if candidate.platform_abi != self.policy.platform_abi:
            raise SelfImprovementError("platform ABI mismatch")
        if candidate.generation != self.policy.generation:
            raise SelfImprovementError("candidate generation mismatch")
        if candidate.component not in self.policy.allowed_components:
            raise SelfImprovementError("component denied")
        if candidate.canary_per_mille > self.policy.max_canary_per_mille:
            raise SelfImprovementError("canary exceeds policy")
        if candidate.expires_at - candidate.submitted_at > self.policy.max_ttl or now < candidate.submitted_at or now >= candidate.expires_at:
            raise SelfImprovementError("candidate expired or ttl exceeds policy")
        if candidate.baseline_component_digest == candidate.candidate_component_digest:
            raise SelfImprovementError("candidate has no change")
        evidence = candidate.evidence
        if evidence.candidate_digest != candidate.candidate_component_digest or evidence.baseline_digest != candidate.baseline_component_digest:
            raise SelfImprovementError("evidence component binding mismatch")
        if evidence.quality_delta_per_mille < self.policy.min_quality_delta_per_mille:
            raise SelfImprovementError("quality evidence below policy")
        if evidence.safety_delta_per_mille < -self.policy.max_safety_regression_per_mille:
            raise SelfImprovementError("safety regression exceeds policy")
        if evidence.regressions != 0:
            raise SelfImprovementError("regressions present")
        if evidence.recorded_at > now:
            raise SelfImprovementError("evidence is from the future")
        if self.policy.require_approval and candidate.approval_id is None:
            raise SelfImprovementError("approval required")
        self._candidates[candidate.candidate_id] = candidate
        result = {
            "schema": SCHEMA,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.candidate_digest,
            "component": candidate.component,
            "evidence_digest": evidence.evidence_digest,
            "quality_delta_per_mille": evidence.quality_delta_per_mille,
            "safety_delta_per_mille": evidence.safety_delta_per_mille,
            "canary_per_mille": candidate.canary_per_mille,
            "rollback_checkpoint": candidate.rollback_checkpoint,
            "admitted": True,
            "code_modified": False,
            "weights_modified": False,
            "privileged_kernel_modified": False,
            "production_policy_modified": False,
            "deployment_executed": False,
            "models_invoked": False,
            "tools_executed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def verify_canary(self, receipt: PromotionReceipt, *, now: int, authority: Mapping[str, Any], nonce: str) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        text(nonce, "nonce", 256)
        if receipt.receipt_id in self._promotions or nonce in self._nonces:
            raise SelfImprovementError("promotion or nonce replay")
        candidate = self._candidates.get(receipt.candidate_id)
        if candidate is None or receipt.candidate_digest != candidate.candidate_digest:
            raise SelfImprovementError("candidate receipt mismatch")
        if now < receipt.canary_started_at or now < receipt.canary_ended_at:
            raise SelfImprovementError("canary is incomplete")
        if now >= candidate.expires_at:
            raise SelfImprovementError("candidate expired")
        if receipt.rollback_requested:
            raise SelfImprovementError("rollback requested")
        if receipt.observed_quality_delta_per_mille < self.policy.min_quality_delta_per_mille:
            raise SelfImprovementError("observed quality below policy")
        if receipt.observed_safety_delta_per_mille < -self.policy.max_safety_regression_per_mille:
            raise SelfImprovementError("observed safety regression exceeds policy")
        self._promotions.add(receipt.receipt_id)
        self._nonces.add(nonce)
        result = {
            "schema": SCHEMA,
            "receipt_id": receipt.receipt_id,
            "receipt_digest": receipt.receipt_digest,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.candidate_digest,
            "canary_verified": True,
            "promotion_executed": False,
            "rollback_executed": False,
            "code_modified": False,
            "production_policy_modified": False,
            "tools_executed": False,
            "now": now,
            "authority": dict(authority),
        }
        result["verification_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "candidates": sorted(c.candidate_digest for c in self._candidates.values()),
            "promotions": sorted(self._promotions),
            "nonces": sorted(self._nonces),
        })


__all__ = ["SCHEMA", "ALLOWED_COMPONENTS", "SelfImprovementError", "ImprovementPolicy", "EvaluationEvidence", "ImprovementCandidate", "PromotionReceipt", "SelfImprovementLedger", "digest"]
