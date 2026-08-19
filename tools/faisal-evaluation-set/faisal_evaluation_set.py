"""Fail-closed admission for reproducible agent evaluation sets.

This module verifies caller-supplied evaluation manifests and results. It does
not create datasets, execute models, grade traces, or approve releases.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.evaluation-set.v1"
MAX_TASKS = 1_000_000
MAX_TTL = 86_400


class EvaluationSetError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise EvaluationSetError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise EvaluationSetError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise EvaluationSetError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise EvaluationSetError(f"{name} is outside bounds")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise EvaluationSetError("authority boundary missing")
    fields = (
        "model_output_is_authority", "grader_output_is_authority",
        "evaluation_receipt_is_deployment_authority", "evaluation_receipt_is_policy_authority",
        "evaluation_receipt_is_production_authority", "dataset_manifest_is_truth",
    )
    for field in fields:
        if value.get(field) is not False:
            raise EvaluationSetError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class EvaluationPolicy:
    policy_id: str
    policy_version: str
    generation: int
    platform_abi: int
    min_task_count: int = 1
    min_coverage_per_mille: int = 1000
    max_overlap_per_mille: int = 0
    max_contamination_per_mille: int = 0
    max_ttl: int = 86_400
    require_independent_split: bool = True
    require_independent_grader: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        integer(self.min_task_count, "min_task_count", 1, MAX_TASKS)
        integer(self.min_coverage_per_mille, "min_coverage_per_mille", 1, 1000)
        integer(self.max_overlap_per_mille, "max_overlap_per_mille", 0, 1000)
        integer(self.max_contamination_per_mille, "max_contamination_per_mille", 0, 1000)
        integer(self.max_ttl, "max_ttl", 1, MAX_TTL)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "platform_abi": self.platform_abi,
            "min_task_count": self.min_task_count,
            "min_coverage_per_mille": self.min_coverage_per_mille,
            "max_overlap_per_mille": self.max_overlap_per_mille,
            "max_contamination_per_mille": self.max_contamination_per_mille,
            "max_ttl": self.max_ttl,
            "require_independent_split": self.require_independent_split,
            "require_independent_grader": self.require_independent_grader,
        })


@dataclass(frozen=True)
class EvaluationSetManifest:
    set_id: str
    task_set_digest: str
    split_digest: str
    grader_digest: str
    policy_digest: str
    task_count: int
    coverage_per_mille: int
    overlap_per_mille: int
    contamination_per_mille: int
    independent_split: bool
    independent_grader: bool
    generation: int
    recorded_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.set_id, "set_id", 128)
        for name, value in (("task_set_digest", self.task_set_digest), ("split_digest", self.split_digest), ("grader_digest", self.grader_digest), ("policy_digest", self.policy_digest)):
            sha(value, name)
        integer(self.task_count, "task_count", 1, MAX_TASKS)
        integer(self.coverage_per_mille, "coverage_per_mille", 0, 1000)
        integer(self.overlap_per_mille, "overlap_per_mille", 0, 1000)
        integer(self.contamination_per_mille, "contamination_per_mille", 0, 1000)
        if not isinstance(self.independent_split, bool) or not isinstance(self.independent_grader, bool):
            raise EvaluationSetError("independence fields invalid")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.recorded_at, "recorded_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.recorded_at + 1, 2**63 - 1)

    @property
    def manifest_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "set_id": self.set_id,
            "task_set_digest": self.task_set_digest,
            "split_digest": self.split_digest,
            "grader_digest": self.grader_digest,
            "policy_digest": self.policy_digest,
            "task_count": self.task_count,
            "coverage_per_mille": self.coverage_per_mille,
            "overlap_per_mille": self.overlap_per_mille,
            "contamination_per_mille": self.contamination_per_mille,
            "independent_split": self.independent_split,
            "independent_grader": self.independent_grader,
            "generation": self.generation,
            "recorded_at": self.recorded_at,
            "expires_at": self.expires_at,
        })


@dataclass(frozen=True)
class EvaluationResult:
    result_id: str
    set_id: str
    manifest_digest: str
    baseline_candidate_digest: str
    candidate_digest: str
    task_result_digest: str
    trace_result_digest: str
    completed_tasks: int
    passed_tasks: int
    safety_failures: int
    recorded_at: int

    def __post_init__(self) -> None:
        text(self.result_id, "result_id", 128)
        text(self.set_id, "set_id", 128)
        for name, value in (("manifest_digest", self.manifest_digest), ("baseline_candidate_digest", self.baseline_candidate_digest), ("candidate_digest", self.candidate_digest), ("task_result_digest", self.task_result_digest), ("trace_result_digest", self.trace_result_digest)):
            sha(value, name)
        integer(self.completed_tasks, "completed_tasks", 0, MAX_TASKS)
        integer(self.passed_tasks, "passed_tasks", 0, self.completed_tasks)
        integer(self.safety_failures, "safety_failures", 0, MAX_TASKS)
        integer(self.recorded_at, "recorded_at", 0, 2**63 - 1)

    @property
    def result_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "result_id": self.result_id,
            "set_id": self.set_id,
            "manifest_digest": self.manifest_digest,
            "baseline_candidate_digest": self.baseline_candidate_digest,
            "candidate_digest": self.candidate_digest,
            "task_result_digest": self.task_result_digest,
            "trace_result_digest": self.trace_result_digest,
            "completed_tasks": self.completed_tasks,
            "passed_tasks": self.passed_tasks,
            "safety_failures": self.safety_failures,
            "recorded_at": self.recorded_at,
        })


class EvaluationSetLedger:
    def __init__(self, policy: EvaluationPolicy) -> None:
        self.policy = policy
        self._manifests: dict[str, EvaluationSetManifest] = {}
        self._results: set[str] = set()
        self._nonces: set[str] = set()

    def admit_manifest(self, manifest: EvaluationSetManifest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if manifest.set_id in self._manifests:
            raise EvaluationSetError("manifest replay")
        if manifest.policy_digest != self.policy.policy_digest:
            raise EvaluationSetError("policy digest mismatch")
        if manifest.generation != self.policy.generation:
            raise EvaluationSetError("manifest generation mismatch")
        if manifest.task_count < self.policy.min_task_count:
            raise EvaluationSetError("task count below policy")
        if manifest.coverage_per_mille < self.policy.min_coverage_per_mille:
            raise EvaluationSetError("coverage below policy")
        if manifest.overlap_per_mille > self.policy.max_overlap_per_mille:
            raise EvaluationSetError("task overlap exceeds policy")
        if manifest.contamination_per_mille > self.policy.max_contamination_per_mille:
            raise EvaluationSetError("contamination exceeds policy")
        if self.policy.require_independent_split and not manifest.independent_split:
            raise EvaluationSetError("independent split required")
        if self.policy.require_independent_grader and not manifest.independent_grader:
            raise EvaluationSetError("independent grader required")
        if manifest.expires_at - manifest.recorded_at > self.policy.max_ttl or now < manifest.recorded_at or now >= manifest.expires_at:
            raise EvaluationSetError("manifest expired or ttl exceeds policy")
        self._manifests[manifest.set_id] = manifest
        result = {
            "schema": SCHEMA,
            "set_id": manifest.set_id,
            "manifest_digest": manifest.manifest_digest,
            "task_count": manifest.task_count,
            "coverage_per_mille": manifest.coverage_per_mille,
            "overlap_per_mille": manifest.overlap_per_mille,
            "contamination_per_mille": manifest.contamination_per_mille,
            "admitted": True,
            "datasets_created": False,
            "models_invoked": False,
            "traces_graded": False,
            "release_approved": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def verify_result(self, result: EvaluationResult, *, now: int, authority: Mapping[str, Any], nonce: str) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        text(nonce, "nonce", 256)
        if result.result_id in self._results or nonce in self._nonces:
            raise EvaluationSetError("result or nonce replay")
        manifest = self._manifests.get(result.set_id)
        if manifest is None or result.manifest_digest != manifest.manifest_digest:
            raise EvaluationSetError("result manifest mismatch")
        if now >= manifest.expires_at:
            raise EvaluationSetError("manifest expired")
        if result.recorded_at > now:
            raise EvaluationSetError("result is from the future")
        if result.completed_tasks != manifest.task_count:
            raise EvaluationSetError("evaluation coverage incomplete")
        if result.safety_failures != 0:
            raise EvaluationSetError("safety failures present")
        self._results.add(result.result_id)
        self._nonces.add(nonce)
        result_data = {
            "schema": SCHEMA,
            "result_id": result.result_id,
            "result_digest": result.result_digest,
            "set_id": result.set_id,
            "manifest_digest": manifest.manifest_digest,
            "completed_tasks": result.completed_tasks,
            "passed_tasks": result.passed_tasks,
            "evaluation_verified": True,
            "models_invoked": False,
            "traces_graded": False,
            "release_approved": False,
            "now": now,
            "authority": dict(authority),
        }
        result_data["verification_digest"] = digest(result_data)
        return result_data

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "manifests": sorted(m.manifest_digest for m in self._manifests.values()),
            "results": sorted(self._results),
            "nonces": sorted(self._nonces),
        })


__all__ = ["SCHEMA", "EvaluationSetError", "EvaluationPolicy", "EvaluationSetManifest", "EvaluationResult", "EvaluationSetLedger", "digest"]
