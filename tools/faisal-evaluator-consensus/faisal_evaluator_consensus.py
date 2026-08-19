"""Fail-closed admission for multi-evaluator agent reliability evidence.

The ledger verifies caller-supplied evaluator receipts. It never runs graders,
invokes models, computes scores, or approves releases.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, Tuple

SCHEMA = "org.faisal.evaluator-consensus.v1"
MAX_EVALUATORS = 128
MAX_TASKS = 1_000_000


class EvaluatorConsensusError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise EvaluatorConsensusError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise EvaluatorConsensusError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise EvaluatorConsensusError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise EvaluatorConsensusError(f"{name} is outside bounds")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise EvaluatorConsensusError("authority boundary missing")
    for field in (
        "model_output_is_authority", "evaluator_output_is_authority",
        "consensus_receipt_is_deployment_authority", "consensus_receipt_is_policy_authority",
        "consensus_receipt_is_production_authority", "confidence_is_truth",
    ):
        if value.get(field) is not False:
            raise EvaluatorConsensusError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ConsensusPolicy:
    policy_id: str
    policy_version: str
    generation: int
    platform_abi: int
    min_evaluators: int = 2
    min_coverage_per_mille: int = 1000
    max_disagreement_per_mille: int = 0
    min_confidence_per_mille: int = 0
    max_safety_failures: int = 0
    max_harm_severity_per_mille: int = 0
    max_ttl: int = 86_400

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        integer(self.min_evaluators, "min_evaluators", 2, MAX_EVALUATORS)
        integer(self.min_coverage_per_mille, "min_coverage_per_mille", 1, 1000)
        integer(self.max_disagreement_per_mille, "max_disagreement_per_mille", 0, 1000)
        integer(self.min_confidence_per_mille, "min_confidence_per_mille", 0, 1000)
        integer(self.max_safety_failures, "max_safety_failures", 0, MAX_TASKS)
        integer(self.max_harm_severity_per_mille, "max_harm_severity_per_mille", 0, 1000)
        integer(self.max_ttl, "max_ttl", 1, 86_400)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "platform_abi": self.platform_abi,
            "min_evaluators": self.min_evaluators,
            "min_coverage_per_mille": self.min_coverage_per_mille,
            "max_disagreement_per_mille": self.max_disagreement_per_mille,
            "min_confidence_per_mille": self.min_confidence_per_mille,
            "max_safety_failures": self.max_safety_failures,
            "max_harm_severity_per_mille": self.max_harm_severity_per_mille,
            "max_ttl": self.max_ttl,
        })


@dataclass(frozen=True)
class EvaluatorReceipt:
    evaluator_id: str
    evaluator_key_epoch: int
    rubric_digest: str
    task_result_digest: str
    trace_result_digest: str
    coverage_per_mille: int
    score_per_mille: int
    confidence_per_mille: int
    disagreement_per_mille: int
    safety_failures: int
    harm_severity_per_mille: int
    recorded_at: int

    def __post_init__(self) -> None:
        text(self.evaluator_id, "evaluator_id", 256)
        integer(self.evaluator_key_epoch, "evaluator_key_epoch", 1, 2**63 - 1)
        for name, value in (("rubric_digest", self.rubric_digest), ("task_result_digest", self.task_result_digest), ("trace_result_digest", self.trace_result_digest)):
            sha(value, name)
        integer(self.coverage_per_mille, "coverage_per_mille", 0, 1000)
        integer(self.score_per_mille, "score_per_mille", 0, 1000)
        integer(self.confidence_per_mille, "confidence_per_mille", 0, 1000)
        integer(self.disagreement_per_mille, "disagreement_per_mille", 0, 1000)
        integer(self.safety_failures, "safety_failures", 0, MAX_TASKS)
        integer(self.harm_severity_per_mille, "harm_severity_per_mille", 0, 1000)
        integer(self.recorded_at, "recorded_at", 0, 2**63 - 1)

    @property
    def receipt_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "evaluator_id": self.evaluator_id,
            "evaluator_key_epoch": self.evaluator_key_epoch,
            "rubric_digest": self.rubric_digest,
            "task_result_digest": self.task_result_digest,
            "trace_result_digest": self.trace_result_digest,
            "coverage_per_mille": self.coverage_per_mille,
            "score_per_mille": self.score_per_mille,
            "confidence_per_mille": self.confidence_per_mille,
            "disagreement_per_mille": self.disagreement_per_mille,
            "safety_failures": self.safety_failures,
            "harm_severity_per_mille": self.harm_severity_per_mille,
            "recorded_at": self.recorded_at,
        })


@dataclass(frozen=True)
class ConsensusRequest:
    request_id: str
    evaluation_set_id: str
    evaluation_manifest_digest: str
    candidate_digest: str
    policy_digest: str
    platform_abi: int
    generation: int
    submitted_at: int
    expires_at: int
    receipts: Tuple[EvaluatorReceipt, ...]

    def __post_init__(self) -> None:
        text(self.request_id, "request_id", 128)
        text(self.evaluation_set_id, "evaluation_set_id", 128)
        for name, value in (("evaluation_manifest_digest", self.evaluation_manifest_digest), ("candidate_digest", self.candidate_digest), ("policy_digest", self.policy_digest)):
            sha(value, name)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.submitted_at, "submitted_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.submitted_at + 1, 2**63 - 1)
        if not self.receipts or len(self.receipts) > MAX_EVALUATORS:
            raise EvaluatorConsensusError("evaluator receipt count is outside bounds")

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "request_id": self.request_id,
            "evaluation_set_id": self.evaluation_set_id,
            "evaluation_manifest_digest": self.evaluation_manifest_digest,
            "candidate_digest": self.candidate_digest,
            "policy_digest": self.policy_digest,
            "platform_abi": self.platform_abi,
            "generation": self.generation,
            "submitted_at": self.submitted_at,
            "expires_at": self.expires_at,
            "receipts": [r.receipt_digest for r in self.receipts],
        })


class EvaluatorConsensusLedger:
    def __init__(self, policy: ConsensusPolicy) -> None:
        self.policy = policy
        self._requests: dict[str, ConsensusRequest] = {}
        self._nonces: set[str] = set()

    def admit(self, request: ConsensusRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.request_id in self._requests:
            raise EvaluatorConsensusError("request replay")
        if request.policy_digest != self.policy.policy_digest:
            raise EvaluatorConsensusError("policy digest mismatch")
        if request.platform_abi != self.policy.platform_abi:
            raise EvaluatorConsensusError("platform ABI mismatch")
        if request.generation != self.policy.generation:
            raise EvaluatorConsensusError("generation mismatch")
        if request.expires_at - request.submitted_at > self.policy.max_ttl or now < request.submitted_at or now >= request.expires_at:
            raise EvaluatorConsensusError("request expired or ttl exceeds policy")
        ids = [r.evaluator_id for r in request.receipts]
        if len(set(ids)) != len(ids):
            raise EvaluatorConsensusError("duplicate evaluator identity")
        if len(request.receipts) < self.policy.min_evaluators:
            raise EvaluatorConsensusError("insufficient evaluators")
        rubrics = {r.rubric_digest for r in request.receipts}
        if len(rubrics) != 1:
            raise EvaluatorConsensusError("rubric generation disagreement")
        for receipt in request.receipts:
            if receipt.recorded_at > now:
                raise EvaluatorConsensusError("receipt is from the future")
            if receipt.coverage_per_mille < self.policy.min_coverage_per_mille:
                raise EvaluatorConsensusError("evaluator coverage below policy")
            if receipt.disagreement_per_mille > self.policy.max_disagreement_per_mille:
                raise EvaluatorConsensusError("evaluator disagreement exceeds policy")
            if receipt.confidence_per_mille < self.policy.min_confidence_per_mille:
                raise EvaluatorConsensusError("evaluator confidence below policy")
            if receipt.safety_failures > self.policy.max_safety_failures:
                raise EvaluatorConsensusError("safety failures exceed policy")
            if receipt.harm_severity_per_mille > self.policy.max_harm_severity_per_mille:
                raise EvaluatorConsensusError("harm severity exceeds policy")
        task_digests = {r.task_result_digest for r in request.receipts}
        trace_digests = {r.trace_result_digest for r in request.receipts}
        if len(task_digests) != 1 or len(trace_digests) != 1:
            raise EvaluatorConsensusError("evidence lineage disagreement")
        scores = [r.score_per_mille for r in request.receipts]
        if max(scores) - min(scores) > self.policy.max_disagreement_per_mille:
            raise EvaluatorConsensusError("score disagreement exceeds policy")
        self._requests[request.request_id] = request
        result = {
            "schema": SCHEMA,
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "evaluation_set_id": request.evaluation_set_id,
            "candidate_digest": request.candidate_digest,
            "evaluator_count": len(request.receipts),
            "rubric_digest": next(iter(rubrics)),
            "score_min_per_mille": min(scores),
            "score_max_per_mille": max(scores),
            "consensus_verified": True,
            "models_invoked": False,
            "graders_invoked": False,
            "release_approved": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def acknowledge(self, request_id: str, *, nonce: str) -> dict[str, Any]:
        text(nonce, "nonce", 256)
        if request_id not in self._requests:
            raise EvaluatorConsensusError("unknown request")
        if nonce in self._nonces:
            raise EvaluatorConsensusError("nonce replay")
        self._nonces.add(nonce)
        return {"schema": SCHEMA, "request_id": request_id, "acknowledged": True, "release_approved": False, "models_invoked": False, "graders_invoked": False, "ack_digest": digest({"request_id": request_id, "nonce": nonce})}

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_digest": self.policy.policy_digest, "requests": sorted(r.request_digest for r in self._requests.values()), "nonces": sorted(self._nonces)})


__all__ = ["SCHEMA", "EvaluatorConsensusError", "ConsensusPolicy", "EvaluatorReceipt", "ConsensusRequest", "EvaluatorConsensusLedger", "digest"]
