#!/usr/bin/env python3
"""Bounded Proposal-Certification-Execution contract for FAISAL.

The module certifies a proposed trace; it never executes steps, calls models, or
turns model output into authority. Trusted evidence, policy version, and replay
state are supplied by the caller-side control plane.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.trace-certification.v1"
MAX_STEPS = 256
MAX_EVIDENCE_PER_STEP = 32
MAX_TOTAL_COST = 10_000
MAX_DEPENDENCIES = 32
RISK_LEVELS = ("low", "medium", "high", "critical")


class TraceCertificationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TraceCertificationError(f"{name} is invalid")
    return value


@dataclass(frozen=True)
class EvidenceRef:
    digest: str
    kind: str
    source: str
    authority: bool = False

    def __post_init__(self) -> None:
        _text(self.digest, "evidence digest", 80)
        _text(self.kind, "evidence kind", 64)
        _text(self.source, "evidence source", 512)
        if self.authority:
            raise TraceCertificationError("evidence cannot be execution authority")

    def canonical(self) -> dict[str, Any]:
        return {"digest": self.digest, "kind": self.kind, "source": self.source, "authority": False}


@dataclass(frozen=True)
class TraceStep:
    step_id: str
    kind: str
    action: str
    target: str
    capability: str
    evidence_digests: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    cost_units: int = 0
    risk: str = "low"
    side_effect: bool = False
    generation: int = 0

    def __post_init__(self) -> None:
        _text(self.step_id, "step_id", 128)
        _text(self.kind, "kind", 64)
        _text(self.action, "action", 256)
        _text(self.target, "target", 512)
        _text(self.capability, "capability", 128)
        if self.risk not in RISK_LEVELS:
            raise TraceCertificationError("risk is unsupported")
        if not isinstance(self.cost_units, int) or self.cost_units < 0 or self.cost_units > MAX_TOTAL_COST:
            raise TraceCertificationError("cost_units is outside bounds")
        if not isinstance(self.generation, int) or self.generation < 0:
            raise TraceCertificationError("step generation is invalid")
        if len(self.evidence_digests) > MAX_EVIDENCE_PER_STEP or len(set(self.evidence_digests)) != len(self.evidence_digests):
            raise TraceCertificationError("evidence references are invalid")
        if len(self.depends_on) > MAX_DEPENDENCIES or len(set(self.depends_on)) != len(self.depends_on):
            raise TraceCertificationError("dependencies are invalid")

    def canonical(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "kind": self.kind,
            "action": self.action,
            "target": self.target,
            "capability": self.capability,
            "evidence_digests": list(self.evidence_digests),
            "depends_on": list(self.depends_on),
            "cost_units": self.cost_units,
            "risk": self.risk,
            "side_effect": self.side_effect,
            "generation": self.generation,
        }


@dataclass(frozen=True)
class TraceProposal:
    trace_id: str
    caller: str
    policy_version: str
    generation: int
    nonce: str
    steps: tuple[TraceStep, ...]
    max_cost_units: int
    capability_scopes: frozenset[str]
    approval_digests: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _text(self.trace_id, "trace_id", 128)
        _text(self.caller, "caller", 128)
        _text(self.policy_version, "policy_version", 128)
        _text(self.nonce, "nonce", 128)
        if not isinstance(self.generation, int) or self.generation < 0:
            raise TraceCertificationError("generation is invalid")
        if not 1 <= len(self.steps) <= MAX_STEPS:
            raise TraceCertificationError("step count is outside bounds")
        if not 0 <= self.max_cost_units <= MAX_TOTAL_COST:
            raise TraceCertificationError("max_cost_units is outside bounds")
        if not self.capability_scopes:
            raise TraceCertificationError("capability_scopes cannot be empty")
        if any(not isinstance(x, str) or not x for x in self.capability_scopes):
            raise TraceCertificationError("capability scope is invalid")

    def canonical(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "caller": self.caller,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "nonce": self.nonce,
            "steps": [step.canonical() for step in self.steps],
            "max_cost_units": self.max_cost_units,
            "capability_scopes": sorted(self.capability_scopes),
            "approval_digests": sorted(self.approval_digests),
        }


class ReplayGuard:
    def __init__(self, limit: int = 4096) -> None:
        if not 1 <= limit <= 65536:
            raise TraceCertificationError("replay guard limit is outside bounds")
        self._limit = limit
        self._seen: dict[str, None] = {}

    def check_and_record(self, nonce: str) -> None:
        if nonce in self._seen:
            raise TraceCertificationError("trace nonce replay rejected")
        self._seen[nonce] = None
        if len(self._seen) > self._limit:
            del self._seen[next(iter(self._seen))]


def certify_trace(
    proposal: TraceProposal,
    evidence_registry: Mapping[str, EvidenceRef],
    *,
    expected_policy_version: str,
    expected_generation: int,
    replay_guard: ReplayGuard,
) -> dict[str, Any]:
    if proposal.policy_version != expected_policy_version:
        raise TraceCertificationError("stale policy version")
    if proposal.generation != expected_generation:
        raise TraceCertificationError("stale trace generation")
    replay_guard.check_and_record(proposal.nonce)
    step_ids = [step.step_id for step in proposal.steps]
    if len(set(step_ids)) != len(step_ids):
        raise TraceCertificationError("duplicate step id")
    position = {step_id: index for index, step_id in enumerate(step_ids)}
    total_cost = 0
    referenced_evidence: set[str] = set()
    for index, step in enumerate(proposal.steps):
        if step.generation != proposal.generation:
            raise TraceCertificationError("step generation does not match trace")
        for dependency in step.depends_on:
            if dependency not in position or position[dependency] >= index:
                raise TraceCertificationError("dependency is missing or not topologically ordered")
        if step.capability not in proposal.capability_scopes and "*" not in proposal.capability_scopes:
            raise TraceCertificationError("step capability is not granted")
        total_cost += step.cost_units
        if total_cost > proposal.max_cost_units:
            raise TraceCertificationError("trace cost budget exceeded")
        if step.side_effect:
            required = f"execute:{step.action}"
            if required not in proposal.capability_scopes and "execute:*" not in proposal.capability_scopes and "*" not in proposal.capability_scopes:
                raise TraceCertificationError("side-effect capability is not granted")
            if step.risk in {"high", "critical"} and f"approval:{step.step_id}" not in proposal.approval_digests:
                raise TraceCertificationError("high-risk step lacks trusted approval digest")
        for digest in step.evidence_digests:
            evidence = evidence_registry.get(digest)
            if evidence is None:
                raise TraceCertificationError("trace references unknown evidence")
            if evidence.authority:
                raise TraceCertificationError("evidence authority boundary violated")
            referenced_evidence.add(digest)
    proposal_digest = _digest(proposal.canonical())
    certificate_body = {
        "schema": SCHEMA,
        "trace_id": proposal.trace_id,
        "proposal_digest": proposal_digest,
        "policy_version": proposal.policy_version,
        "generation": proposal.generation,
        "step_count": len(proposal.steps),
        "total_cost_units": total_cost,
        "evidence_digests": sorted(referenced_evidence),
        "certified": True,
        "execution_authorized": True,
        "executed": False,
        "model_output_is_authority": False,
        "evidence_is_authority": False,
        "certificate_is_execution": False,
    }
    certificate_body["certificate_digest"] = _digest(certificate_body)
    return certificate_body


def verify_certificate(certificate: Mapping[str, Any], proposal: TraceProposal) -> bool:
    if certificate.get("schema") != SCHEMA or certificate.get("certified") is not True:
        return False
    if certificate.get("proposal_digest") != _digest(proposal.canonical()):
        return False
    if certificate.get("trace_id") != proposal.trace_id or certificate.get("generation") != proposal.generation:
        return False
    if certificate.get("executed") is not False or certificate.get("certificate_is_execution") is not False:
        return False
    body = dict(certificate)
    claimed = body.pop("certificate_digest", None)
    return claimed == _digest(body)
