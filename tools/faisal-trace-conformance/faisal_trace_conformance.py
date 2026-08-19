#!/usr/bin/env python3
"""Post-execution conformance for FAISAL certified traces.

This module compares caller-supplied realized step records with a previously
certified proposal. It never executes tools, signs production receipts, or
claims that a result is correct; it only verifies structural conformance and
returns a halt/rollback/escalation decision when conformance is absent.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from faisal_trace_cert import SCHEMA as CERT_SCHEMA
from faisal_trace_cert import TraceProposal, TraceCertificationError, verify_certificate

SCHEMA = "org.faisal.trace-conformance.v1"
RECEIPT_SCHEMA = "org.faisal.execution-receipt.v1"
MAX_RESULT_DIGEST = 80
STATUSES = frozenset({"completed", "failed", "halted", "rolled_back"})


class TraceConformanceError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise TraceConformanceError(f"{name} is invalid")
    return value


def _hash_text(value: str, name: str) -> str:
    _text(value, name, MAX_RESULT_DIGEST)
    if not value.startswith("sha256:") or len(value) != 71:
        raise TraceConformanceError(f"{name} must be a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise TraceConformanceError(f"{name} is not hexadecimal") from exc
    return value


@dataclass(frozen=True)
class RealizedStep:
    step_id: str
    action: str
    target: str
    capability: str
    status: str
    result_digest: str | None = None
    error_code: str | None = None
    generation: int = 0

    def __post_init__(self) -> None:
        _text(self.step_id, "step_id", 128)
        _text(self.action, "action", 256)
        _text(self.target, "target", 512)
        _text(self.capability, "capability", 128)
        if self.status not in STATUSES:
            raise TraceConformanceError("status is unsupported")
        if self.result_digest is not None:
            _hash_text(self.result_digest, "result_digest")
        if self.error_code is not None:
            _text(self.error_code, "error_code", 128)
        if not isinstance(self.generation, int) or self.generation < 0:
            raise TraceConformanceError("generation is invalid")
        if self.status == "completed" and self.result_digest is None:
            raise TraceConformanceError("completed step requires result_digest")
        if self.status in {"failed", "halted", "rolled_back"} and not self.error_code:
            raise TraceConformanceError("non-completed step requires error_code")

    def canonical(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "action": self.action,
            "target": self.target,
            "capability": self.capability,
            "status": self.status,
            "result_digest": self.result_digest,
            "error_code": self.error_code,
            "generation": self.generation,
        }


def _proposal_step_map(proposal: TraceProposal) -> dict[str, Any]:
    return {step.step_id: step for step in proposal.steps}


def _receipt_payload(proposal: TraceProposal, index: int, realized: RealizedStep, previous_hash: str | None) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "sequence": index,
        "trace_id": proposal.trace_id,
        "proposal_digest": _digest(proposal.canonical()),
        "step": realized.canonical(),
        "previous_receipt_hash": previous_hash,
        "authority": False,
        "signature_present": False,
        "executed_by_this_module": False,
    }


def build_receipt_chain(proposal: TraceProposal, realized_steps: Iterable[RealizedStep]) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    previous: str | None = None
    for index, realized in enumerate(realized_steps):
        payload = _receipt_payload(proposal, index, realized, previous)
        receipt = dict(payload)
        receipt["receipt_hash"] = _digest(payload)
        chain.append(receipt)
        previous = receipt["receipt_hash"]
    return chain


def verify_receipt_chain(proposal: TraceProposal, chain: Iterable[Mapping[str, Any]]) -> bool:
    previous: str | None = None
    expected_proposal_digest = _digest(proposal.canonical())
    for index, receipt in enumerate(chain):
        body = dict(receipt)
        claimed = body.pop("receipt_hash", None)
        if body.get("schema") != RECEIPT_SCHEMA or body.get("sequence") != index:
            return False
        if body.get("trace_id") != proposal.trace_id or body.get("proposal_digest") != expected_proposal_digest:
            return False
        if body.get("previous_receipt_hash") != previous or body.get("authority") is not False or body.get("executed_by_this_module") is not False:
            return False
        if claimed != _digest(body):
            return False
        previous = claimed
    return True


def verify_conformance(proposal: TraceProposal, certificate: Mapping[str, Any], realized_steps: Iterable[RealizedStep], *, expected_generation: int) -> dict[str, Any]:
    if not verify_certificate(certificate, proposal):
        raise TraceConformanceError("certificate verification failed")
    if certificate.get("execution_authorized") is not True or certificate.get("executed") is not False:
        raise TraceConformanceError("certificate execution boundary is invalid")
    realized = tuple(realized_steps)
    if not realized:
        raise TraceConformanceError("realized trace is empty")
    if len(realized) > len(proposal.steps):
        raise TraceConformanceError("realized trace contains extra steps")
    expected = proposal.steps
    terminal_failure: RealizedStep | None = None
    for index, actual in enumerate(realized):
        planned = expected[index]
        if actual.step_id != planned.step_id or actual.action != planned.action or actual.target != planned.target or actual.capability != planned.capability:
            raise TraceConformanceError("realized step diverges from certified proposal")
        if actual.generation != expected_generation or actual.generation != proposal.generation:
            raise TraceConformanceError("realized step generation is stale or mismatched")
        if actual.status != "completed":
            terminal_failure = actual
            if index != len(realized) - 1:
                raise TraceConformanceError("steps executed after a failed or halted step")
            break
    chain = build_receipt_chain(proposal, realized)
    if not verify_receipt_chain(proposal, chain):
        raise TraceConformanceError("receipt chain verification failed")
    if terminal_failure is not None:
        return {
            "schema": SCHEMA,
            "trace_id": proposal.trace_id,
            "proposal_digest": _digest(proposal.canonical()),
            "conformance": "halt_required",
            "completion": False,
            "failure_step_id": terminal_failure.step_id,
            "failure_code": terminal_failure.error_code,
            "next_action": "halt_rollback_or_escalate",
            "receipt_chain": chain,
            "executed_by_this_module": False,
            "result_correctness": False,
        }
    if len(realized) != len(expected):
        return {
            "schema": SCHEMA,
            "trace_id": proposal.trace_id,
            "proposal_digest": _digest(proposal.canonical()),
            "conformance": "incomplete",
            "completion": False,
            "next_action": "do_not_complete_resume_or_escalate",
            "receipt_chain": chain,
            "executed_by_this_module": False,
            "result_correctness": False,
        }
    return {
        "schema": SCHEMA,
        "trace_id": proposal.trace_id,
        "proposal_digest": _digest(proposal.canonical()),
        "conformance": "complete",
        "completion": True,
        "next_action": "close_certified_trace",
        "receipt_chain": chain,
        "executed_by_this_module": False,
        "result_correctness": False,
    }
