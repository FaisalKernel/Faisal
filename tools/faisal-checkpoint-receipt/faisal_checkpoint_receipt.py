#!/usr/bin/env python3
"""FAISAL durable execution checkpoint receipt contract.

This module records and verifies resumable objective checkpoints without executing
work, contacting an authority server, minting credentials, or treating model and
provider output as authority. It is designed as a provider-neutral control-plane
contract that can sit beside the kernel execution engine's persisted checkpoint.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "org.faisal.execution-checkpoint-receipt.v1"
MAX_RECEIPTS = 4096
MAX_OBJECTIVES = 256
MAX_AGE_SECONDS = 86_400


class CheckpointContractError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise CheckpointContractError(f"{name}: invalid")
    return value


def _digest(value: Any, name: str) -> str:
    value = _text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise CheckpointContractError(f"{name}: invalid digest")
    return value


def _u64(value: Any, name: str, *, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if not isinstance(value, int) or not minimum <= value <= maximum:
        raise CheckpointContractError(f"{name}: invalid")
    return value


@dataclass(frozen=True)
class CheckpointInput:
    objective_id: str
    execution_generation: int
    checkpoint_sequence: int
    lease_id: str
    lease_generation: int
    trace_digest: str
    state_digest: str
    world_digest: str
    resource_digest: str
    event_sequence: int
    event_digest: str
    previous_checkpoint_digest: str | None
    created_at: int

    def canonical(self) -> dict[str, Any]:
        return {
            "objective_id": _text(self.objective_id, "objective_id"),
            "execution_generation": _u64(self.execution_generation, "execution_generation", minimum=1),
            "checkpoint_sequence": _u64(self.checkpoint_sequence, "checkpoint_sequence", minimum=1),
            "lease_id": _text(self.lease_id, "lease_id"),
            "lease_generation": _u64(self.lease_generation, "lease_generation", minimum=1),
            "trace_digest": _digest(self.trace_digest, "trace_digest"),
            "state_digest": _digest(self.state_digest, "state_digest"),
            "world_digest": _digest(self.world_digest, "world_digest"),
            "resource_digest": _digest(self.resource_digest, "resource_digest"),
            "event_sequence": _u64(self.event_sequence, "event_sequence", minimum=1),
            "event_digest": _digest(self.event_digest, "event_digest"),
            "previous_checkpoint_digest": None if self.previous_checkpoint_digest is None else _digest(self.previous_checkpoint_digest, "previous_checkpoint_digest"),
            "created_at": _u64(self.created_at, "created_at"),
        }


@dataclass
class _CheckpointHead:
    receipt_digest: str
    checkpoint_sequence: int
    event_sequence: int
    created_at: int
    lease_id: str
    lease_generation: int
    execution_generation: int


class CheckpointLedger:
    """Bounded offline checkpoint chain and recovery-admission ledger."""

    def __init__(self, *, max_receipts: int = MAX_RECEIPTS, max_objectives: int = MAX_OBJECTIVES, max_age_seconds: int = MAX_AGE_SECONDS) -> None:
        if not 1 <= max_receipts <= MAX_RECEIPTS:
            raise CheckpointContractError("max_receipts is outside bounds")
        if not 1 <= max_objectives <= MAX_OBJECTIVES:
            raise CheckpointContractError("max_objectives is outside bounds")
        if not 1 <= max_age_seconds <= MAX_AGE_SECONDS:
            raise CheckpointContractError("max_age_seconds is outside bounds")
        self.max_receipts = max_receipts
        self.max_objectives = max_objectives
        self.max_age_seconds = max_age_seconds
        self._heads: dict[str, _CheckpointHead] = {}
        self._receipts: dict[str, dict[str, Any]] = {}
        self._resume_digests: set[str] = set()
        self._version = 0

    @property
    def version(self) -> int:
        return self._version

    def record(self, checkpoint: CheckpointInput, *, now: int, current_execution_generation: int, current_lease_id: str, current_lease_generation: int) -> dict[str, Any]:
        body = checkpoint.canonical()
        now = _u64(now, "now")
        _u64(current_execution_generation, "current_execution_generation", minimum=1)
        _text(current_lease_id, "current_lease_id")
        _u64(current_lease_generation, "current_lease_generation", minimum=1)
        if body["execution_generation"] != current_execution_generation:
            raise CheckpointContractError("execution generation fence mismatch")
        if body["lease_id"] != current_lease_id or body["lease_generation"] != current_lease_generation:
            raise CheckpointContractError("lease fence mismatch")
        if body["created_at"] > now or now - body["created_at"] > self.max_age_seconds:
            raise CheckpointContractError("checkpoint freshness window violated")
        head = self._heads.get(body["objective_id"])
        if head is None:
            if len(self._heads) >= self.max_objectives:
                raise CheckpointContractError("objective bound exceeded")
            if body["checkpoint_sequence"] != 1 or body["previous_checkpoint_digest"] is not None:
                raise CheckpointContractError("initial checkpoint chain linkage invalid")
        else:
            if body["checkpoint_sequence"] != head.checkpoint_sequence + 1:
                raise CheckpointContractError("checkpoint sequence is not monotonic")
            if body["event_sequence"] <= head.event_sequence:
                raise CheckpointContractError("event sequence is not monotonic")
            if body["created_at"] < head.created_at:
                raise CheckpointContractError("checkpoint time moved backward")
            if body["previous_checkpoint_digest"] != head.receipt_digest:
                raise CheckpointContractError("checkpoint predecessor mismatch")
            if body["execution_generation"] != head.execution_generation:
                raise CheckpointContractError("checkpoint generation changed without a new execution")
        if len(self._receipts) >= self.max_receipts:
            raise CheckpointContractError("checkpoint receipt bound exceeded")
        receipt = {
            "schema": SCHEMA,
            "checkpoint": body,
            "authority": {
                "model_output_is_authority": False,
                "provider_metadata_is_authority": False,
                "checkpoint_is_execution": False,
                "receipt_is_model_correctness_proof": False,
                "recovery_requires_caller_policy": True,
                "production_approval": False,
            },
        }
        receipt_digest = digest(receipt)
        receipt["receipt_digest"] = receipt_digest
        self._receipts[receipt_digest] = receipt
        self._heads[body["objective_id"]] = _CheckpointHead(receipt_digest, body["checkpoint_sequence"], body["event_sequence"], body["created_at"], body["lease_id"], body["lease_generation"], body["execution_generation"])
        self._version += 1
        return {**receipt, "verified": True}

    def verify(self, receipt: Mapping[str, Any], *, objective_id: str, expected_execution_generation: int, expected_lease_id: str, expected_lease_generation: int) -> dict[str, Any]:
        if not isinstance(receipt, Mapping) or receipt.get("schema") != SCHEMA:
            raise CheckpointContractError("receipt schema unsupported")
        declared = receipt.get("receipt_digest")
        unsigned = dict(receipt)
        unsigned.pop("receipt_digest", None)
        unsigned.pop("verified", None)
        if declared != digest(unsigned):
            raise CheckpointContractError("receipt digest mismatch")
        authority = receipt.get("authority")
        if not isinstance(authority, Mapping) or any(authority.get(key) is not False for key in ("model_output_is_authority", "provider_metadata_is_authority", "checkpoint_is_execution", "receipt_is_model_correctness_proof")):
            raise CheckpointContractError("receipt authority boundary missing")
        body = CheckpointInput(**dict(receipt.get("checkpoint", {}))).canonical()
        if body["objective_id"] != _text(objective_id, "objective_id"):
            raise CheckpointContractError("objective identity mismatch")
        if body["execution_generation"] != _u64(expected_execution_generation, "expected_execution_generation", minimum=1):
            raise CheckpointContractError("execution generation mismatch")
        if body["lease_id"] != _text(expected_lease_id, "expected_lease_id") or body["lease_generation"] != _u64(expected_lease_generation, "expected_lease_generation", minimum=1):
            raise CheckpointContractError("lease identity mismatch")
        return {"verified": True, "receipt_digest": declared, "objective_id": body["objective_id"], "checkpoint_sequence": body["checkpoint_sequence"], "event_sequence": body["event_sequence"], "recovery_requires_caller_policy": True}

    def admit_resume(self, receipt: Mapping[str, Any], *, objective_id: str, expected_execution_generation: int, expected_lease_id: str, expected_lease_generation: int, resume_nonce: str) -> dict[str, Any]:
        verified = self.verify(receipt, objective_id=objective_id, expected_execution_generation=expected_execution_generation, expected_lease_id=expected_lease_id, expected_lease_generation=expected_lease_generation)
        nonce = _text(resume_nonce, "resume_nonce", 256)
        resume_material = {"receipt_digest": verified["receipt_digest"], "objective_id": objective_id, "execution_generation": expected_execution_generation, "lease_id": expected_lease_id, "lease_generation": expected_lease_generation, "resume_nonce": nonce}
        resume_digest = digest(resume_material)
        if resume_digest in self._resume_digests:
            raise CheckpointContractError("resume replay detected")
        self._resume_digests.add(resume_digest)
        return {**verified, "resume_digest": resume_digest, "admitted": True, "model_output_is_authority": False, "resume_is_execution": False}

    def digest(self) -> str:
        return digest({"version": self._version, "heads": {key: vars(value) for key, value in sorted(self._heads.items())}, "receipts": sorted(self._receipts), "resumes": sorted(self._resume_digests)})
