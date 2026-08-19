from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.intent-repair.v1"
MAX_TEXT = 256
MAX_ITEMS = 64

class IntentRepairError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise IntentRepairError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise IntentRepairError(f"{name} is not a digest")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise IntentRepairError(f"{name} is outside bounds")
    return value

def digests(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > MAX_ITEMS:
        raise IntentRepairError(f"{name} is outside bounds")
    for value in values: sha(value, f"{name} item")
    if tuple(sorted(set(values))) != values:
        raise IntentRepairError(f"{name} must be sorted and unique")
    return values

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "verifier_output_is_authority", "artifact_is_authority", "intent_receipt_is_execution_authority", "intent_receipt_is_production_authority", "production_approval")
    if any(authority.get(key) is not False for key in required):
        raise IntentRepairError("authority boundary violation")

@dataclass(frozen=True)
class IntentPolicy:
    policy_id: str
    intent_digest: str
    required_constraint_digests: tuple[str, ...]
    generation: int
    issued_at: int
    expires_at: int
    max_subtasks: int
    max_repairs: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); sha(self.intent_digest, "intent_digest"); digests(self.required_constraint_digests, "required_constraint_digests")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_subtasks, "max_subtasks", 1, 10000); integer(self.max_repairs, "max_repairs", 0, 1000)
        if self.expires_at - self.issued_at > 86400: raise IntentRepairError("policy TTL is outside bounds")

@dataclass(frozen=True)
class SubtaskProposal:
    proposal_id: str
    intent_digest: str
    subtask_digest: str
    constraint_digests: tuple[str, ...]
    input_artifact_digests: tuple[str, ...]
    checkpoint_digest: str
    trace_position: int
    generation: int
    issued_at: int

    def __post_init__(self) -> None:
        text(self.proposal_id, "proposal_id"); sha(self.intent_digest, "intent_digest"); sha(self.subtask_digest, "subtask_digest")
        digests(self.constraint_digests, "constraint_digests"); digests(self.input_artifact_digests, "input_artifact_digests"); sha(self.checkpoint_digest, "checkpoint_digest")
        integer(self.trace_position, "trace_position", 0, 2**63 - 1); integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)

@dataclass(frozen=True)
class RepairProposal:
    repair_id: str
    intent_digest: str
    artifact_digest: str
    failed_constraint_digests: tuple[str, ...]
    verifier_digest: str
    checkpoint_digest: str
    trace_position: int
    repair_index: int
    generation: int
    issued_at: int
    verification_passed: bool

    def __post_init__(self) -> None:
        text(self.repair_id, "repair_id"); sha(self.intent_digest, "intent_digest"); sha(self.artifact_digest, "artifact_digest"); digests(self.failed_constraint_digests, "failed_constraint_digests"); sha(self.verifier_digest, "verifier_digest"); sha(self.checkpoint_digest, "checkpoint_digest")
        integer(self.trace_position, "trace_position", 0, 2**63 - 1); integer(self.repair_index, "repair_index", 1, 1000); integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        if not isinstance(self.verification_passed, bool): raise IntentRepairError("verification_passed is invalid")

class IntentRepairLedger:
    def __init__(self, policy: IntentPolicy) -> None:
        self.policy = policy
        self._subtasks: dict[str, dict[str, Any]] = {}
        self._repairs: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    def _common(self, intent_digest: str, generation: int, issued_at: int, current_generation: int, now: int, nonce: str, authority: Mapping[str, Any]) -> None:
        authority_boundary(authority); sha(intent_digest, "intent_digest"); integer(generation, "generation", 1, 2**63 - 1); integer(issued_at, "issued_at", 0, 2**63 - 1); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if generation != current_generation or generation != self.policy.generation: raise IntentRepairError("generation mismatch")
        if intent_digest != self.policy.intent_digest: raise IntentRepairError("global intent mismatch")
        if nonce in self._nonces: raise IntentRepairError("replay")
        if now < issued_at or now < self.policy.issued_at or now >= self.policy.expires_at: raise IntentRepairError("intent policy is stale or expired")

    def admit_subtask(self, proposal: SubtaskProposal, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        self._common(proposal.intent_digest, proposal.generation, proposal.issued_at, current_generation, now, nonce, authority)
        if proposal.proposal_id in self._subtasks: raise IntentRepairError("subtask replay")
        if len(self._subtasks) >= self.policy.max_subtasks: raise IntentRepairError("subtask budget exhausted")
        if not set(self.policy.required_constraint_digests).issubset(proposal.constraint_digests): raise IntentRepairError("required intent constraint missing")
        if self._subtasks and proposal.trace_position <= max(item["trace_position"] for item in self._subtasks.values()): raise IntentRepairError("subtask trace position is not monotonic")
        result = {"schema": SCHEMA, "status": "subtask_admitted", "proposal_id": proposal.proposal_id, "intent_digest": proposal.intent_digest, "subtask_digest": proposal.subtask_digest, "constraint_digests": proposal.constraint_digests, "checkpoint_digest": proposal.checkpoint_digest, "trace_position": proposal.trace_position, "execution_performed": False, "artifact_modified": False, "production_approved": False, "authority": dict(authority)}
        result["receipt_digest"] = digest(result); self._subtasks[proposal.proposal_id] = result; self._nonces.add(nonce)
        return json.loads(json.dumps(result))

    def admit_repair(self, repair: RepairProposal, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        self._common(repair.intent_digest, repair.generation, repair.issued_at, current_generation, now, nonce, authority)
        if repair.repair_id in self._repairs: raise IntentRepairError("repair replay")
        if repair.repair_index > self.policy.max_repairs: raise IntentRepairError("repair budget exhausted")
        if not repair.failed_constraint_digests: raise IntentRepairError("repair requires failed constraints")
        if repair.verification_passed: raise IntentRepairError("repair is unnecessary after passing verification")
        result = {"schema": SCHEMA, "status": "repair_admitted", "repair_id": repair.repair_id, "intent_digest": repair.intent_digest, "artifact_digest": repair.artifact_digest, "failed_constraint_digests": repair.failed_constraint_digests, "verifier_digest": repair.verifier_digest, "checkpoint_digest": repair.checkpoint_digest, "trace_position": repair.trace_position, "repair_index": repair.repair_index, "execution_performed": False, "artifact_modified": False, "verification_performed": False, "production_approved": False, "authority": dict(authority)}
        result["receipt_digest"] = digest(result); self._repairs[repair.repair_id] = result; self._nonces.add(nonce)
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "subtasks": self._subtasks, "repairs": self._repairs})
