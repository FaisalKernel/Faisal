from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.interrupt-fence.v1"
MAX_TTL = 86_400
MAX_TRACE_LAG = 1_000_000
OPERATIONS = {"pause", "revise", "retract", "resume", "rollback"}

class InterruptFenceError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise InterruptFenceError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise InterruptFenceError(f"{name} is not a digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise InterruptFenceError(f"{name} is not a digest") from exc
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise InterruptFenceError(f"{name} is outside bounds")
    return value

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "interrupt_is_execution_authority", "rollback_is_execution_authority", "revocation_is_credential_authority", "side_effect_ledger_is_truth", "production_approval")
    if any(authority.get(field) is not False for field in required):
        raise InterruptFenceError("authority boundary violation")

@dataclass(frozen=True)
class InterruptFencePolicy:
    policy_id: str
    task_id: str
    intent_digest: str
    generation: int
    issued_at: int
    expires_at: int
    max_checkpoint_age: int = 100_000
    max_trace_lag: int = MAX_TRACE_LAG
    require_fork_after_irreversible_effect: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.task_id, "task_id"); sha(self.intent_digest, "intent_digest")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_checkpoint_age, "max_checkpoint_age", 1, MAX_TRACE_LAG); integer(self.max_trace_lag, "max_trace_lag", 1, MAX_TRACE_LAG)
        if self.expires_at - self.issued_at > MAX_TTL: raise InterruptFenceError("policy TTL is outside bounds")
        if not isinstance(self.require_fork_after_irreversible_effect, bool): raise InterruptFenceError("fork policy flag is invalid")

@dataclass(frozen=True)
class InterruptRequest:
    request_id: str
    operation: str
    task_id: str
    parent_intent_digest: str
    requested_intent_digest: str
    intent_generation: int
    checkpoint_digest: str
    checkpoint_trace_position: int
    current_trace_position: int
    checkpoint_side_effect_root: str
    current_side_effect_root: str
    checkpoint_irreversible_watermark: int
    current_irreversible_watermark: int
    transition_sequence: int
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.operation, "operation")
        if self.operation not in OPERATIONS: raise InterruptFenceError("unsupported interrupt operation")
        text(self.task_id, "task_id"); sha(self.parent_intent_digest, "parent_intent_digest"); sha(self.requested_intent_digest, "requested_intent_digest"); integer(self.intent_generation, "intent_generation", 1, 2**63 - 1)
        sha(self.checkpoint_digest, "checkpoint_digest"); integer(self.checkpoint_trace_position, "checkpoint_trace_position", 0, 2**63 - 1); integer(self.current_trace_position, "current_trace_position", self.checkpoint_trace_position, 2**63 - 1)
        sha(self.checkpoint_side_effect_root, "checkpoint_side_effect_root"); sha(self.current_side_effect_root, "current_side_effect_root"); integer(self.checkpoint_irreversible_watermark, "checkpoint_irreversible_watermark", 0, 2**63 - 1); integer(self.current_irreversible_watermark, "current_irreversible_watermark", self.checkpoint_irreversible_watermark, 2**63 - 1)
        integer(self.transition_sequence, "transition_sequence", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL: raise InterruptFenceError("request TTL is outside bounds")
        if self.operation in {"pause", "resume", "rollback"} and self.parent_intent_digest != self.requested_intent_digest:
            raise InterruptFenceError("stable operation cannot change intent")
        if self.operation in {"revise", "retract"} and self.parent_intent_digest == self.requested_intent_digest:
            raise InterruptFenceError("intent-changing operation requires a new intent digest")

    @property
    def request_digest(self) -> str:
        return digest({"schema": SCHEMA, "request_id": self.request_id, "operation": self.operation, "task_id": self.task_id, "parent_intent_digest": self.parent_intent_digest, "requested_intent_digest": self.requested_intent_digest, "intent_generation": self.intent_generation, "checkpoint_digest": self.checkpoint_digest, "checkpoint_trace_position": self.checkpoint_trace_position, "current_trace_position": self.current_trace_position, "checkpoint_side_effect_root": self.checkpoint_side_effect_root, "current_side_effect_root": self.current_side_effect_root, "checkpoint_irreversible_watermark": self.checkpoint_irreversible_watermark, "current_irreversible_watermark": self.current_irreversible_watermark, "transition_sequence": self.transition_sequence, "issued_at": self.issued_at, "expires_at": self.expires_at})

class InterruptFenceLedger:
    def __init__(self, policy: InterruptFencePolicy) -> None:
        self.policy = policy
        self._receipts: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()
        self._phase = "running"
        self._generation = policy.generation
        self._intent_digest = policy.intent_digest
        self._next_sequence = 1

    def admit(self, request: InterruptRequest, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if request.request_digest in self._receipts or nonce in self._nonces: raise InterruptFenceError("interrupt request replay")
        if request.task_id != self.policy.task_id: raise InterruptFenceError("task scope mismatch")
        if request.transition_sequence != self._next_sequence: raise InterruptFenceError("transition sequence is not monotonic")
        if request.operation in {"pause", "resume", "rollback"} and (request.intent_generation != current_generation or request.intent_generation != self._generation): raise InterruptFenceError("intent generation mismatch")
        if request.operation in {"pause", "resume", "rollback"} and request.requested_intent_digest != self._intent_digest: raise InterruptFenceError("stale intent resume or rollback")
        if request.operation in {"revise", "retract"} and request.parent_intent_digest != self._intent_digest: raise InterruptFenceError("revision parent intent mismatch")
        if request.operation in {"revise", "retract"} and request.intent_generation != current_generation + 1: raise InterruptFenceError("intent revision must advance generation")
        if now < request.issued_at or now >= request.expires_at or now < self.policy.issued_at or now >= self.policy.expires_at: raise InterruptFenceError("interrupt request is stale or expired")
        if request.current_trace_position - request.checkpoint_trace_position > self.policy.max_trace_lag: raise InterruptFenceError("checkpoint is too stale")
        if request.operation == "pause" and self._phase != "running": raise InterruptFenceError("pause requires running phase")
        if request.operation in {"revise", "retract"} and self._phase == "rolled_back": raise InterruptFenceError("cannot revise after rollback without new task lineage")
        if request.operation == "resume" and self._phase not in {"paused", "interrupted"}: raise InterruptFenceError("resume requires paused or interrupted phase")
        if request.operation == "rollback" and self._phase not in {"paused", "interrupted"}: raise InterruptFenceError("rollback requires paused or interrupted phase")
        if request.operation == "rollback" and request.checkpoint_trace_position >= request.current_trace_position: raise InterruptFenceError("rollback checkpoint is not older than current trace")
        effect_fork_required = request.operation == "rollback" and request.checkpoint_irreversible_watermark < request.current_irreversible_watermark
        if effect_fork_required and not self.policy.require_fork_after_irreversible_effect: raise InterruptFenceError("rollback crosses irreversible side effect")
        verdict = "require_fork" if effect_fork_required else "admit"
        if request.operation == "pause": self._phase = "paused"
        elif request.operation in {"revise", "retract"}: self._phase = "interrupted"; self._generation = request.intent_generation; self._intent_digest = request.requested_intent_digest
        elif request.operation == "resume": self._phase = "running"
        elif request.operation == "rollback" and not effect_fork_required: self._phase = "rolled_back"
        result = {"schema": SCHEMA, "status": "interrupt_fence_verdict", "verdict": verdict, "request_digest": request.request_digest, "operation": request.operation, "task_id": request.task_id, "phase": self._phase, "intent_digest": self._intent_digest, "intent_generation": self._generation, "transition_sequence": request.transition_sequence, "checkpoint_digest": request.checkpoint_digest, "checkpoint_trace_position": request.checkpoint_trace_position, "current_trace_position": request.current_trace_position, "checkpoint_irreversible_watermark": request.checkpoint_irreversible_watermark, "current_irreversible_watermark": request.current_irreversible_watermark, "effect_fork_required": effect_fork_required, "external_effects_undone": False, "process_paused": False, "credentials_revoked": False, "rollback_executed": False, "tools_executed": False, "authority": dict(authority), "production_approved": False}
        result["receipt_digest"] = digest(result); self._receipts[request.request_digest] = result; self._nonces.add(nonce); self._next_sequence += 1
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "phase": self._phase, "generation": self._generation, "intent_digest": self._intent_digest, "next_sequence": self._next_sequence, "receipts": self._receipts})
