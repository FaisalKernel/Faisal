from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.memory-intervention.v1"
MAX_TEXT = 256
MAX_DIGESTS = 64
MAX_TTL = 86_400

class MemoryInterventionError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MemoryInterventionError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise MemoryInterventionError(f"{name} is not a digest")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise MemoryInterventionError(f"{name} is outside bounds")
    return value

def real(value: float, name: str, low: float, high: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < low or value > high:
        raise MemoryInterventionError(f"{name} is outside bounds")
    return float(value)

def digests(values: tuple[str, ...], name: str, minimum: int = 0) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) < minimum or len(values) > MAX_DIGESTS:
        raise MemoryInterventionError(f"{name} is outside bounds")
    for value in values:
        sha(value, f"{name} item")
    if tuple(sorted(set(values))) != values:
        raise MemoryInterventionError(f"{name} must be sorted and unique")
    return values

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = (
        "model_output_is_authority",
        "memory_is_authority",
        "intervention_is_execution_authority",
        "intervention_is_policy_authority",
        "production_approval",
    )
    if any(authority.get(field) is not False for field in required):
        raise MemoryInterventionError("authority boundary violation")

@dataclass(frozen=True)
class MemoryInterventionPolicy:
    policy_id: str
    task_id: str
    session_id: str
    intent_digest: str
    max_memory_sensitivity: int
    generation: int
    issued_at: int
    expires_at: int
    max_tokens: int
    cooldown_steps: int
    max_interventions: int
    min_confidence: float
    min_novelty: float

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.task_id, "task_id"); text(self.session_id, "session_id"); sha(self.intent_digest, "intent_digest")
        integer(self.max_memory_sensitivity, "max_memory_sensitivity", 0, 3); integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_tokens, "max_tokens", 1, 16_384); integer(self.cooldown_steps, "cooldown_steps", 0, 10_000); integer(self.max_interventions, "max_interventions", 1, 10_000)
        real(self.min_confidence, "min_confidence", 0.0, 1.0); real(self.min_novelty, "min_novelty", 0.0, 1.0)
        if self.expires_at - self.issued_at > MAX_TTL:
            raise MemoryInterventionError("policy TTL is outside bounds")

@dataclass(frozen=True)
class MemoryInterventionRequest:
    request_id: str
    task_id: str
    session_id: str
    intent_digest: str
    memory_digest: str
    source_evidence_digests: tuple[str, ...]
    trigger_reason: str
    confidence: float
    novelty: float
    estimated_tokens: int
    memory_sensitivity: int
    step: int
    last_intervention_step: int
    generation: int
    issued_at: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.task_id, "task_id"); text(self.session_id, "session_id"); sha(self.intent_digest, "intent_digest"); sha(self.memory_digest, "memory_digest")
        digests(self.source_evidence_digests, "source_evidence_digests"); text(self.trigger_reason, "trigger_reason", 128)
        real(self.confidence, "confidence", 0.0, 1.0); real(self.novelty, "novelty", 0.0, 1.0); integer(self.estimated_tokens, "estimated_tokens", 1, 16_384)
        integer(self.memory_sensitivity, "memory_sensitivity", 0, 3); integer(self.step, "step", 0, 2**63 - 1); integer(self.last_intervention_step, "last_intervention_step", -1, 2**63 - 1)
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        if self.last_intervention_step >= self.step:
            raise MemoryInterventionError("last_intervention_step must precede current step")

class MemoryInterventionLedger:
    def __init__(self, policy: MemoryInterventionPolicy) -> None:
        self.policy = policy
        self._receipts: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()
        self._memory_digests: set[str] = set()

    def admit(self, request: MemoryInterventionRequest, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if request.request_id in self._receipts or nonce in self._nonces or request.memory_digest in self._memory_digests:
            raise MemoryInterventionError("memory intervention replay")
        if request.task_id != self.policy.task_id or request.session_id != self.policy.session_id:
            raise MemoryInterventionError("task or session scope mismatch")
        if request.intent_digest != self.policy.intent_digest:
            raise MemoryInterventionError("intent scope mismatch")
        if not request.source_evidence_digests:
            raise MemoryInterventionError("memory intervention lacks source evidence")
        if request.generation != current_generation or request.generation != self.policy.generation:
            raise MemoryInterventionError("generation mismatch")
        if now < request.issued_at or now < self.policy.issued_at or now >= self.policy.expires_at:
            raise MemoryInterventionError("memory intervention policy is stale or expired")
        if request.confidence < self.policy.min_confidence or request.novelty < self.policy.min_novelty:
            raise MemoryInterventionError("confidence or novelty threshold not met")
        if request.estimated_tokens > self.policy.max_tokens:
            raise MemoryInterventionError("memory token budget exceeded")
        if request.memory_sensitivity > self.policy.max_memory_sensitivity:
            raise MemoryInterventionError("memory sensitivity exceeds policy")
        if request.last_intervention_step >= 0 and request.step - request.last_intervention_step < self.policy.cooldown_steps:
            raise MemoryInterventionError("memory intervention cooldown active")
        if len(self._receipts) >= self.policy.max_interventions:
            raise MemoryInterventionError("memory intervention budget exhausted")
        result = {
            "schema": SCHEMA,
            "status": "intervention_admitted",
            "request_id": request.request_id,
            "task_id": request.task_id,
            "session_id": request.session_id,
            "intent_digest": request.intent_digest,
            "memory_digest": request.memory_digest,
            "source_evidence_digests": request.source_evidence_digests,
            "trigger_reason": request.trigger_reason,
            "confidence": request.confidence,
            "novelty": request.novelty,
            "estimated_tokens": request.estimated_tokens,
            "memory_sensitivity": request.memory_sensitivity,
            "step": request.step,
            "execution_performed": False,
            "memory_retrieved": False,
            "prompt_injected": False,
            "tools_executed": False,
            "production_approved": False,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        self._receipts[request.request_id] = result; self._nonces.add(nonce); self._memory_digests.add(request.memory_digest)
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "receipts": self._receipts})
