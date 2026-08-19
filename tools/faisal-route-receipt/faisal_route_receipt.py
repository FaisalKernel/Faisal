from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.route-receipt.v1"
MAX_TEXT = 256
MAX_CHAIN = 16
MAX_STEPS = 256
MAX_TTL = 86_400

class RouteReceiptError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise RouteReceiptError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise RouteReceiptError(f"{name} is not a digest")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise RouteReceiptError(f"{name} is outside bounds")
    return value

def real(value: float, name: str, low: float, high: float) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or value < low or value > high:
        raise RouteReceiptError(f"{name} is outside bounds")
    return float(value)

def names(values: tuple[str, ...], name: str, minimum: int = 0, maximum: int = MAX_CHAIN) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) < minimum or len(values) > maximum or any(not isinstance(value, str) or not value or len(value) > MAX_TEXT for value in values):
        raise RouteReceiptError(f"{name} is outside bounds")
    if len(set(values)) != len(values):
        raise RouteReceiptError(f"{name} must be unique")
    return values

def authorities(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "provider_metadata_is_authority", "confidence_is_truth", "route_receipt_is_execution_authority", "route_receipt_is_policy_authority", "production_approval")
    if any(authority.get(field) is not False for field in required):
        raise RouteReceiptError("authority boundary violation")

@dataclass(frozen=True)
class RouteReceiptPolicy:
    policy_id: str
    task_id: str
    session_id: str
    intent_digest: str
    approved_models: tuple[str, ...]
    approved_versions: tuple[str, ...]
    approved_providers: tuple[str, ...]
    max_fallback_depth: int
    generation: int
    issued_at: int
    expires_at: int
    max_route_cost_milli: int
    min_confidence: float
    min_stability: float

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.task_id, "task_id"); text(self.session_id, "session_id"); sha(self.intent_digest, "intent_digest")
        names(self.approved_models, "approved_models", minimum=1); names(self.approved_versions, "approved_versions", minimum=1); names(self.approved_providers, "approved_providers", minimum=1)
        integer(self.max_fallback_depth, "max_fallback_depth", 0, MAX_CHAIN); integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_route_cost_milli, "max_route_cost_milli", 0, 10**9); real(self.min_confidence, "min_confidence", 0.0, 1.0); real(self.min_stability, "min_stability", 0.0, 1.0)
        if self.expires_at - self.issued_at > MAX_TTL: raise RouteReceiptError("policy TTL is outside bounds")

@dataclass(frozen=True)
class TrajectorySummary:
    step_count: int
    mean_confidence: float
    final_confidence: float
    min_confidence: float
    stability: float
    tool_uncertainty: float
    fallback_depth: int

    def __post_init__(self) -> None:
        integer(self.step_count, "step_count", 1, MAX_STEPS); real(self.mean_confidence, "mean_confidence", 0.0, 1.0); real(self.final_confidence, "final_confidence", 0.0, 1.0); real(self.min_confidence, "min_confidence", 0.0, 1.0); real(self.stability, "stability", 0.0, 1.0); real(self.tool_uncertainty, "tool_uncertainty", 0.0, 1.0); integer(self.fallback_depth, "fallback_depth", 0, MAX_CHAIN)
        if self.min_confidence > self.mean_confidence or self.mean_confidence > self.final_confidence and self.step_count == 1: raise RouteReceiptError("trajectory confidence summary is inconsistent")

@dataclass(frozen=True)
class RouteReceiptRequest:
    request_id: str
    task_id: str
    session_id: str
    intent_digest: str
    requested_model: str
    requested_version: str
    effective_model: str
    effective_version: str
    effective_provider: str
    service_tier: str
    fallback_chain: tuple[str, ...]
    tool_use: bool
    trajectory: TrajectorySummary
    route_cost_milli: int
    generation: int
    issued_at: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.task_id, "task_id"); text(self.session_id, "session_id"); sha(self.intent_digest, "intent_digest")
        text(self.requested_model, "requested_model"); text(self.requested_version, "requested_version"); text(self.effective_model, "effective_model"); text(self.effective_version, "effective_version"); text(self.effective_provider, "effective_provider"); text(self.service_tier, "service_tier")
        names(self.fallback_chain, "fallback_chain"); integer(self.route_cost_milli, "route_cost_milli", 0, 10**9); integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        if not isinstance(self.tool_use, bool): raise RouteReceiptError("tool_use is invalid")

class RouteReceiptLedger:
    def __init__(self, policy: RouteReceiptPolicy) -> None:
        self.policy = policy
        self._receipts: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    def admit(self, request: RouteReceiptRequest, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authorities(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if request.request_id in self._receipts or nonce in self._nonces: raise RouteReceiptError("route receipt replay")
        if request.task_id != self.policy.task_id or request.session_id != self.policy.session_id: raise RouteReceiptError("task or session mismatch")
        if request.intent_digest != self.policy.intent_digest: raise RouteReceiptError("intent mismatch")
        if request.generation != current_generation or request.generation != self.policy.generation: raise RouteReceiptError("generation mismatch")
        if now < request.issued_at or now < self.policy.issued_at or now >= self.policy.expires_at: raise RouteReceiptError("route receipt policy is stale or expired")
        if request.requested_model not in self.policy.approved_models or request.effective_model not in self.policy.approved_models: raise RouteReceiptError("model is not approved")
        if request.requested_version not in self.policy.approved_versions or request.effective_version not in self.policy.approved_versions: raise RouteReceiptError("version is not approved")
        if request.effective_provider not in self.policy.approved_providers: raise RouteReceiptError("provider is not approved")
        if len(request.fallback_chain) > self.policy.max_fallback_depth: raise RouteReceiptError("fallback depth exceeded")
        if any(model not in self.policy.approved_models for model in request.fallback_chain): raise RouteReceiptError("fallback model is not approved")
        if request.trajectory.fallback_depth != len(request.fallback_chain): raise RouteReceiptError("fallback depth does not match trajectory")
        if request.trajectory.fallback_depth > self.policy.max_fallback_depth: raise RouteReceiptError("trajectory fallback depth exceeded")
        if request.trajectory.final_confidence < self.policy.min_confidence or request.trajectory.stability < self.policy.min_stability: raise RouteReceiptError("confidence or stability threshold not met")
        if request.route_cost_milli > self.policy.max_route_cost_milli: raise RouteReceiptError("route cost budget exceeded")
        result = {"schema": SCHEMA, "status": "route_receipt_admitted", "request_id": request.request_id, "task_id": request.task_id, "session_id": request.session_id, "intent_digest": request.intent_digest, "requested_model": request.requested_model, "requested_version": request.requested_version, "effective_model": request.effective_model, "effective_version": request.effective_version, "effective_provider": request.effective_provider, "service_tier": request.service_tier, "fallback_chain": request.fallback_chain, "tool_use": request.tool_use, "trajectory": request.trajectory.__dict__, "route_cost_milli": request.route_cost_milli, "route_verified": True, "confidence_calibrated": True, "inference_executed": False, "model_selected": False, "production_approved": False, "authority": dict(authority)}
        result["receipt_digest"] = digest(result); self._receipts[request.request_id] = result; self._nonces.add(nonce)
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "receipts": self._receipts})
