from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.kv-cache-admission.v1"
MAX_TEXT = 256
MAX_HINTS = 16
MAX_TTL = 86400

class KVCacheAdmissionError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise KVCacheAdmissionError(f"{name} is invalid")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise KVCacheAdmissionError(f"{name} is outside bounds")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise KVCacheAdmissionError(f"{name} is not a digest")
    return value

def boundary(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "provider_metadata_is_authority", "cache_hint_is_execution_authority", "cache_hint_is_policy_authority", "production_approval")
    if any(authority.get(key) is not False for key in required):
        raise KVCacheAdmissionError("authority boundary violation")

@dataclass(frozen=True)
class CachePolicy:
    policy_id: str
    generation: int
    max_ttl: int
    max_priority: int
    max_output_tokens: int
    max_pinned_sessions: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.max_ttl, "max_ttl", 1, MAX_TTL); integer(self.max_priority, "max_priority", 0, 100)
        integer(self.max_output_tokens, "max_output_tokens", 1, 2**31 - 1); integer(self.max_pinned_sessions, "max_pinned_sessions", 1, 1000000)

@dataclass(frozen=True)
class AgentHints:
    priority: int
    estimated_output_tokens: int
    speculative_prefill: bool
    cache_ttl: int
    pin: bool

    def __post_init__(self) -> None:
        integer(self.priority, "priority", 0, 100); integer(self.estimated_output_tokens, "estimated_output_tokens", 1, 2**31 - 1)
        if not isinstance(self.speculative_prefill, bool) or not isinstance(self.pin, bool): raise KVCacheAdmissionError("hint flags are invalid")
        integer(self.cache_ttl, "cache_ttl", 1, MAX_TTL)

@dataclass(frozen=True)
class CacheAdmissionRequest:
    request_id: str
    session_id: str
    route_digest: str
    surface_digest: str
    generation: int
    issued_at: int
    hints: AgentHints
    prior_session_digest: str

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.session_id, "session_id"); sha(self.route_digest, "route_digest"); sha(self.surface_digest, "surface_digest")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        if self.prior_session_digest != "genesis": sha(self.prior_session_digest, "prior_session_digest")

class KVCacheAdmissionLedger:
    def __init__(self, policy: CachePolicy) -> None:
        self.policy = policy
        self._admitted: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()
        self._sessions: dict[str, str] = {}
        self._session_surfaces: dict[str, tuple[str, str]] = {}

    def admit(self, request: CacheAdmissionRequest, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        boundary(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if request.generation != current_generation or request.generation != self.policy.generation: raise KVCacheAdmissionError("generation mismatch")
        if request.request_id in self._admitted or nonce in self._nonces: raise KVCacheAdmissionError("admission replay")
        prior = self._sessions.get(request.session_id, "genesis")
        if request.prior_session_digest != prior: raise KVCacheAdmissionError("session chain mismatch")
        bound_surface = self._session_surfaces.get(request.session_id)
        if bound_surface is not None and bound_surface != (request.route_digest, request.surface_digest):
            raise KVCacheAdmissionError("session route or surface mismatch")
        if request.hints.cache_ttl > self.policy.max_ttl: raise KVCacheAdmissionError("cache TTL exceeds policy")
        if request.hints.priority > self.policy.max_priority: raise KVCacheAdmissionError("priority exceeds policy")
        if request.hints.estimated_output_tokens > self.policy.max_output_tokens: raise KVCacheAdmissionError("estimated output exceeds policy")
        if now < request.issued_at or now - request.issued_at > self.policy.max_ttl: raise KVCacheAdmissionError("request is stale or future-dated")
        if request.hints.pin and len({sid for sid, item in self._admitted.items() if item["recommendation"]["pin"]}) >= self.policy.max_pinned_sessions: raise KVCacheAdmissionError("pinned-session capacity exhausted")
        recommendation = {"cache_key": digest({"session_id": request.session_id, "surface_digest": request.surface_digest, "route_digest": request.route_digest}), "session_id": request.session_id, "route_digest": request.route_digest, "surface_digest": request.surface_digest, "priority": request.hints.priority, "estimated_output_tokens": request.hints.estimated_output_tokens, "speculative_prefill": request.hints.speculative_prefill, "pin": request.hints.pin, "cache_expires_at": now + request.hints.cache_ttl, "execution_performed": False, "memory_pinned": False, "production_approved": False, "authority": dict(authority)}
        result = {"schema": SCHEMA, "status": "admitted", "request_id": request.request_id, "generation": request.generation, "recommendation": recommendation}
        result["record_digest"] = digest(result)
        self._admitted[request.request_id] = result; self._nonces.add(nonce); self._sessions[request.session_id] = result["record_digest"]
        self._session_surfaces.setdefault(request.session_id, (request.route_digest, request.surface_digest))
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "admissions": self._admitted})
