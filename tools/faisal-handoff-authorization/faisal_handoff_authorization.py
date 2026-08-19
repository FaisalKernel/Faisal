from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.handoff-authorization.v1"
MAX_SCOPE = 64
MAX_MEMORY_DIGESTS = 64
MAX_TTL = 86_400
MAX_HANDOFFS = 4096

class HandoffAuthorizationError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise HandoffAuthorizationError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise HandoffAuthorizationError(f"{name} is not a digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise HandoffAuthorizationError(f"{name} is not a digest") from exc
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise HandoffAuthorizationError(f"{name} is outside bounds")
    return value

def names(values: tuple[str, ...], name: str, minimum: int = 0) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) < minimum or len(values) > MAX_SCOPE:
        raise HandoffAuthorizationError(f"{name} is outside bounds")
    result = tuple(text(value, f"{name} item", 128) for value in values)
    if tuple(sorted(set(result))) != result:
        raise HandoffAuthorizationError(f"{name} must be sorted and unique")
    return result

def digests(values: tuple[str, ...], name: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > MAX_MEMORY_DIGESTS:
        raise HandoffAuthorizationError(f"{name} is outside bounds")
    result = tuple(sha(value, f"{name} item") for value in values)
    if tuple(sorted(set(result))) != result:
        raise HandoffAuthorizationError(f"{name} must be sorted and unique")
    return result

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = (
        "model_output_is_authority",
        "agent_claim_is_authority",
        "memory_is_authority",
        "authorization_receipt_is_execution_authority",
        "authorization_receipt_is_policy_authority",
        "production_approval",
    )
    if any(authority.get(field) is not False for field in required):
        raise HandoffAuthorizationError("authority boundary violation")

@dataclass(frozen=True)
class HandoffAuthorizationPolicy:
    policy_id: str
    task_id: str
    original_request_digest: str
    source_policy_digest: str
    allowed_scope: tuple[str, ...]
    confirmation_scope: tuple[str, ...]
    denied_scope: tuple[str, ...]
    allowed_memory_digests: tuple[str, ...]
    generation: int
    issued_at: int
    expires_at: int
    max_memory_disclosures: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.task_id, "task_id"); sha(self.original_request_digest, "original_request_digest"); sha(self.source_policy_digest, "source_policy_digest")
        names(self.allowed_scope, "allowed_scope", minimum=1); names(self.confirmation_scope, "confirmation_scope"); names(self.denied_scope, "denied_scope"); digests(self.allowed_memory_digests, "allowed_memory_digests")
        if not set(self.confirmation_scope).issubset(set(self.allowed_scope)) or not set(self.denied_scope).issubset(set(self.allowed_scope)):
            raise HandoffAuthorizationError("policy scope classification exceeds allowed scope")
        if set(self.confirmation_scope) & set(self.denied_scope):
            raise HandoffAuthorizationError("confirmation and denied scope overlap")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        integer(self.max_memory_disclosures, "max_memory_disclosures", 0, MAX_MEMORY_DIGESTS)
        if self.expires_at - self.issued_at > MAX_TTL:
            raise HandoffAuthorizationError("policy TTL is outside bounds")

@dataclass(frozen=True)
class HandoffAuthorizationRequest:
    request_id: str
    handoff_id: str
    issuer_agent_id: str
    delegatee_agent_id: str
    task_id: str
    original_request_digest: str
    source_policy_digest: str
    parent_scope: tuple[str, ...]
    requested_scope: tuple[str, ...]
    disclosed_memory_digests: tuple[str, ...]
    generation: int
    issued_at: int
    expires_at: int
    trace_position: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.handoff_id, "handoff_id"); text(self.issuer_agent_id, "issuer_agent_id"); text(self.delegatee_agent_id, "delegatee_agent_id"); text(self.task_id, "task_id")
        sha(self.original_request_digest, "original_request_digest"); sha(self.source_policy_digest, "source_policy_digest"); names(self.parent_scope, "parent_scope", minimum=1); names(self.requested_scope, "requested_scope", minimum=1); digests(self.disclosed_memory_digests, "disclosed_memory_digests")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1); integer(self.trace_position, "trace_position", 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL:
            raise HandoffAuthorizationError("handoff TTL is outside bounds")

    @property
    def request_digest(self) -> str:
        return digest({"schema": SCHEMA, "request_id": self.request_id, "handoff_id": self.handoff_id, "issuer_agent_id": self.issuer_agent_id, "delegatee_agent_id": self.delegatee_agent_id, "task_id": self.task_id, "original_request_digest": self.original_request_digest, "source_policy_digest": self.source_policy_digest, "parent_scope": self.parent_scope, "requested_scope": self.requested_scope, "disclosed_memory_digests": self.disclosed_memory_digests, "generation": self.generation, "issued_at": self.issued_at, "expires_at": self.expires_at, "trace_position": self.trace_position})

class HandoffAuthorizationLedger:
    def __init__(self, *, max_handoffs: int = MAX_HANDOFFS) -> None:
        integer(max_handoffs, "max_handoffs", 1, MAX_HANDOFFS)
        self.max_handoffs = max_handoffs
        self._receipts: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    def admit(self, request: HandoffAuthorizationRequest, *, policy: HandoffAuthorizationPolicy, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        request_digest = request.request_digest
        if request_digest in self._receipts or nonce in self._nonces:
            raise HandoffAuthorizationError("handoff authorization replay")
        if len(self._receipts) >= self.max_handoffs:
            raise HandoffAuthorizationError("handoff authorization capacity exhausted")
        if request.task_id != policy.task_id or request.original_request_digest != policy.original_request_digest or request.source_policy_digest != policy.source_policy_digest:
            raise HandoffAuthorizationError("original task or authorization provenance mismatch")
        if request.generation != current_generation or request.generation != policy.generation:
            raise HandoffAuthorizationError("generation mismatch")
        if now < request.issued_at or now < policy.issued_at or now >= request.expires_at or now >= policy.expires_at:
            raise HandoffAuthorizationError("handoff authorization is stale or expired")
        if request.expires_at > policy.expires_at:
            raise HandoffAuthorizationError("handoff expiry exceeds source policy")
        parent_scope = set(request.parent_scope); requested_scope = set(request.requested_scope); allowed_scope = set(policy.allowed_scope)
        if not requested_scope.issubset(parent_scope):
            raise HandoffAuthorizationError("delegated scope widened")
        if not parent_scope.issubset(allowed_scope):
            raise HandoffAuthorizationError("parent scope exceeds original policy")
        if not requested_scope.issubset(allowed_scope):
            raise HandoffAuthorizationError("requested scope exceeds original policy")
        disclosed = set(request.disclosed_memory_digests)
        if not disclosed.issubset(set(policy.allowed_memory_digests)):
            raise HandoffAuthorizationError("memory disclosure exceeds policy")
        if len(disclosed) > policy.max_memory_disclosures:
            raise HandoffAuthorizationError("memory disclosure budget exceeded")
        if requested_scope & set(policy.denied_scope):
            verdict = "deny"; reason = "requested_scope_denied"
        elif requested_scope & set(policy.confirmation_scope):
            verdict = "require_confirmation"; reason = "requested_scope_requires_confirmation"
        else:
            verdict = "allow"; reason = "scope_matched_current_policy"
        result = {"schema": SCHEMA, "status": "authorization_verdict", "verdict": verdict, "reason": reason, "request_digest": request_digest, "handoff_id": request.handoff_id, "issuer_agent_id": request.issuer_agent_id, "delegatee_agent_id": request.delegatee_agent_id, "task_id": request.task_id, "original_request_digest": request.original_request_digest, "source_policy_digest": request.source_policy_digest, "parent_scope": request.parent_scope, "requested_scope": request.requested_scope, "disclosed_memory_digests": request.disclosed_memory_digests, "trace_position": request.trace_position, "scope_attenuated": requested_scope < parent_scope, "memory_transferred": False, "capabilities_delegated": False, "tools_executed": False, "authority": dict(authority), "production_approved": False}
        result["receipt_digest"] = digest(result); self._receipts[request_digest] = result; self._nonces.add(nonce)
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "receipts": self._receipts})
