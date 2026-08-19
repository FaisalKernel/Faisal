from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.tool-attestation.v1"
MAX_TEXT = 256
MAX_SCOPES = 32
MAX_ARGS = 64
MAX_VERSION_PARTS = 4

class ToolAttestationError(ValueError):
    pass

def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ToolAttestationError(f"{name} is invalid")
    return value

def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise ToolAttestationError(f"{name} is not a digest")
    return value

def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise ToolAttestationError(f"{name} is outside bounds")
    return value

def scopes(values: frozenset[str], name: str) -> frozenset[str]:
    if not isinstance(values, frozenset) or len(values) > MAX_SCOPES or any(not isinstance(v, str) or not v or len(v) > MAX_TEXT for v in values):
        raise ToolAttestationError(f"{name} is invalid")
    return values

def version(value: tuple[int, ...], name: str) -> tuple[int, ...]:
    if not isinstance(value, tuple) or not value or len(value) > MAX_VERSION_PARTS or any(not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > 2**31 - 1 for v in value):
        raise ToolAttestationError(f"{name} is invalid")
    return value

def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = ("model_output_is_authority", "tool_metadata_is_authority", "tool_result_is_authority", "attestation_is_execution_authority", "attestation_is_policy_authority", "production_approval")
    if any(authority.get(key) is not False for key in required):
        raise ToolAttestationError("authority boundary violation")

@dataclass(frozen=True)
class ToolPolicy:
    policy_id: str
    server_id: str
    tool_name: str
    approved_definition_digest: str
    approved_dependency_digest: str
    minimum_version: tuple[int, ...]
    required_scopes: frozenset[str]
    destination_sensitivity: int
    max_argument_sensitivity: int
    generation: int
    issued_at: int
    expires_at: int
    confirmation_required: bool

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id"); text(self.server_id, "server_id"); text(self.tool_name, "tool_name")
        sha(self.approved_definition_digest, "approved_definition_digest"); sha(self.approved_dependency_digest, "approved_dependency_digest")
        version(self.minimum_version, "minimum_version"); scopes(self.required_scopes, "required_scopes")
        integer(self.destination_sensitivity, "destination_sensitivity", 0, 3); integer(self.max_argument_sensitivity, "max_argument_sensitivity", 0, 3)
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1); integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > 86400: raise ToolAttestationError("policy TTL is outside bounds")
        if self.max_argument_sensitivity > self.destination_sensitivity: raise ToolAttestationError("argument sensitivity exceeds destination")
        if not isinstance(self.confirmation_required, bool): raise ToolAttestationError("confirmation_required is invalid")

@dataclass(frozen=True)
class ToolCallRequest:
    request_id: str
    server_id: str
    tool_name: str
    definition_digest: str
    dependency_digest: str
    tool_version: tuple[int, ...]
    granted_scopes: frozenset[str]
    argument_labels: tuple[tuple[str, int], ...]
    confirmed: bool
    generation: int
    issued_at: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id"); text(self.server_id, "server_id"); text(self.tool_name, "tool_name")
        sha(self.definition_digest, "definition_digest"); sha(self.dependency_digest, "dependency_digest"); version(self.tool_version, "tool_version"); scopes(self.granted_scopes, "granted_scopes")
        integer(self.generation, "generation", 1, 2**63 - 1); integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        if not isinstance(self.confirmed, bool): raise ToolAttestationError("confirmed is invalid")
        if not isinstance(self.argument_labels, tuple) or len(self.argument_labels) > MAX_ARGS: raise ToolAttestationError("argument_labels are outside bounds")
        names = []
        for name, label in self.argument_labels:
            names.append(text(name, "argument name")); integer(label, "argument sensitivity", 0, 3)
        if tuple(sorted(set(names))) != tuple(names): raise ToolAttestationError("argument labels must be sorted and unique")

class ToolAttestationLedger:
    def __init__(self, policy: ToolPolicy) -> None:
        self.policy = policy
        self._admitted: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    def admit(self, request: ToolCallRequest, *, current_generation: int, nonce: str, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority); integer(current_generation, "current_generation", 1, 2**63 - 1); integer(now, "now", 0, 2**63 - 1); text(nonce, "nonce")
        if request.request_id in self._admitted or nonce in self._nonces: raise ToolAttestationError("tool admission replay")
        if request.server_id != self.policy.server_id or request.tool_name != self.policy.tool_name: raise ToolAttestationError("tool identity mismatch")
        if request.generation != current_generation or request.generation != self.policy.generation: raise ToolAttestationError("generation mismatch")
        if request.definition_digest != self.policy.approved_definition_digest: raise ToolAttestationError("tool definition drift")
        if request.dependency_digest != self.policy.approved_dependency_digest: raise ToolAttestationError("dependency drift")
        if request.tool_version < self.policy.minimum_version: raise ToolAttestationError("tool version regression")
        if not self.policy.required_scopes <= request.granted_scopes: raise ToolAttestationError("capability scope missing")
        if any(label > self.policy.max_argument_sensitivity or label > self.policy.destination_sensitivity for _, label in request.argument_labels): raise ToolAttestationError("argument data-flow label exceeds destination")
        if now < request.issued_at or now < self.policy.issued_at or now >= self.policy.expires_at: raise ToolAttestationError("tool policy is stale or expired")
        if self.policy.confirmation_required and not request.confirmed: raise ToolAttestationError("explicit confirmation required")
        result = {"schema": SCHEMA, "status": "admitted", "request_id": request.request_id, "server_id": request.server_id, "tool_name": request.tool_name, "definition_verified": True, "dependency_verified": True, "version_verified": True, "scope_verified": True, "data_flow_verified": True, "confirmation_verified": (request.confirmed or not self.policy.confirmation_required), "execution_performed": False, "tool_invoked": False, "production_approved": False, "authority": dict(authority)}
        result["receipt_digest"] = digest(result)
        self._admitted[request.request_id] = result; self._nonces.add(nonce)
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "admissions": self._admitted})
