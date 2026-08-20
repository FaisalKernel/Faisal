from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.agent-capability-attestation.v1"
MAX_TEXT = 256
MAX_CAPABILITIES = 32
MAX_TTL = 3600
MAX_DELEGATION_DEPTH = 8
AGENT_KINDS = frozenset(("autonomous", "orchestrator", "ephemeral"))


class AgentCapabilityAttestationError(ValueError):
    pass


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def text(value: str, name: str, limit: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise AgentCapabilityAttestationError(f"{name} is invalid")
    return value


def sha(value: str, name: str) -> str:
    value = text(value, name)
    if not value.startswith("sha256:") or len(value) != 71:
        raise AgentCapabilityAttestationError(f"{name} is not a digest")
    return value


def integer(value: int, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < low or value > high:
        raise AgentCapabilityAttestationError(f"{name} is outside bounds")
    return value


def capabilities(values: frozenset[str], name: str) -> frozenset[str]:
    if not isinstance(values, frozenset) or not values or len(values) > MAX_CAPABILITIES:
        raise AgentCapabilityAttestationError(f"{name} is invalid")
    if any(not isinstance(value, str) or not value or len(value) > MAX_TEXT for value in values):
        raise AgentCapabilityAttestationError(f"{name} is invalid")
    return values


def authority_boundary(authority: Mapping[str, Any]) -> None:
    required = (
        "model_output_is_authority",
        "agent_identity_is_execution_authority",
        "attestation_is_execution_authority",
        "attestation_is_policy_authority",
        "workload_selectors_are_hardware_proof",
        "production_approval",
    )
    if any(authority.get(key) is not False for key in required):
        raise AgentCapabilityAttestationError("authority boundary violation")


@dataclass(frozen=True)
class AgentCapabilityPolicy:
    policy_id: str
    trust_domain: str
    agent_id: str
    agent_kind: str
    parent_agent_id: str
    parent_authority_digest: str
    workload_selector_digest: str
    purpose_digest: str
    allowed_capabilities: frozenset[str]
    max_delegation_depth: int
    generation: int
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id")
        text(self.trust_domain, "trust_domain")
        text(self.agent_id, "agent_id")
        text(self.parent_agent_id, "parent_agent_id")
        if self.agent_id == self.parent_agent_id:
            raise AgentCapabilityAttestationError("agent cannot parent itself")
        if self.agent_kind not in AGENT_KINDS:
            raise AgentCapabilityAttestationError("agent_kind is invalid")
        sha(self.parent_authority_digest, "parent_authority_digest")
        sha(self.workload_selector_digest, "workload_selector_digest")
        sha(self.purpose_digest, "purpose_digest")
        capabilities(self.allowed_capabilities, "allowed_capabilities")
        integer(self.max_delegation_depth, "max_delegation_depth", 0, MAX_DELEGATION_DEPTH)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_TTL:
            raise AgentCapabilityAttestationError("policy TTL is outside bounds")


@dataclass(frozen=True)
class AgentCapabilityRequest:
    request_id: str
    agent_id: str
    agent_kind: str
    parent_agent_id: str
    parent_authority_digest: str
    workload_selector_digest: str
    purpose_digest: str
    requested_capabilities: frozenset[str]
    delegation_depth: int
    generation: int
    issued_at: int

    def __post_init__(self) -> None:
        text(self.request_id, "request_id")
        text(self.agent_id, "agent_id")
        text(self.parent_agent_id, "parent_agent_id")
        if self.agent_id == self.parent_agent_id:
            raise AgentCapabilityAttestationError("agent cannot parent itself")
        if self.agent_kind not in AGENT_KINDS:
            raise AgentCapabilityAttestationError("agent_kind is invalid")
        sha(self.parent_authority_digest, "parent_authority_digest")
        sha(self.workload_selector_digest, "workload_selector_digest")
        sha(self.purpose_digest, "purpose_digest")
        capabilities(self.requested_capabilities, "requested_capabilities")
        integer(self.delegation_depth, "delegation_depth", 0, MAX_DELEGATION_DEPTH)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)


class AgentCapabilityAttestationLedger:
    def __init__(self, policy: AgentCapabilityPolicy) -> None:
        self.policy = policy
        self._receipts: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()

    def attest(
        self,
        request: AgentCapabilityRequest,
        *,
        current_generation: int,
        nonce: str,
        authority: Mapping[str, Any],
        now: int,
    ) -> dict[str, Any]:
        authority_boundary(authority)
        integer(current_generation, "current_generation", 1, 2**63 - 1)
        integer(now, "now", 0, 2**63 - 1)
        text(nonce, "nonce")
        if request.request_id in self._receipts or nonce in self._nonces:
            raise AgentCapabilityAttestationError("agent attestation replay")
        if request.agent_id != self.policy.agent_id or request.agent_kind != self.policy.agent_kind:
            raise AgentCapabilityAttestationError("agent identity mismatch")
        if request.parent_agent_id != self.policy.parent_agent_id:
            raise AgentCapabilityAttestationError("parent agent mismatch")
        if request.parent_authority_digest != self.policy.parent_authority_digest:
            raise AgentCapabilityAttestationError("parent authority mismatch")
        if request.workload_selector_digest != self.policy.workload_selector_digest:
            raise AgentCapabilityAttestationError("workload selector mismatch")
        if request.purpose_digest != self.policy.purpose_digest:
            raise AgentCapabilityAttestationError("purpose mismatch")
        if not request.requested_capabilities <= self.policy.allowed_capabilities:
            raise AgentCapabilityAttestationError("capability escalation")
        if request.delegation_depth > self.policy.max_delegation_depth:
            raise AgentCapabilityAttestationError("delegation depth exceeds policy")
        if request.generation != current_generation or request.generation != self.policy.generation:
            raise AgentCapabilityAttestationError("generation mismatch")
        if now < request.issued_at or now < self.policy.issued_at or now >= self.policy.expires_at:
            raise AgentCapabilityAttestationError("agent policy is stale or expired")
        receipt = {
            "schema": SCHEMA,
            "status": "attested",
            "request_id": request.request_id,
            "agent_id": request.agent_id,
            "agent_kind": request.agent_kind,
            "parent_agent_id": request.parent_agent_id,
            "identity_verified": True,
            "parentage_verified": True,
            "selector_verified": True,
            "purpose_verified": True,
            "capability_attenuation_verified": True,
            "lifecycle_verified": True,
            "credential_issued": False,
            "execution_performed": False,
            "production_approved": False,
            "authority": dict(authority),
        }
        receipt["receipt_digest"] = digest(receipt)
        self._receipts[request.request_id] = receipt
        self._nonces.add(nonce)
        return json.loads(json.dumps(receipt))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "receipts": self._receipts})
