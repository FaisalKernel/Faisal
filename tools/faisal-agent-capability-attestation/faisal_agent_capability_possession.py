from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from faisal_agent_capability_attestation import (
    AgentCapabilityAttestationError,
    MAX_CAPABILITIES,
    MAX_TEXT,
    authority_boundary,
    digest,
    integer,
    sha,
    text,
)


SCHEMA = "org.faisal.agent-capability-possession.v1"
MAX_PROOF_TTL = 300
METHODS = frozenset(("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"))


def method(value: str, name: str) -> str:
    value = text(value, name)
    if value not in METHODS:
        raise AgentCapabilityAttestationError(f"{name} is invalid")
    return value


def optional_digest(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    return sha(value, name)


@dataclass(frozen=True)
class AgentCapabilityPossessionPolicy:
    policy_id: str
    attestation_digest: str
    agent_id: str
    key_thumbprint_digest: str
    allowed_capabilities: frozenset[str]
    generation: int
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id")
        sha(self.attestation_digest, "attestation_digest")
        text(self.agent_id, "agent_id")
        sha(self.key_thumbprint_digest, "key_thumbprint_digest")
        if not isinstance(self.allowed_capabilities, frozenset) or not self.allowed_capabilities or len(self.allowed_capabilities) > MAX_CAPABILITIES:
            raise AgentCapabilityAttestationError("allowed_capabilities is invalid")
        if any(not isinstance(value, str) or not value or len(value) > MAX_TEXT for value in self.allowed_capabilities):
            raise AgentCapabilityAttestationError("allowed_capabilities is invalid")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_PROOF_TTL:
            raise AgentCapabilityAttestationError("policy TTL is outside bounds")


@dataclass(frozen=True)
class AgentCapabilityPossessionRequest:
    proof_id: str
    attestation_digest: str
    agent_id: str
    key_thumbprint_digest: str
    capability: str
    request_method: str
    target_digest: str
    nonce_digest: str | None
    generation: int
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        text(self.proof_id, "proof_id")
        sha(self.attestation_digest, "attestation_digest")
        text(self.agent_id, "agent_id")
        sha(self.key_thumbprint_digest, "key_thumbprint_digest")
        text(self.capability, "capability")
        method(self.request_method, "request_method")
        sha(self.target_digest, "target_digest")
        optional_digest(self.nonce_digest, "nonce_digest")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_PROOF_TTL:
            raise AgentCapabilityAttestationError("proof TTL is outside bounds")


class AgentCapabilityPossessionLedger:
    """Records bounded local possession-binding receipts; it never verifies signatures or executes requests."""

    def __init__(self, policy: AgentCapabilityPossessionPolicy) -> None:
        self.policy = policy
        self._receipts: dict[str, dict[str, Any]] = {}

    def present(
        self,
        request: AgentCapabilityPossessionRequest,
        *,
        expected_method: str,
        expected_target_digest: str,
        expected_nonce_digest: str | None,
        nonce_required: bool,
        current_generation: int,
        authority: Mapping[str, Any],
        now: int,
    ) -> dict[str, Any]:
        authority_boundary(authority)
        expected_method = method(expected_method, "expected_method")
        sha(expected_target_digest, "expected_target_digest")
        expected_nonce_digest = optional_digest(expected_nonce_digest, "expected_nonce_digest")
        if not isinstance(nonce_required, bool):
            raise AgentCapabilityAttestationError("nonce_required is invalid")
        integer(current_generation, "current_generation", 1, 2**63 - 1)
        integer(now, "now", 0, 2**63 - 1)
        if request.proof_id in self._receipts:
            raise AgentCapabilityAttestationError("possession proof replay")
        if request.attestation_digest != self.policy.attestation_digest:
            raise AgentCapabilityAttestationError("attestation binding mismatch")
        if request.agent_id != self.policy.agent_id:
            raise AgentCapabilityAttestationError("agent identity mismatch")
        if request.key_thumbprint_digest != self.policy.key_thumbprint_digest:
            raise AgentCapabilityAttestationError("key thumbprint mismatch")
        if request.capability not in self.policy.allowed_capabilities:
            raise AgentCapabilityAttestationError("capability mismatch")
        if request.request_method != expected_method:
            raise AgentCapabilityAttestationError("request method mismatch")
        if request.target_digest != expected_target_digest:
            raise AgentCapabilityAttestationError("request target mismatch")
        if request.generation != current_generation or request.generation != self.policy.generation:
            raise AgentCapabilityAttestationError("generation mismatch")
        if now < request.issued_at or now < self.policy.issued_at or now >= request.expires_at or now >= self.policy.expires_at:
            raise AgentCapabilityAttestationError("possession proof is stale or expired")
        if nonce_required and expected_nonce_digest is None:
            raise AgentCapabilityAttestationError("required expected nonce is missing")
        if expected_nonce_digest is None:
            if request.nonce_digest is not None:
                raise AgentCapabilityAttestationError("unexpected nonce binding")
        elif request.nonce_digest != expected_nonce_digest:
            raise AgentCapabilityAttestationError("nonce mismatch")
        receipt = {
            "schema": SCHEMA,
            "status": "bound",
            "proof_id": request.proof_id,
            "attestation_digest": request.attestation_digest,
            "agent_id": request.agent_id,
            "capability": request.capability,
            "request_method": request.request_method,
            "target_digest": request.target_digest,
            "generation": request.generation,
            "attestation_binding_verified": True,
            "agent_identity_verified": True,
            "key_thumbprint_binding_verified": True,
            "capability_binding_verified": True,
            "request_binding_verified": True,
            "nonce_binding_verified": expected_nonce_digest is not None,
            "lifecycle_verified": True,
            "replay_protected": True,
            "cryptographic_proof_verified": False,
            "credential_issued": False,
            "execution_performed": False,
            "production_approved": False,
            "authority": dict(authority),
        }
        receipt["receipt_digest"] = digest(receipt)
        self._receipts[request.proof_id] = receipt
        return json.loads(json.dumps(receipt))

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "receipts": self._receipts})
