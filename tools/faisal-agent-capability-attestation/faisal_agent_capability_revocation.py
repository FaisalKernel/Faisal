from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from faisal_agent_capability_attestation import AgentCapabilityAttestationError, MAX_CAPABILITIES, MAX_TEXT, authority_boundary, digest, integer, sha, text


SCHEMA = "org.faisal.agent-capability-revocation.v1"
MAX_SNAPSHOT_TTL = 300


def digest_set(values: frozenset[str], name: str) -> frozenset[str]:
    if not isinstance(values, frozenset) or len(values) > MAX_CAPABILITIES * 32:
        raise AgentCapabilityAttestationError(f"{name} is invalid")
    for value in values:
        sha(value, name)
    return values


@dataclass(frozen=True)
class AgentCapabilityRevocationPolicy:
    policy_id: str
    agent_id: str
    allowed_capabilities: frozenset[str]
    minimum_epoch: int

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id")
        text(self.agent_id, "agent_id")
        if not isinstance(self.allowed_capabilities, frozenset) or not self.allowed_capabilities or len(self.allowed_capabilities) > MAX_CAPABILITIES:
            raise AgentCapabilityAttestationError("allowed_capabilities is invalid")
        if any(not isinstance(value, str) or not value or len(value) > MAX_TEXT for value in self.allowed_capabilities):
            raise AgentCapabilityAttestationError("allowed_capabilities is invalid")
        integer(self.minimum_epoch, "minimum_epoch", 1, 2**63 - 1)


@dataclass(frozen=True)
class AgentCapabilityRevocationSnapshot:
    snapshot_id: str
    epoch: int
    issued_at: int
    expires_at: int
    complete: bool
    revoked_receipt_digests: frozenset[str]

    def __post_init__(self) -> None:
        text(self.snapshot_id, "snapshot_id")
        integer(self.epoch, "epoch", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.expires_at - self.issued_at > MAX_SNAPSHOT_TTL:
            raise AgentCapabilityAttestationError("snapshot TTL is outside bounds")
        if self.complete is not True:
            raise AgentCapabilityAttestationError("snapshot must be complete")
        digest_set(self.revoked_receipt_digests, "revoked_receipt_digests")

    def snapshot_digest(self) -> str:
        return digest({"schema": SCHEMA, "snapshot_id": self.snapshot_id, "epoch": self.epoch, "issued_at": self.issued_at, "expires_at": self.expires_at, "complete": self.complete, "revoked_receipt_digests": sorted(self.revoked_receipt_digests)})


class AgentCapabilityRevocationLedger:
    """Applies caller-supplied complete local snapshots; it never contacts or authenticates a revocation source."""

    def __init__(self, policy: AgentCapabilityRevocationPolicy) -> None:
        self.policy = policy
        self._snapshot: AgentCapabilityRevocationSnapshot | None = None
        self._decisions: dict[str, dict[str, Any]] = {}

    def install(self, snapshot: AgentCapabilityRevocationSnapshot, *, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority)
        integer(now, "now", 0, 2**63 - 1)
        if now < snapshot.issued_at or now >= snapshot.expires_at:
            raise AgentCapabilityAttestationError("revocation snapshot is stale or expired")
        if snapshot.epoch < self.policy.minimum_epoch:
            raise AgentCapabilityAttestationError("revocation snapshot epoch below policy")
        if self._snapshot is not None and snapshot.epoch <= self._snapshot.epoch:
            raise AgentCapabilityAttestationError("revocation snapshot epoch regressed or replayed")
        self._snapshot = snapshot
        receipt = {"schema": SCHEMA, "status": "installed", "snapshot_id": snapshot.snapshot_id, "snapshot_epoch": snapshot.epoch, "snapshot_digest": snapshot.snapshot_digest(), "complete_snapshot_verified": True, "revocation_source_authenticated": False, "credentials_revoked": False, "execution_performed": False, "production_approved": False, "authority": dict(authority)}
        receipt["receipt_digest"] = digest(receipt)
        return json.loads(json.dumps(receipt))

    def evaluate(self, receipt_digest: str, *, agent_id: str, capability: str, required_epoch: int, authority: Mapping[str, Any], now: int) -> dict[str, Any]:
        authority_boundary(authority)
        sha(receipt_digest, "receipt_digest")
        text(agent_id, "agent_id")
        text(capability, "capability")
        integer(required_epoch, "required_epoch", 1, 2**63 - 1)
        integer(now, "now", 0, 2**63 - 1)
        snapshot = self._snapshot
        if snapshot is None:
            raise AgentCapabilityAttestationError("revocation snapshot unavailable")
        if snapshot.epoch < required_epoch:
            raise AgentCapabilityAttestationError("revocation snapshot is below required epoch")
        if now < snapshot.issued_at or now >= snapshot.expires_at:
            raise AgentCapabilityAttestationError("installed revocation snapshot is stale or expired")
        if agent_id != self.policy.agent_id:
            raise AgentCapabilityAttestationError("agent identity mismatch")
        if capability not in self.policy.allowed_capabilities:
            raise AgentCapabilityAttestationError("capability mismatch")
        if receipt_digest in snapshot.revoked_receipt_digests:
            raise AgentCapabilityAttestationError("capability receipt is revoked")
        decision_key = digest({"receipt_digest": receipt_digest, "epoch": snapshot.epoch, "agent_id": agent_id, "capability": capability})
        result = {"schema": SCHEMA, "status": "active", "receipt_digest": receipt_digest, "snapshot_epoch": snapshot.epoch, "snapshot_digest": snapshot.snapshot_digest(), "agent_id": agent_id, "capability": capability, "complete_snapshot_verified": True, "epoch_verified": True, "freshness_verified": True, "revocation_checked": True, "revocation_source_authenticated": False, "credentials_revoked": False, "execution_performed": False, "production_approved": False, "authority": dict(authority)}
        result["decision_digest"] = digest(result)
        self._decisions[decision_key] = result
        return json.loads(json.dumps(result))

    def ledger_digest(self) -> str:
        snapshot = self._snapshot.snapshot_digest() if self._snapshot else None
        return digest({"schema": SCHEMA, "policy_id": self.policy.policy_id, "snapshot": snapshot, "decisions": self._decisions})
