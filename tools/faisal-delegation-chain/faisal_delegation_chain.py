"""Fail-closed delegation-chain capability verification for FAISAL.

This contract verifies caller-supplied delegation evidence. It does not issue
credentials, perform cryptographic attestation, contact identity providers,
execute tools, or convert a receipt into execution or privilege authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.delegation-chain.v1"
MAX_DEPTH = 32
MAX_HOPS = 8192
MAX_CAPABILITIES = 128


class DelegationChainError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise DelegationChainError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise DelegationChainError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise DelegationChainError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise DelegationChainError(f"{name} is outside bounds")
    return value


def caps(value: Any, name: str) -> frozenset[str]:
    if not isinstance(value, (list, tuple, set, frozenset)) or len(value) > MAX_CAPABILITIES:
        raise DelegationChainError(f"{name} is invalid")
    result = frozenset(text(x, name, 256) for x in value)
    if not result:
        raise DelegationChainError(f"{name} is empty")
    return result


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise DelegationChainError("authority boundary missing")
    for field in (
        "model_output_is_authority", "agent_claim_is_authority",
        "credential_metadata_is_authority", "delegation_receipt_is_execution_authority",
        "delegation_receipt_is_policy_authority", "delegation_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise DelegationChainError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ChainPolicy:
    policy_id: str
    policy_version: str
    generation: int
    allowed_audience: str
    allowed_capabilities: frozenset[str]
    max_depth: int = MAX_DEPTH
    max_ttl: int = 86_400
    max_execution_count: int = 1000
    revocation_epoch: int = 0

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        text(self.allowed_audience, "allowed_audience", 256)
        if not self.allowed_capabilities:
            raise DelegationChainError("allowed_capabilities is empty")
        if not self.allowed_capabilities.issubset(set(caps(self.allowed_capabilities, "allowed_capabilities"))):
            raise DelegationChainError("allowed_capabilities invalid")
        integer(self.max_depth, "max_depth", 1, MAX_DEPTH)
        integer(self.max_ttl, "max_ttl", 1, 86_400)
        integer(self.max_execution_count, "max_execution_count", 1, 1_000_000)
        integer(self.revocation_epoch, "revocation_epoch", 0, 2**63 - 1)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "allowed_audience": self.allowed_audience,
            "allowed_capabilities": sorted(self.allowed_capabilities),
            "max_depth": self.max_depth,
            "max_ttl": self.max_ttl,
            "max_execution_count": self.max_execution_count,
            "revocation_epoch": self.revocation_epoch,
        })


@dataclass(frozen=True)
class DelegationHop:
    chain_id: str
    hop_id: str
    issuer_id: str
    subject_id: str
    parent_hop_digest: str | None
    capability_scope: frozenset[str]
    audience: str
    task_id: str
    route_digest: str
    generation: int
    issued_at: int
    expires_at: int
    execution_limit: int
    revocation_epoch: int = 0

    def __post_init__(self) -> None:
        text(self.chain_id, "chain_id", 128)
        text(self.hop_id, "hop_id", 128)
        text(self.issuer_id, "issuer_id", 256)
        text(self.subject_id, "subject_id", 256)
        if self.parent_hop_digest is not None:
            sha(self.parent_hop_digest, "parent_hop_digest")
        caps(self.capability_scope, "capability_scope")
        text(self.audience, "audience", 256)
        text(self.task_id, "task_id", 128)
        sha(self.route_digest, "route_digest")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.issued_at:
            raise DelegationChainError("hop expiry must follow issue time")
        integer(self.execution_limit, "execution_limit", 1, 1_000_000)
        integer(self.revocation_epoch, "revocation_epoch", 0, 2**63 - 1)

    @property
    def hop_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "chain_id": self.chain_id,
            "hop_id": self.hop_id,
            "issuer_id": self.issuer_id,
            "subject_id": self.subject_id,
            "parent_hop_digest": self.parent_hop_digest,
            "capability_scope": sorted(self.capability_scope),
            "audience": self.audience,
            "task_id": self.task_id,
            "route_digest": self.route_digest,
            "generation": self.generation,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "execution_limit": self.execution_limit,
            "revocation_epoch": self.revocation_epoch,
        })


@dataclass(frozen=True)
class UseRequest:
    use_id: str
    chain_id: str
    leaf_hop_id: str
    audience: str
    task_id: str
    route_digest: str
    requested_capabilities: frozenset[str]
    generation: int
    execution_count: int
    requested_at: int
    expires_at: int
    nonce: str

    def __post_init__(self) -> None:
        text(self.use_id, "use_id", 128)
        text(self.chain_id, "chain_id", 128)
        text(self.leaf_hop_id, "leaf_hop_id", 128)
        text(self.audience, "audience", 256)
        text(self.task_id, "task_id", 128)
        sha(self.route_digest, "route_digest")
        caps(self.requested_capabilities, "requested_capabilities")
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.execution_count, "execution_count", 1, 1_000_000)
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise DelegationChainError("use expiry must follow request")
        text(self.nonce, "nonce", 256)

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "use_id": self.use_id,
            "chain_id": self.chain_id,
            "leaf_hop_id": self.leaf_hop_id,
            "audience": self.audience,
            "task_id": self.task_id,
            "route_digest": self.route_digest,
            "requested_capabilities": sorted(self.requested_capabilities),
            "generation": self.generation,
            "execution_count": self.execution_count,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
        })


class DelegationChainLedger:
    def __init__(self, policy: ChainPolicy) -> None:
        self.policy = policy
        self._hops: dict[str, DelegationHop] = {}
        self._chains: dict[str, list[str]] = {}
        self._revoked: dict[str, int] = {}
        self._uses: set[str] = set()
        self._nonces: set[str] = set()

    def register_hop(self, hop: DelegationHop) -> str:
        if hop.hop_id in self._hops:
            raise DelegationChainError("hop replay")
        if len(self._hops) >= MAX_HOPS:
            raise DelegationChainError("hop bound exceeded")
        if hop.generation != self.policy.generation:
            raise DelegationChainError("hop generation mismatch")
        if hop.audience != self.policy.allowed_audience:
            raise DelegationChainError("hop audience denied")
        if not hop.capability_scope.issubset(self.policy.allowed_capabilities):
            raise DelegationChainError("hop capability exceeds policy")
        if hop.expires_at - hop.issued_at > self.policy.max_ttl:
            raise DelegationChainError("hop ttl exceeds policy")
        if hop.execution_limit > self.policy.max_execution_count:
            raise DelegationChainError("hop execution limit exceeds policy")
        if hop.parent_hop_digest is None:
            if hop.chain_id in self._chains:
                raise DelegationChainError("duplicate chain root")
        else:
            parent = next((x for x in self._hops.values() if x.hop_digest == hop.parent_hop_digest), None)
            if parent is None:
                raise DelegationChainError("parent hop not found")
            if parent.chain_id != hop.chain_id:
                raise DelegationChainError("chain splice")
            if parent.subject_id != hop.issuer_id:
                raise DelegationChainError("issuer does not match parent subject")
            if not hop.capability_scope.issubset(parent.capability_scope):
                raise DelegationChainError("capability attenuation violated")
            for field in ("audience", "task_id", "route_digest", "generation"):
                if getattr(parent, field) != getattr(hop, field):
                    raise DelegationChainError(f"hop {field} mismatch")
            if hop.expires_at > parent.expires_at:
                raise DelegationChainError("expiry amplification")
        chain = self._chains.setdefault(hop.chain_id, [])
        if len(chain) >= self.policy.max_depth:
            raise DelegationChainError("delegation depth exceeded")
        chain.append(hop.hop_id)
        self._hops[hop.hop_id] = hop
        return hop.hop_digest

    def revoke(self, hop_id: str, *, epoch: int) -> None:
        if hop_id not in self._hops:
            raise DelegationChainError("hop not found")
        integer(epoch, "epoch", 1, 2**63 - 1)
        if epoch <= self._revoked.get(hop_id, 0):
            raise DelegationChainError("revocation epoch is not monotonic")
        self._revoked[hop_id] = epoch

    def _chain_to_root(self, leaf: DelegationHop) -> list[DelegationHop]:
        result: list[DelegationHop] = []
        current = leaf
        seen: set[str] = set()
        while True:
            if current.hop_id in seen:
                raise DelegationChainError("delegation cycle")
            seen.add(current.hop_id)
            result.append(current)
            if current.parent_hop_digest is None:
                return list(reversed(result))
            parent = next((x for x in self._hops.values() if x.hop_digest == current.parent_hop_digest), None)
            if parent is None:
                raise DelegationChainError("broken chain")
            current = parent

    def admit_use(self, request: UseRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.use_id in self._uses or request.nonce in self._nonces:
            raise DelegationChainError("use or nonce replay")
        if request.generation != self.policy.generation:
            raise DelegationChainError("request generation mismatch")
        if request.audience != self.policy.allowed_audience:
            raise DelegationChainError("request audience denied")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise DelegationChainError("request ttl exceeds policy")
        if now < request.requested_at or now >= request.expires_at:
            raise DelegationChainError("request expired")
        leaf = self._hops.get(request.leaf_hop_id)
        if leaf is None or leaf.chain_id != request.chain_id:
            raise DelegationChainError("leaf not found or chain mismatch")
        chain = self._chain_to_root(leaf)
        if len(chain) > self.policy.max_depth:
            raise DelegationChainError("chain depth exceeded")
        effective = set(chain[0].capability_scope)
        for hop in chain:
            if hop.revocation_epoch < self._revoked.get(hop.hop_id, 0) or self._revoked.get(hop.hop_id, 0) > self.policy.revocation_epoch:
                raise DelegationChainError("revoked hop")
            if hop.generation != request.generation or hop.audience != request.audience or hop.task_id != request.task_id or hop.route_digest != request.route_digest:
                raise DelegationChainError("chain binding mismatch")
            if now < hop.issued_at or now >= hop.expires_at:
                raise DelegationChainError("hop expired")
            if request.expires_at > hop.expires_at:
                raise DelegationChainError("request exceeds hop expiry")
            effective.intersection_update(hop.capability_scope)
        if not set(request.requested_capabilities).issubset(effective):
            raise DelegationChainError("requested capability exceeds effective scope")
        if request.execution_count > min(h.execution_limit for h in chain):
            raise DelegationChainError("execution count exceeds chain limit")
        self._uses.add(request.use_id)
        self._nonces.add(request.nonce)
        result = {
            "schema": SCHEMA,
            "use_id": request.use_id,
            "request_digest": request.request_digest,
            "chain_id": request.chain_id,
            "leaf_hop_id": leaf.hop_id,
            "chain_depth": len(chain),
            "hop_digests": [hop.hop_digest for hop in chain],
            "effective_capabilities": sorted(effective),
            "requested_capabilities": sorted(request.requested_capabilities),
            "audience": request.audience,
            "task_id": request.task_id,
            "route_digest": request.route_digest,
            "generation": request.generation,
            "execution_count": request.execution_count,
            "admitted": True,
            "credentials_issued": False,
            "cryptographic_attestation_verified": False,
            "tools_executed": False,
            "external_services_contacted": False,
            "now": now,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def ledger_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_digest": self.policy.policy_digest,
            "hops": sorted(hop.hop_digest for hop in self._hops.values()),
            "revoked": sorted(self._revoked.items()),
            "uses": sorted(self._uses),
            "nonces": sorted(self._nonces),
        })


__all__ = ["SCHEMA", "DelegationChainError", "ChainPolicy", "DelegationHop", "UseRequest", "DelegationChainLedger", "digest"]
