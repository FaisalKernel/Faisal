"""Fail-closed capability-manifest freshness verification for FAISAL.

This contract detects capability-envelope drift between admission and use. It
verifies caller-supplied digests and lifecycle evidence; it does not perform
cryptographic attestation, issue credentials, inspect live processes, invoke
models/tools, or turn a receipt into execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.capability-freshness.v1"
MAX_MANIFESTS = 8192
MAX_TOOLS = 512


class CapabilityFreshnessError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise CapabilityFreshnessError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise CapabilityFreshnessError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise CapabilityFreshnessError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise CapabilityFreshnessError(f"{name} is outside bounds")
    return value


def items(value: Any, name: str, limit: int = 512) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)) or not value or len(value) > limit:
        raise CapabilityFreshnessError(f"{name} is invalid")
    result = tuple(sorted({text(x, name, 256) for x in value}))
    if not result:
        raise CapabilityFreshnessError(f"{name} is empty")
    return result


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise CapabilityFreshnessError("authority boundary missing")
    for field in (
        "model_output_is_authority", "tool_metadata_is_authority",
        "manifest_claim_is_attestation", "freshness_receipt_is_execution_authority",
        "freshness_receipt_is_policy_authority", "freshness_receipt_is_production_authority",
    ):
        if value.get(field) is not False:
            raise CapabilityFreshnessError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class FreshnessPolicy:
    policy_id: str
    policy_version: str
    generation: int
    allowed_models: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    allowed_routes: tuple[str, ...]
    audience: str
    max_ttl: int = 86_400
    require_observed_manifest: bool = True

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        items(self.allowed_models, "allowed_models")
        items(self.allowed_tools, "allowed_tools", MAX_TOOLS)
        items(self.allowed_routes, "allowed_routes")
        text(self.audience, "audience", 256)
        integer(self.max_ttl, "max_ttl", 1, 86_400)

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "allowed_models": list(self.allowed_models),
            "allowed_tools": list(self.allowed_tools),
            "allowed_routes": list(self.allowed_routes),
            "audience": self.audience,
            "max_ttl": self.max_ttl,
            "require_observed_manifest": self.require_observed_manifest,
        })


@dataclass(frozen=True)
class CapabilityManifest:
    manifest_id: str
    agent_id: str
    model_id: str
    model_version: str
    tools: tuple[str, ...]
    route_id: str
    audience: str
    task_id: str
    generation: int
    key_epoch: int
    issued_at: int
    expires_at: int
    revoked: bool = False

    def __post_init__(self) -> None:
        text(self.manifest_id, "manifest_id", 128)
        text(self.agent_id, "agent_id", 256)
        text(self.model_id, "model_id", 256)
        text(self.model_version, "model_version", 128)
        items(self.tools, "tools", MAX_TOOLS)
        text(self.route_id, "route_id", 256)
        text(self.audience, "audience", 256)
        text(self.task_id, "task_id", 128)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.key_epoch, "key_epoch", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.issued_at:
            raise CapabilityFreshnessError("manifest expiry must follow issue time")

    @property
    def manifest_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "manifest_id": self.manifest_id,
            "agent_id": self.agent_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "tools": list(self.tools),
            "route_id": self.route_id,
            "audience": self.audience,
            "task_id": self.task_id,
            "generation": self.generation,
            "key_epoch": self.key_epoch,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
        })


@dataclass(frozen=True)
class FreshnessRequest:
    request_id: str
    agent_id: str
    task_id: str
    audience: str
    route_id: str
    admitted_manifest_id: str
    admitted_manifest_digest: str
    observed_manifest_id: str
    observed_manifest_digest: str
    delegation_hop_digest: str
    admitted_generation: int
    observed_generation: int
    admitted_key_epoch: int
    observed_key_epoch: int
    requested_at: int
    expires_at: int
    nonce: str

    def __post_init__(self) -> None:
        text(self.request_id, "request_id", 128)
        text(self.agent_id, "agent_id", 256)
        text(self.task_id, "task_id", 128)
        text(self.audience, "audience", 256)
        text(self.route_id, "route_id", 256)
        text(self.admitted_manifest_id, "admitted_manifest_id", 128)
        sha(self.admitted_manifest_digest, "admitted_manifest_digest")
        text(self.observed_manifest_id, "observed_manifest_id", 128)
        sha(self.observed_manifest_digest, "observed_manifest_digest")
        sha(self.delegation_hop_digest, "delegation_hop_digest")
        integer(self.admitted_generation, "admitted_generation", 1, 2**63 - 1)
        integer(self.observed_generation, "observed_generation", 1, 2**63 - 1)
        integer(self.admitted_key_epoch, "admitted_key_epoch", 1, 2**63 - 1)
        integer(self.observed_key_epoch, "observed_key_epoch", 1, 2**63 - 1)
        integer(self.requested_at, "requested_at", 0, 2**63 - 1)
        integer(self.expires_at, "expires_at", 0, 2**63 - 1)
        if self.expires_at <= self.requested_at:
            raise CapabilityFreshnessError("request expiry must follow request time")
        text(self.nonce, "nonce", 256)

    @property
    def request_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "audience": self.audience,
            "route_id": self.route_id,
            "admitted_manifest_id": self.admitted_manifest_id,
            "admitted_manifest_digest": self.admitted_manifest_digest,
            "observed_manifest_id": self.observed_manifest_id,
            "observed_manifest_digest": self.observed_manifest_digest,
            "delegation_hop_digest": self.delegation_hop_digest,
            "admitted_generation": self.admitted_generation,
            "observed_generation": self.observed_generation,
            "admitted_key_epoch": self.admitted_key_epoch,
            "observed_key_epoch": self.observed_key_epoch,
            "requested_at": self.requested_at,
            "expires_at": self.expires_at,
        })


class CapabilityFreshnessLedger:
    def __init__(self, policy: FreshnessPolicy) -> None:
        self.policy = policy
        self._manifests: dict[str, CapabilityManifest] = {}
        self._latest_generation: dict[str, int] = {}
        self._revoked_epochs: dict[str, int] = {}
        self._uses: set[str] = set()
        self._nonces: set[str] = set()

    def register_manifest(self, manifest: CapabilityManifest) -> str:
        if manifest.manifest_id in self._manifests:
            raise CapabilityFreshnessError("manifest replay")
        if len(self._manifests) >= MAX_MANIFESTS:
            raise CapabilityFreshnessError("manifest bound exceeded")
        if manifest.audience != self.policy.audience:
            raise CapabilityFreshnessError("manifest audience denied")
        if manifest.model_id not in self.policy.allowed_models:
            raise CapabilityFreshnessError("manifest model denied")
        if not set(manifest.tools).issubset(set(self.policy.allowed_tools)):
            raise CapabilityFreshnessError("manifest tool set denied")
        if manifest.route_id not in self.policy.allowed_routes:
            raise CapabilityFreshnessError("manifest route denied")
        prior = self._latest_generation.get(manifest.agent_id, 0)
        if manifest.generation < prior:
            raise CapabilityFreshnessError("manifest generation rolled back")
        self._latest_generation[manifest.agent_id] = manifest.generation
        self._manifests[manifest.manifest_id] = manifest
        return manifest.manifest_digest

    def revoke(self, agent_id: str, *, key_epoch: int) -> None:
        text(agent_id, "agent_id", 256)
        integer(key_epoch, "key_epoch", 1, 2**63 - 1)
        if key_epoch <= self._revoked_epochs.get(agent_id, 0):
            raise CapabilityFreshnessError("revocation epoch is not monotonic")
        self._revoked_epochs[agent_id] = key_epoch

    def admit(self, request: FreshnessRequest, *, now: int, authority: Mapping[str, Any]) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        authority_boundary(authority)
        if request.request_id in self._uses or request.nonce in self._nonces:
            raise CapabilityFreshnessError("use or nonce replay")
        if request.audience != self.policy.audience:
            raise CapabilityFreshnessError("request audience denied")
        if request.admitted_generation != self.policy.generation or request.observed_generation != self.policy.generation:
            raise CapabilityFreshnessError("policy generation mismatch")
        if request.expires_at - request.requested_at > self.policy.max_ttl:
            raise CapabilityFreshnessError("request ttl exceeds policy")
        if now < request.requested_at or now >= request.expires_at:
            raise CapabilityFreshnessError("request expired")
        admitted = self._manifests.get(request.admitted_manifest_id)
        observed = self._manifests.get(request.observed_manifest_id)
        if admitted is None or observed is None:
            raise CapabilityFreshnessError("manifest not found")
        if request.admitted_manifest_digest != admitted.manifest_digest or request.observed_manifest_digest != observed.manifest_digest:
            raise CapabilityFreshnessError("manifest digest mismatch")
        if admitted.agent_id != request.agent_id or observed.agent_id != request.agent_id:
            raise CapabilityFreshnessError("agent binding mismatch")
        if admitted.task_id != request.task_id or observed.task_id != request.task_id:
            raise CapabilityFreshnessError("task binding mismatch")
        if admitted.audience != request.audience or observed.audience != request.audience:
            raise CapabilityFreshnessError("audience binding mismatch")
        if admitted.route_id != request.route_id or observed.route_id != request.route_id:
            raise CapabilityFreshnessError("route binding mismatch")
        if admitted.model_id != observed.model_id or admitted.model_version != observed.model_version:
            raise CapabilityFreshnessError("model capability drift")
        if admitted.tools != observed.tools:
            raise CapabilityFreshnessError("tool capability drift")
        if admitted.route_id != observed.route_id:
            raise CapabilityFreshnessError("route capability drift")
        if request.observed_generation != request.admitted_generation:
            raise CapabilityFreshnessError("manifest generation drift")
        if request.observed_key_epoch != request.admitted_key_epoch:
            raise CapabilityFreshnessError("key epoch drift")
        if observed.revoked or observed.key_epoch < self._revoked_epochs.get(observed.agent_id, 0):
            raise CapabilityFreshnessError("observed manifest revoked")
        if now < admitted.issued_at or now >= admitted.expires_at or now < observed.issued_at or now >= observed.expires_at:
            raise CapabilityFreshnessError("manifest expired")
        if request.expires_at > min(admitted.expires_at, observed.expires_at):
            raise CapabilityFreshnessError("request exceeds manifest expiry")
        self._uses.add(request.request_id)
        self._nonces.add(request.nonce)
        result = {
            "schema": SCHEMA,
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "agent_id": request.agent_id,
            "task_id": request.task_id,
            "audience": request.audience,
            "route_id": request.route_id,
            "admitted_manifest_digest": admitted.manifest_digest,
            "observed_manifest_digest": observed.manifest_digest,
            "delegation_hop_digest": request.delegation_hop_digest,
            "generation": request.observed_generation,
            "key_epoch": request.observed_key_epoch,
            "capability_drift": False,
            "fresh": True,
            "cryptographic_attestation_verified": False,
            "credentials_issued": False,
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
            "manifests": sorted(m.manifest_digest for m in self._manifests.values()),
            "latest_generation": sorted(self._latest_generation.items()),
            "revoked_epochs": sorted(self._revoked_epochs.items()),
            "uses": sorted(self._uses),
            "nonces": sorted(self._nonces),
        })


__all__ = ["SCHEMA", "CapabilityFreshnessError", "FreshnessPolicy", "CapabilityManifest", "FreshnessRequest", "CapabilityFreshnessLedger", "digest"]
