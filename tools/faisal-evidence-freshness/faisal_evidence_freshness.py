"""Fail-closed admission for freshness of qualification evidence.

This module verifies caller-supplied qualification leases. It never runs
qualification, inspects live hardware or services, or grants production
authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping, Tuple

SCHEMA = "org.faisal.evidence-freshness.v1"
MAX_COMPONENTS = 512
MAX_TTL = 86_400 * 365


class EvidenceFreshnessError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def text(value: Any, name: str, limit: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise EvidenceFreshnessError(f"{name} is invalid")
    return value


def sha(value: Any, name: str) -> str:
    value = text(value, name, 80)
    if len(value) != 71 or not value.startswith("sha256:"):
        raise EvidenceFreshnessError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise EvidenceFreshnessError(f"{name} is not a SHA-256 digest") from exc
    return value


def integer(value: Any, name: str, low: int, high: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
        raise EvidenceFreshnessError(f"{name} is outside bounds")
    return value


def authority_boundary(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise EvidenceFreshnessError("authority boundary missing")
    for field in (
        "evidence_is_truth", "evidence_is_execution_authority",
        "evidence_is_policy_authority", "evidence_is_production_authority",
        "qualification_receipt_is_attestation",
    ):
        if value.get(field) is not False:
            raise EvidenceFreshnessError(f"authority boundary {field} must be false")


def normalized_names(values: Tuple[str, ...], name: str) -> Tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > MAX_COMPONENTS:
        raise EvidenceFreshnessError(f"{name} is outside bounds")
    result = tuple(text(v, f"{name} item", 256) for v in values)
    if tuple(sorted(set(result))) != result:
        raise EvidenceFreshnessError(f"{name} must be sorted and unique")
    return result


@dataclass(frozen=True)
class FreshnessPolicy:
    policy_id: str
    policy_version: str
    generation: int
    platform_abi: int
    max_evidence_age: int = 86_400
    max_lease_ttl: int = 86_400
    critical_components: Tuple[str, ...] = ("environment", "hardware", "model", "policy", "route", "tool")

    def __post_init__(self) -> None:
        text(self.policy_id, "policy_id", 128)
        text(self.policy_version, "policy_version", 64)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.platform_abi, "platform_abi", 1, 2**31 - 1)
        integer(self.max_evidence_age, "max_evidence_age", 1, MAX_TTL)
        integer(self.max_lease_ttl, "max_lease_ttl", 1, MAX_TTL)
        normalized_names(self.critical_components, "critical_components")

    @property
    def policy_digest(self) -> str:
        return digest({
            "schema": SCHEMA,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "generation": self.generation,
            "platform_abi": self.platform_abi,
            "max_evidence_age": self.max_evidence_age,
            "max_lease_ttl": self.max_lease_ttl,
            "critical_components": self.critical_components,
        })


@dataclass(frozen=True)
class QualificationSurface:
    surface_id: str
    model_digest: str
    tool_digest: str
    route_digest: str
    policy_digest: str
    hardware_digest: str
    environment_digest: str
    benchmark_digest: str
    abi: int
    generation: int

    def __post_init__(self) -> None:
        text(self.surface_id, "surface_id", 128)
        for name, value in (
            ("model_digest", self.model_digest), ("tool_digest", self.tool_digest),
            ("route_digest", self.route_digest), ("policy_digest", self.policy_digest),
            ("hardware_digest", self.hardware_digest), ("environment_digest", self.environment_digest),
            ("benchmark_digest", self.benchmark_digest),
        ):
            sha(value, name)
        integer(self.abi, "abi", 1, 2**31 - 1)
        integer(self.generation, "generation", 1, 2**63 - 1)

    @property
    def surface_digest(self) -> str:
        return digest({
            "schema": SCHEMA, "surface_id": self.surface_id,
            "model_digest": self.model_digest, "tool_digest": self.tool_digest,
            "route_digest": self.route_digest, "policy_digest": self.policy_digest,
            "hardware_digest": self.hardware_digest, "environment_digest": self.environment_digest,
            "benchmark_digest": self.benchmark_digest, "abi": self.abi, "generation": self.generation,
        })


@dataclass(frozen=True)
class QualificationLease:
    lease_id: str
    qualification_id: str
    surface_digest: str
    evidence_digest: str
    provenance_digest: str
    policy_digest: str
    generation: int
    issued_at: int
    evidence_recorded_at: int
    expires_at: int
    drift_components: Tuple[str, ...]
    critical_drift: bool
    quarantined: bool = False
    revoked: bool = False

    def __post_init__(self) -> None:
        text(self.lease_id, "lease_id", 128)
        text(self.qualification_id, "qualification_id", 128)
        for name, value in (("surface_digest", self.surface_digest), ("evidence_digest", self.evidence_digest), ("provenance_digest", self.provenance_digest), ("policy_digest", self.policy_digest)):
            sha(value, name)
        integer(self.generation, "generation", 1, 2**63 - 1)
        integer(self.issued_at, "issued_at", 0, 2**63 - 1)
        integer(self.evidence_recorded_at, "evidence_recorded_at", 0, self.issued_at)
        integer(self.expires_at, "expires_at", self.issued_at + 1, 2**63 - 1)
        if self.drift_components:
            normalized_names(self.drift_components, "drift_components")
        if not isinstance(self.critical_drift, bool) or not isinstance(self.quarantined, bool) or not isinstance(self.revoked, bool):
            raise EvidenceFreshnessError("lease flags are invalid")

    @property
    def lease_digest(self) -> str:
        return digest({
            "schema": SCHEMA, "lease_id": self.lease_id, "qualification_id": self.qualification_id,
            "surface_digest": self.surface_digest, "evidence_digest": self.evidence_digest,
            "provenance_digest": self.provenance_digest, "policy_digest": self.policy_digest,
            "generation": self.generation, "issued_at": self.issued_at,
            "evidence_recorded_at": self.evidence_recorded_at, "expires_at": self.expires_at,
            "drift_components": self.drift_components, "critical_drift": self.critical_drift,
            "quarantined": self.quarantined, "revoked": self.revoked,
        })


class EvidenceFreshnessLedger:
    def __init__(self, policy: FreshnessPolicy) -> None:
        self.policy = policy
        self._leases: dict[str, QualificationLease] = {}
        self._nonces: set[str] = set()

    def admit(self, surface: QualificationSurface, lease: QualificationLease, *, now: int, authority: Mapping[str, Any], nonce: str) -> dict[str, Any]:
        integer(now, "now", 0, 2**63 - 1)
        text(nonce, "nonce", 256)
        authority_boundary(authority)
        if nonce in self._nonces:
            raise EvidenceFreshnessError("nonce replay")
        if lease.lease_id in self._leases:
            raise EvidenceFreshnessError("lease replay")
        if lease.surface_digest != surface.surface_digest:
            raise EvidenceFreshnessError("qualification surface mismatch")
        if lease.policy_digest != self.policy.policy_digest:
            raise EvidenceFreshnessError("policy digest mismatch")
        if surface.abi != self.policy.platform_abi or lease.generation != self.policy.generation or surface.generation != self.policy.generation:
            raise EvidenceFreshnessError("ABI or generation mismatch")
        if lease.expires_at - lease.issued_at > self.policy.max_lease_ttl or now < lease.issued_at or now >= lease.expires_at:
            raise EvidenceFreshnessError("lease expired or TTL exceeds policy")
        if now - lease.evidence_recorded_at > self.policy.max_evidence_age:
            raise EvidenceFreshnessError("evidence is stale")
        if lease.drift_components:
            critical = set(lease.drift_components) & set(self.policy.critical_components)
            if lease.critical_drift or critical:
                raise EvidenceFreshnessError("critical drift requires requalification")
        if lease.quarantined:
            raise EvidenceFreshnessError("lease quarantined")
        if lease.revoked:
            raise EvidenceFreshnessError("lease revoked")
        self._leases[lease.lease_id] = lease
        self._nonces.add(nonce)
        result = {
            "schema": SCHEMA,
            "lease_id": lease.lease_id,
            "lease_digest": lease.lease_digest,
            "surface_digest": surface.surface_digest,
            "freshness_verified": True,
            "drift_components": lease.drift_components,
            "critical_drift": False,
            "qualification_executed": False,
            "attestation_performed": False,
            "production_approved": False,
            "authority": dict(authority),
        }
        result["receipt_digest"] = digest(result)
        return result

    def revoke(self, lease_id: str) -> dict[str, Any]:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise EvidenceFreshnessError("unknown lease")
        revoked = QualificationLease(lease.lease_id, lease.qualification_id, lease.surface_digest, lease.evidence_digest, lease.provenance_digest, lease.policy_digest, lease.generation, lease.issued_at, lease.evidence_recorded_at, lease.expires_at, lease.drift_components, lease.critical_drift, lease.quarantined, True)
        self._leases[lease_id] = revoked
        return {"schema": SCHEMA, "lease_id": lease_id, "revoked": True, "production_approved": False, "revocation_digest": digest({"lease_id": lease_id, "lease_digest": revoked.lease_digest})}

    def quarantine(self, lease_id: str) -> dict[str, Any]:
        lease = self._leases.get(lease_id)
        if lease is None:
            raise EvidenceFreshnessError("unknown lease")
        quarantined = QualificationLease(lease.lease_id, lease.qualification_id, lease.surface_digest, lease.evidence_digest, lease.provenance_digest, lease.policy_digest, lease.generation, lease.issued_at, lease.evidence_recorded_at, lease.expires_at, lease.drift_components, lease.critical_drift, True, lease.revoked)
        self._leases[lease_id] = quarantined
        return {"schema": SCHEMA, "lease_id": lease_id, "quarantined": True, "production_approved": False, "quarantine_digest": digest({"lease_id": lease_id, "lease_digest": quarantined.lease_digest})}

    def ledger_digest(self) -> str:
        return digest({"schema": SCHEMA, "policy_digest": self.policy.policy_digest, "leases": sorted(l.lease_digest for l in self._leases.values()), "nonces": sorted(self._nonces)})


__all__ = ["SCHEMA", "EvidenceFreshnessError", "FreshnessPolicy", "QualificationSurface", "QualificationLease", "EvidenceFreshnessLedger", "digest"]
