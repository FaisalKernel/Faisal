#!/usr/bin/env python3
"""Bounded attenuation and revocation contract for FAISAL agent delegation.

This is a deterministic control-plane contract. It does not mint signed
credentials, contact an authorization server, or treat model output as
authority. Production proof-of-possession and key custody remain external.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.delegation.v1"
MAX_DEPTH = 32
MAX_TTL_SECONDS = 7 * 24 * 60 * 60
MAX_CALLS = 1_000_000


class DelegationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise DelegationError(f"{name} is invalid")
    return value


def _scope_subset(child: "DelegationScope", parent: "DelegationScope") -> bool:
    return (
        child.tools <= parent.tools
        and child.resources <= parent.resources
        and child.argument_constraints <= parent.argument_constraints
        and child.max_calls <= parent.max_calls
    )


@dataclass(frozen=True)
class DelegationScope:
    tools: frozenset[str]
    resources: frozenset[str]
    argument_constraints: frozenset[tuple[str, str, str]] = frozenset()
    max_calls: int = 1

    def __post_init__(self) -> None:
        if not self.tools or not self.resources:
            raise DelegationError("scope tools and resources must be non-empty")
        if any(not isinstance(item, str) or not item for item in self.tools | self.resources):
            raise DelegationError("scope member is invalid")
        if any(not isinstance(item, tuple) or len(item) != 3 or any(not isinstance(part, str) or not part for part in item) for item in self.argument_constraints):
            raise DelegationError("argument constraint is invalid")
        if not isinstance(self.max_calls, int) or not 1 <= self.max_calls <= MAX_CALLS:
            raise DelegationError("max_calls is outside bounds")

    def canonical(self) -> dict[str, Any]:
        return {
            "tools": sorted(self.tools),
            "resources": sorted(self.resources),
            "argument_constraints": [list(item) for item in sorted(self.argument_constraints)],
            "max_calls": self.max_calls,
        }

    def digest(self) -> str:
        return digest(self.canonical())


@dataclass(frozen=True)
class DelegationRecord:
    delegation_id: str
    issuer: str
    delegatee: str
    parent_digest: str | None
    depth: int
    max_depth: int
    issued_at: int
    expires_at: int
    scope: DelegationScope
    holder_proof_digest: str
    nonce: str

    def __post_init__(self) -> None:
        _text(self.delegation_id, "delegation_id", 128)
        _text(self.issuer, "issuer", 256)
        _text(self.delegatee, "delegatee", 256)
        _text(self.holder_proof_digest, "holder_proof_digest", 80)
        _text(self.nonce, "nonce", 128)
        if self.parent_digest is not None:
            _text(self.parent_digest, "parent_digest", 80)
        if not 0 <= self.depth <= MAX_DEPTH or not 0 <= self.max_depth <= MAX_DEPTH or self.depth > self.max_depth:
            raise DelegationError("depth is outside bounds")
        if not isinstance(self.issued_at, int) or not isinstance(self.expires_at, int) or self.expires_at <= self.issued_at:
            raise DelegationError("delegation time window is invalid")
        if self.expires_at - self.issued_at > MAX_TTL_SECONDS:
            raise DelegationError("delegation TTL exceeds bound")

    def canonical(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "delegation_id": self.delegation_id,
            "issuer": self.issuer,
            "delegatee": self.delegatee,
            "parent_digest": self.parent_digest,
            "depth": self.depth,
            "max_depth": self.max_depth,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope": self.scope.canonical(),
            "holder_proof_digest": self.holder_proof_digest,
            "nonce": self.nonce,
        }

    def record_digest(self) -> str:
        return digest(self.canonical())


@dataclass(frozen=True)
class Invocation:
    tool: str
    resource: str
    argument_constraint: tuple[str, str, str] | None
    call_nonce: str
    used_calls: int = 0

    def __post_init__(self) -> None:
        _text(self.tool, "invocation tool")
        _text(self.resource, "invocation resource")
        _text(self.call_nonce, "call_nonce")
        if self.argument_constraint is not None and (len(self.argument_constraint) != 3 or any(not isinstance(x, str) or not x for x in self.argument_constraint)):
            raise DelegationError("invocation argument constraint is invalid")
        if not isinstance(self.used_calls, int) or self.used_calls < 0:
            raise DelegationError("used_calls is invalid")


def issue_root(*, delegation_id: str, issuer: str, delegatee: str, issued_at: int, expires_at: int, scope: DelegationScope, max_depth: int, holder_proof_digest: str, nonce: str) -> DelegationRecord:
    return DelegationRecord(delegation_id, issuer, delegatee, None, 0, max_depth, issued_at, expires_at, scope, holder_proof_digest, nonce)


def derive_child(parent: DelegationRecord, *, delegation_id: str, delegatee: str, issued_at: int, expires_at: int, scope: DelegationScope, holder_proof_digest: str, nonce: str) -> DelegationRecord:
    if parent.depth + 1 > parent.max_depth:
        raise DelegationError("delegation depth exhausted")
    if issued_at < parent.issued_at or expires_at > parent.expires_at or expires_at <= issued_at:
        raise DelegationError("child time window is not attenuated")
    if not _scope_subset(scope, parent.scope):
        raise DelegationError("child scope amplifies parent authority")
    return DelegationRecord(delegation_id, parent.delegatee, delegatee, parent.record_digest(), parent.depth + 1, parent.max_depth, issued_at, expires_at, scope, holder_proof_digest, nonce)


def verify_chain(chain: Iterable[DelegationRecord], *, now: int, revoked_ids: frozenset[str] = frozenset(), revoked_lineages: frozenset[str] = frozenset()) -> DelegationRecord:
    records = tuple(chain)
    if not records:
        raise DelegationError("delegation chain is empty")
    root = records[0]
    if root.parent_digest is not None or root.depth != 0:
        raise DelegationError("root delegation is malformed")
    parent = root
    if root.delegation_id in revoked_ids or root.record_digest() in revoked_lineages:
        raise DelegationError("delegation is revoked")
    for record in records:
        if record.delegation_id in revoked_ids or record.record_digest() in revoked_lineages:
            raise DelegationError("delegation lineage is revoked")
        if not record.issued_at <= now < record.expires_at:
            raise DelegationError("delegation is outside validity window")
    for record in records[1:]:
        if record.parent_digest != parent.record_digest() or record.depth != parent.depth + 1:
            raise DelegationError("delegation parent linkage or depth is invalid")
        if record.issuer != parent.delegatee:
            raise DelegationError("delegation issuer does not match parent delegatee")
        if record.expires_at > parent.expires_at or record.issued_at < parent.issued_at:
            raise DelegationError("delegation TTL is not monotonic")
        if not _scope_subset(record.scope, parent.scope):
            raise DelegationError("delegation scope is not attenuated")
        parent = record
    return records[-1]


def authorize_invocation(chain: Iterable[DelegationRecord], invocation: Invocation, *, now: int, revoked_ids: frozenset[str] = frozenset(), revoked_lineages: frozenset[str] = frozenset()) -> dict[str, Any]:
    leaf = verify_chain(chain, now=now, revoked_ids=revoked_ids, revoked_lineages=revoked_lineages)
    if invocation.tool not in leaf.scope.tools or invocation.resource not in leaf.scope.resources:
        raise DelegationError("invocation is outside attenuated scope")
    if invocation.used_calls >= leaf.scope.max_calls:
        raise DelegationError("delegation call budget exhausted")
    if invocation.argument_constraint is not None and invocation.argument_constraint not in leaf.scope.argument_constraints:
        raise DelegationError("invocation argument constraint is outside scope")
    return {
        "schema": SCHEMA,
        "delegation_id": leaf.delegation_id,
        "delegation_digest": leaf.record_digest(),
        "tool": invocation.tool,
        "resource": invocation.resource,
        "call_nonce": invocation.call_nonce,
        "authorized": True,
        "executed": False,
        "model_output_is_authority": False,
        "production_approval": False,
    }
