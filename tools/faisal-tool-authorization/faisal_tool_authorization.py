"""Fail-closed tool authorization and invocation admission for FAISAL.

This contract is deliberately provider-neutral. It validates caller-supplied
resource indicators, exact tool descriptor digests, scopes, confirmation
receipts, generation/expiry/use fences, and invocation argument digests. It
never executes a tool, handles OAuth credentials, or treats model output,
tool descriptions, or an authorization receipt as ambient authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.tool-authorization.v1"
GRANT_SCHEMA = "org.faisal.tool-grant.v1"
MAX_SCOPES = 128
MAX_USES = 1024
RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ToolAuthorizationError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ToolAuthorizationError(f"{name} is invalid")
    return value


def _sha(value: Any, name: str) -> str:
    value = _text(value, name, 80)
    if not value.startswith("sha256:") or len(value) != 71:
        raise ToolAuthorizationError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise ToolAuthorizationError(f"{name} is not a SHA-256 digest") from exc
    return value


def _int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ToolAuthorizationError(f"{name} is outside bounds")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ToolAuthorizationError(f"{name} must be boolean")
    return value


def _authority(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ToolAuthorizationError("authority boundary missing")
    for field in ("model_output_is_authority", "tool_description_is_authority", "tool_result_is_authority", "grant_is_production_authority"):
        if value.get(field) is not False:
            raise ToolAuthorizationError(f"authority boundary {field} must be false")


def _risk(value: Any, name: str) -> str:
    value = _text(value, name, 16)
    if value not in RISK_LEVELS:
        raise ToolAuthorizationError(f"unsupported {name}")
    return value


def _scopes(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_SCOPES or len(set(value)) != len(value):
        raise ToolAuthorizationError(f"{name} is invalid")
    normalized = tuple(sorted(_text(scope, f"{name}.scope", 128) for scope in value))
    return normalized


@dataclass(frozen=True)
class ToolDescriptor:
    server_id: str
    tool_name: str
    resource_uri: str
    descriptor_digest: str
    declared_scopes: tuple[str, ...]
    risk_level: str
    generation: int
    annotations_untrusted: bool = True

    def __post_init__(self) -> None:
        _text(self.server_id, "server_id", 128)
        _text(self.tool_name, "tool_name", 128)
        _text(self.resource_uri, "resource_uri", 1024)
        _sha(self.descriptor_digest, "descriptor_digest")
        _scopes(list(self.declared_scopes), "declared_scopes")
        _risk(self.risk_level, "risk_level")
        _int(self.generation, "generation", 0, 2**63 - 1)
        _bool(self.annotations_untrusted, "annotations_untrusted")
        if not self.annotations_untrusted:
            raise ToolAuthorizationError("tool annotations must remain untrusted")


@dataclass(frozen=True)
class ToolGrant:
    grant_id: str
    actor_id: str
    resource_uri: str
    tool_descriptor_digest: str
    scopes: tuple[str, ...]
    issued_at: int
    expires_at: int
    generation: int
    max_uses: int
    confirmation_digest: str
    minimum_risk_confirmation: str = "low"

    def __post_init__(self) -> None:
        _text(self.grant_id, "grant_id", 128)
        _text(self.actor_id, "actor_id", 256)
        _text(self.resource_uri, "resource_uri", 1024)
        _sha(self.tool_descriptor_digest, "tool_descriptor_digest")
        _scopes(list(self.scopes), "scopes")
        _int(self.issued_at, "issued_at", 0, 2**63 - 1)
        _int(self.expires_at, "expires_at", 1, 2**63 - 1)
        if self.expires_at <= self.issued_at:
            raise ToolAuthorizationError("grant expiry must follow issue time")
        _int(self.generation, "generation", 0, 2**63 - 1)
        _int(self.max_uses, "max_uses", 1, MAX_USES)
        _sha(self.confirmation_digest, "confirmation_digest")
        _risk(self.minimum_risk_confirmation, "minimum_risk_confirmation")

    @property
    def grant_digest(self) -> str:
        return digest({
            "schema": GRANT_SCHEMA,
            "grant_id": self.grant_id,
            "actor_id": self.actor_id,
            "resource_uri": self.resource_uri,
            "tool_descriptor_digest": self.tool_descriptor_digest,
            "scopes": list(self.scopes),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "generation": self.generation,
            "max_uses": self.max_uses,
            "confirmation_digest": self.confirmation_digest,
            "minimum_risk_confirmation": self.minimum_risk_confirmation,
        })


@dataclass(frozen=True)
class InvocationRequest:
    invocation_id: str
    actor_id: str
    resource_uri: str
    tool_name: str
    descriptor_digest: str
    requested_scopes: tuple[str, ...]
    argument_digest: str
    risk_level: str
    requested_at: int
    generation: int
    confirmation_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.invocation_id, "invocation_id", 128)
        _text(self.actor_id, "actor_id", 256)
        _text(self.resource_uri, "resource_uri", 1024)
        _text(self.tool_name, "tool_name", 128)
        _sha(self.descriptor_digest, "descriptor_digest")
        _scopes(list(self.requested_scopes), "requested_scopes")
        _sha(self.argument_digest, "argument_digest")
        _risk(self.risk_level, "risk_level")
        _int(self.requested_at, "requested_at", 0, 2**63 - 1)
        _int(self.generation, "generation", 0, 2**63 - 1)
        if self.confirmation_digest is not None:
            _sha(self.confirmation_digest, "confirmation_digest")


class ToolAdmissionLedger:
    def __init__(self, *, max_admissions: int = 4096) -> None:
        _int(max_admissions, "max_admissions", 1, MAX_USES * 4)
        self.max_admissions = max_admissions
        self._used_grants: dict[str, int] = {}
        self._invocations: set[str] = set()

    def admit(self, descriptor: ToolDescriptor, grant: ToolGrant, request: InvocationRequest, *, current_generation: int, now: int, nonce: str) -> dict[str, Any]:
        _int(current_generation, "current_generation", 0, 2**63 - 1)
        _int(now, "now", 0, 2**63 - 1)
        nonce = _text(nonce, "nonce", 128)
        if request.invocation_id in self._invocations:
            raise ToolAuthorizationError("invocation replay")
        if descriptor.generation != current_generation or grant.generation != current_generation or request.generation != current_generation:
            raise ToolAuthorizationError("generation mismatch")
        if now < grant.issued_at or now >= grant.expires_at:
            raise ToolAuthorizationError("grant expired or not yet valid")
        if request.requested_at < grant.issued_at or request.requested_at >= grant.expires_at:
            raise ToolAuthorizationError("invocation outside grant lifetime")
        if request.actor_id != grant.actor_id:
            raise ToolAuthorizationError("actor mismatch")
        if request.resource_uri != grant.resource_uri or descriptor.resource_uri != grant.resource_uri:
            raise ToolAuthorizationError("resource indicator mismatch")
        if request.descriptor_digest != grant.tool_descriptor_digest or descriptor.descriptor_digest != request.descriptor_digest:
            raise ToolAuthorizationError("tool descriptor mismatch")
        if request.tool_name != descriptor.tool_name:
            raise ToolAuthorizationError("tool name mismatch")
        requested = set(request.requested_scopes)
        granted = set(grant.scopes)
        declared = set(descriptor.declared_scopes)
        if not requested.issubset(granted) or not requested.issubset(declared):
            raise ToolAuthorizationError("scope exceeds grant or descriptor")
        if RISK_LEVELS[request.risk_level] > RISK_LEVELS[grant.minimum_risk_confirmation]:
            if request.confirmation_digest is None or request.confirmation_digest != grant.confirmation_digest:
                raise ToolAuthorizationError("risk confirmation required")
        used = self._used_grants.get(grant.grant_digest, 0)
        if used >= grant.max_uses:
            raise ToolAuthorizationError("grant use limit exceeded")
        if len(self._invocations) >= self.max_admissions:
            raise ToolAuthorizationError("admission bound exceeded")
        self._invocations.add(request.invocation_id)
        self._used_grants[grant.grant_digest] = used + 1
        result = {
            "schema": SCHEMA,
            "invocation_id": request.invocation_id,
            "grant_digest": grant.grant_digest,
            "descriptor_digest": descriptor.descriptor_digest,
            "resource_uri": request.resource_uri,
            "requested_scopes": list(request.requested_scopes),
            "argument_digest": request.argument_digest,
            "risk_level": request.risk_level,
            "generation": current_generation,
            "use_number": used + 1,
            "nonce_digest": digest(nonce),
            "admitted": True,
            "authority": {
                "model_output_is_authority": False,
                "tool_description_is_authority": False,
                "tool_result_is_authority": False,
                "grant_is_production_authority": False,
            },
        }
        result["receipt_digest"] = digest(result)
        return result

    def digest(self) -> str:
        return digest({"schema": SCHEMA, "used_grants": self._used_grants, "invocations": sorted(self._invocations)})


__all__ = ["SCHEMA", "GRANT_SCHEMA", "ToolAuthorizationError", "ToolDescriptor", "ToolGrant", "InvocationRequest", "ToolAdmissionLedger", "digest"]
