#!/usr/bin/env python3
"""FAISAL cross-agent handoff receipt admission contract.

This contract validates handoff metadata before a local control plane accepts it
as a resumable task relationship. It does not contact remote agents, execute a
task, mint credentials, or treat Agent Cards, model output, provider metadata, or
remote results as authority.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "org.faisal.agent-handoff-receipt.v1"
RESULT_SCHEMA = "org.faisal.agent-handoff-result-receipt.v1"
MAX_SCOPE_ITEMS = 64
MAX_HANDOFFS = 4096
MAX_TTL_SECONDS = 86_400
TRUST_ORDER = {"quarantined": 0, "untrusted": 1, "bounded": 2, "trusted": 3}
APPROVAL_ORDER = {"none": 0, "caller_approved": 1, "operator_approved": 2}


class HandoffError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise HandoffError(f"{name}: invalid")
    return value


def _digest(value: Any, name: str) -> str:
    value = _text(value, name, 71)
    if not value.startswith("sha256:") or len(value) != 71:
        raise HandoffError(f"{name}: invalid digest")
    return value


def _u64(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, int) or value < minimum or value > (1 << 63) - 1:
        raise HandoffError(f"{name}: invalid")
    return value


def _scope(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)) or not value or len(value) > MAX_SCOPE_ITEMS:
        raise HandoffError(f"{name}: invalid")
    result = tuple(sorted({_text(item, name, 128) for item in value}))
    if not result:
        raise HandoffError(f"{name}: empty")
    return result


@dataclass(frozen=True)
class HandoffRequest:
    handoff_id: str
    issuer_agent_id: str
    delegatee_agent_id: str
    objective_digest: str
    parent_delegation_digest: str
    capability_scope: tuple[str, ...]
    trace_position: int
    generation: int
    issued_at: int
    expires_at: int
    approval: str = "none"
    source_trust: str = "bounded"
    model_output_authority: bool = False
    provider_metadata_authority: bool = False

    def canonical(self) -> dict[str, Any]:
        approval = _text(self.approval, "approval")
        trust = _text(self.source_trust, "source_trust")
        if approval not in APPROVAL_ORDER or trust not in TRUST_ORDER:
            raise HandoffError("approval or trust unsupported")
        issued_at = _u64(self.issued_at, "issued_at")
        expires_at = _u64(self.expires_at, "expires_at")
        if expires_at <= issued_at or expires_at - issued_at > MAX_TTL_SECONDS:
            raise HandoffError("handoff TTL invalid")
        return {
            "handoff_id": _text(self.handoff_id, "handoff_id"),
            "issuer_agent_id": _text(self.issuer_agent_id, "issuer_agent_id"),
            "delegatee_agent_id": _text(self.delegatee_agent_id, "delegatee_agent_id"),
            "objective_digest": _digest(self.objective_digest, "objective_digest"),
            "parent_delegation_digest": _digest(self.parent_delegation_digest, "parent_delegation_digest"),
            "capability_scope": list(_scope(self.capability_scope, "capability_scope")),
            "trace_position": _u64(self.trace_position, "trace_position", minimum=1),
            "generation": _u64(self.generation, "generation", minimum=1),
            "issued_at": issued_at,
            "expires_at": expires_at,
            "approval": approval,
            "source_trust": trust,
            "model_output_authority": bool(self.model_output_authority),
            "provider_metadata_authority": bool(self.provider_metadata_authority),
        }


@dataclass(frozen=True)
class HandoffPolicy:
    allowed_scope: tuple[str, ...]
    minimum_trust: str = "bounded"
    minimum_approval: str = "caller_approved"
    require_operator_for_scope: tuple[str, ...] = ()
    max_ttl_seconds: int = MAX_TTL_SECONDS
    allow_remote_result_quarantine: bool = True

    def canonical(self) -> dict[str, Any]:
        trust = _text(self.minimum_trust, "minimum_trust")
        approval = _text(self.minimum_approval, "minimum_approval")
        max_ttl = _u64(self.max_ttl_seconds, "max_ttl_seconds", minimum=1)
        if trust not in TRUST_ORDER or approval not in APPROVAL_ORDER or max_ttl > MAX_TTL_SECONDS:
            raise HandoffError("handoff policy unsupported")
        required_operator = tuple(sorted(set(_scope(self.require_operator_for_scope, "require_operator_for_scope") if self.require_operator_for_scope else ())))
        return {"allowed_scope": list(_scope(self.allowed_scope, "allowed_scope")), "minimum_trust": trust, "minimum_approval": approval, "require_operator_for_scope": list(required_operator), "max_ttl_seconds": max_ttl, "allow_remote_result_quarantine": bool(self.allow_remote_result_quarantine)}


@dataclass(frozen=True)
class HandoffResult:
    handoff_digest: str
    result_digest: str
    result_provenance_digest: str
    source_kind: str
    source_trust: str
    generation: int
    trace_position: int
    observed_at: int
    model_output_authority: bool = False
    provider_metadata_authority: bool = False

    def canonical(self) -> dict[str, Any]:
        trust = _text(self.source_trust, "source_trust")
        if trust not in TRUST_ORDER:
            raise HandoffError("result trust unsupported")
        source_kind = _text(self.source_kind, "source_kind")
        if source_kind not in {"delegatee", "operator", "verified_tool", "model_output", "unknown"}:
            raise HandoffError("result source unsupported")
        return {"schema": RESULT_SCHEMA, "handoff_digest": _digest(self.handoff_digest, "handoff_digest"), "result_digest": _digest(self.result_digest, "result_digest"), "result_provenance_digest": _digest(self.result_provenance_digest, "result_provenance_digest"), "source_kind": source_kind, "source_trust": trust, "generation": _u64(self.generation, "generation", minimum=1), "trace_position": _u64(self.trace_position, "trace_position", minimum=1), "observed_at": _u64(self.observed_at, "observed_at"), "model_output_authority": bool(self.model_output_authority), "provider_metadata_authority": bool(self.provider_metadata_authority)}


class HandoffAdmission:
    def __init__(self, *, max_handoffs: int = MAX_HANDOFFS) -> None:
        if not 1 <= max_handoffs <= MAX_HANDOFFS:
            raise HandoffError("max_handoffs outside bound")
        self.max_handoffs = max_handoffs
        self._handoffs: dict[str, dict[str, Any]] = {}
        self._results: dict[str, dict[str, Any]] = {}
        self._replay: set[str] = set()
        self._version = 0

    def admit(self, request: HandoffRequest, *, policy: HandoffPolicy, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        body = request.canonical()
        policy_body = policy.canonical()
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", minimum=1)
        nonce = _text(nonce, "nonce")
        request_digest = digest({"schema": SCHEMA, "request": body})
        if request_digest in self._handoffs:
            raise HandoffError("handoff replay detected")
        if len(self._handoffs) >= self.max_handoffs:
            raise HandoffError("handoff admission bound exceeded")
        if body["generation"] != current_generation:
            raise HandoffError("handoff generation mismatch")
        if body["issued_at"] > now or body["expires_at"] <= now or now - body["issued_at"] > policy_body["max_ttl_seconds"]:
            raise HandoffError("handoff freshness or expiry violated")
        if not set(body["capability_scope"]).issubset(set(policy_body["allowed_scope"])):
            raise HandoffError("handoff capability scope exceeds policy")
        if TRUST_ORDER[body["source_trust"]] < TRUST_ORDER[policy_body["minimum_trust"]]:
            raise HandoffError("handoff trust below policy")
        if APPROVAL_ORDER[body["approval"]] < APPROVAL_ORDER[policy_body["minimum_approval"]]:
            raise HandoffError("handoff approval below policy")
        if any(scope in body["capability_scope"] for scope in policy_body["require_operator_for_scope"]) and body["approval"] != "operator_approved":
            raise HandoffError("operator approval required for handoff scope")
        if body["model_output_authority"] or body["provider_metadata_authority"]:
            raise HandoffError("remote metadata cannot assert authority")
        record = {"schema": SCHEMA, "request": body, "handoff_digest": request_digest, "status": "admitted", "nonce_digest": digest({"handoff_digest": request_digest, "nonce": nonce}), "authority": {"model_output_is_authority": False, "provider_metadata_is_authority": False, "handoff_is_execution": False, "remote_result_is_authority": False, "production_approval": False}, "policy": policy_body}
        self._handoffs[request_digest] = record
        self._version += 1
        return {**record, "admitted": True, "verified": True}

    def admit_result(self, handoff_record: Mapping[str, Any], result: HandoffResult, *, policy: HandoffPolicy, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        if not isinstance(handoff_record, Mapping) or handoff_record.get("schema") != SCHEMA or handoff_record.get("status") != "admitted":
            raise HandoffError("result requires admitted handoff")
        handoff_digest = _digest(handoff_record.get("handoff_digest"), "handoff_digest")
        stored = self._handoffs.get(handoff_digest)
        supplied = {key: value for key, value in dict(handoff_record).items() if key not in {"admitted", "verified"}}
        if stored is None or {key: stored.get(key) for key in stored if key != "nonce_digest"} != {key: supplied.get(key) for key in supplied if key != "nonce_digest"}:
            raise HandoffError("handoff record not found or tampered")
        result_body = result.canonical()
        policy_body = policy.canonical()
        now = _u64(now, "now")
        current_generation = _u64(current_generation, "current_generation", minimum=1)
        nonce = _text(nonce, "nonce")
        if result_body["handoff_digest"] != handoff_digest:
            raise HandoffError("result handoff mismatch")
        request = stored["request"]
        if result_body["generation"] != current_generation or result_body["generation"] != request["generation"]:
            raise HandoffError("result generation mismatch")
        if result_body["trace_position"] < request["trace_position"]:
            raise HandoffError("result trace regressed")
        if result_body["observed_at"] > now or result_body["observed_at"] - request["issued_at"] > policy_body["max_ttl_seconds"]:
            raise HandoffError("result freshness violated")
        if result_body["model_output_authority"] or result_body["provider_metadata_authority"]:
            raise HandoffError("result cannot assert authority")
        result_key = digest({"handoff_digest": handoff_digest, "result_digest": result_body["result_digest"], "nonce": nonce})
        if result_key in self._replay:
            raise HandoffError("result replay detected")
        self._replay.add(result_key)
        quarantined = result_body["source_kind"] in {"model_output", "unknown"} or TRUST_ORDER[result_body["source_trust"]] < TRUST_ORDER[policy_body["minimum_trust"]]
        if quarantined and not policy_body["allow_remote_result_quarantine"]:
            raise HandoffError("remote result quarantine disabled")
        record = {"schema": RESULT_SCHEMA, "handoff_digest": handoff_digest, "result": result_body, "status": "quarantined" if quarantined else "admitted", "reason": "remote_result_untrusted" if quarantined else "remote_result_bounded", "authority": {"model_output_is_authority": False, "provider_metadata_is_authority": False, "remote_result_is_authority": False, "result_is_execution": False, "production_approval": False}}
        self._results[result_key] = record
        self._version += 1
        return {**record, "admitted": not quarantined, "quarantined": quarantined}

    def digest(self) -> str:
        return digest({"version": self._version, "handoffs": sorted(self._handoffs), "results": sorted(self._results), "replay": sorted(self._replay)})
