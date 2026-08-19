"""Fail-closed context-window admission for long-horizon FAISAL agents.

This is a provider-neutral control-plane primitive. It selects bounded context
references; it does not summarize, call models, retrieve data, or authorize
side effects. Compaction summaries are caller-supplied evidence and remain
data-only until separately verified by an application policy.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.context-window.v1"
COMPACTION_SCHEMA = "org.faisal.context-compaction.v1"
MAX_ITEMS = 4096
MAX_CONTEXT_TOKENS = 10**9
MAX_DIGESTS = 4096


class ContextError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ContextError(f"{name} is invalid")
    return value


def _sha(value: Any, name: str) -> str:
    value = _text(value, name, 80)
    if not value.startswith("sha256:") or len(value) != 71:
        raise ContextError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise ContextError(f"{name} is not a SHA-256 digest") from exc
    return value


def _int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ContextError(f"{name} is outside bounds")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ContextError(f"{name} must be boolean")
    return value


def _authority(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ContextError("authority boundary missing")
    for field in ("model_output_is_authority", "compaction_is_authority", "context_is_execution_authority", "production_approval"):
        if value.get(field) is not False:
            raise ContextError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ContextItem:
    item_id: str
    kind: str
    source_digest: str
    generation: int
    trust_rank: int
    token_estimate: int
    priority: int
    recency: int
    expires_at: int = 0
    pinned: bool = False
    required: bool = False
    quarantined: bool = False

    def __post_init__(self) -> None:
        _text(self.item_id, "item_id", 128)
        _text(self.kind, "kind", 64)
        _sha(self.source_digest, "source_digest")
        _int(self.generation, "generation", 0, 2**63 - 1)
        _int(self.trust_rank, "trust_rank", 0, 3)
        _int(self.token_estimate, "token_estimate", 1, MAX_CONTEXT_TOKENS)
        _int(self.priority, "priority", 0, 1000)
        _int(self.recency, "recency", 0, 2**63 - 1)
        _int(self.expires_at, "expires_at", 0, 2**63 - 1)
        _bool(self.pinned, "pinned")
        _bool(self.required, "required")
        _bool(self.quarantined, "quarantined")

    def canonical(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind,
            "source_digest": self.source_digest,
            "generation": self.generation,
            "trust_rank": self.trust_rank,
            "token_estimate": self.token_estimate,
            "priority": self.priority,
            "recency": self.recency,
            "expires_at": self.expires_at,
            "pinned": self.pinned,
            "required": self.required,
            "quarantined": self.quarantined,
        }

    @property
    def item_digest(self) -> str:
        return digest(self.canonical())


@dataclass(frozen=True)
class ContextPolicy:
    max_context_tokens: int
    max_items: int = 256
    minimum_trust_rank: int = 1
    allow_partial_context: bool = True

    def __post_init__(self) -> None:
        _int(self.max_context_tokens, "max_context_tokens", 1, MAX_CONTEXT_TOKENS)
        _int(self.max_items, "max_items", 1, MAX_ITEMS)
        _int(self.minimum_trust_rank, "minimum_trust_rank", 0, 3)
        _bool(self.allow_partial_context, "allow_partial_context")


class ContextLedger:
    def __init__(self, *, max_admissions: int = 4096) -> None:
        _int(max_admissions, "max_admissions", 1, MAX_ITEMS)
        self.max_admissions = max_admissions
        self._admitted: set[str] = set()
        self._nonces: set[str] = set()
        self._version = 0

    def admit(self, plan: Mapping[str, Any], *, current_generation: int, nonce: str) -> dict[str, Any]:
        if not isinstance(plan, Mapping) or plan.get("schema") != SCHEMA:
            raise ContextError("context plan schema unsupported")
        _sha(plan.get("context_digest"), "context_digest")
        _authority(plan.get("authority"))
        _int(current_generation, "current_generation", 0, 2**63 - 1)
        if plan.get("generation") != current_generation:
            raise ContextError("context generation mismatch")
        nonce = _text(nonce, "nonce", 128)
        if nonce in self._nonces or plan["context_digest"] in self._admitted:
            raise ContextError("context admission replay")
        if len(self._admitted) >= self.max_admissions:
            raise ContextError("context admission bound exceeded")
        self._nonces.add(nonce)
        self._admitted.add(plan["context_digest"])
        self._version += 1
        result = dict(plan)
        result["admitted"] = True
        result["ledger_version"] = self._version
        return json.loads(json.dumps(result))

    def digest(self) -> str:
        return digest({"schema": SCHEMA, "version": self._version, "admitted": sorted(self._admitted)})


def _validate_compaction(receipt: Mapping[str, Any], *, omitted: list[ContextItem], generation: int, remaining_tokens: int) -> dict[str, Any]:
    if receipt.get("schema") != COMPACTION_SCHEMA:
        raise ContextError("compaction receipt schema unsupported")
    _int(receipt.get("generation"), "compaction.generation", 0, 2**63 - 1)
    if receipt["generation"] != generation:
        raise ContextError("compaction generation mismatch")
    source_digests = receipt.get("source_item_digests")
    if not isinstance(source_digests, list) or not source_digests or len(source_digests) > MAX_DIGESTS:
        raise ContextError("compaction sources invalid")
    normalized_sources = [_sha(item, "compaction.source_item_digest") for item in source_digests]
    omitted_digests = {item.item_digest for item in omitted}
    if set(normalized_sources) != omitted_digests:
        raise ContextError("compaction sources do not exactly cover omitted items")
    summary_digest = _sha(receipt.get("summary_digest"), "compaction.summary_digest")
    summary_tokens = _int(receipt.get("summary_tokens"), "compaction.summary_tokens", 1, MAX_CONTEXT_TOKENS)
    if summary_tokens > remaining_tokens:
        raise ContextError("compaction summary exceeds remaining context budget")
    _authority(receipt.get("authority"))
    return {
        "schema": COMPACTION_SCHEMA,
        "generation": generation,
        "source_item_digests": sorted(normalized_sources),
        "summary_digest": summary_digest,
        "summary_tokens": summary_tokens,
        "authority": {
            "model_output_is_authority": False,
            "compaction_is_authority": False,
            "context_is_execution_authority": False,
            "production_approval": False,
        },
    }


def plan_context(items: Iterable[ContextItem], policy: ContextPolicy, *, generation: int, observed_at: int, compaction_receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
    _int(generation, "generation", 0, 2**63 - 1)
    _int(observed_at, "observed_at", 0, 2**63 - 1)
    item_list = list(items)
    if not item_list or len(item_list) > MAX_ITEMS:
        raise ContextError("context item inventory is outside bounds")
    if len({item.item_id for item in item_list}) != len(item_list):
        raise ContextError("duplicate context item")
    eligible: list[ContextItem] = []
    rejected: dict[str, str] = {}
    for item in item_list:
        if item.generation != generation:
            rejected[item.item_id] = "generation_mismatch"
        elif item.quarantined:
            rejected[item.item_id] = "quarantined"
        elif item.trust_rank < policy.minimum_trust_rank:
            rejected[item.item_id] = "trust_below_minimum"
        elif item.expires_at and item.expires_at <= observed_at:
            rejected[item.item_id] = "expired"
        else:
            eligible.append(item)
    for item in item_list:
        if item.required and item.item_id in rejected:
            raise ContextError(f"required context item rejected: {item.item_id}:{rejected[item.item_id]}")
    eligible.sort(key=lambda item: (-int(item.pinned), -item.priority, -item.recency, item.token_estimate, item.item_id))
    selected: list[ContextItem] = []
    omitted: list[ContextItem] = []
    total_tokens = 0
    for item in eligible:
        if len(selected) >= policy.max_items or total_tokens + item.token_estimate > policy.max_context_tokens:
            omitted.append(item)
        else:
            selected.append(item)
            total_tokens += item.token_estimate
    if omitted and compaction_receipt is None and not policy.allow_partial_context:
        raise ContextError("context overflow requires compaction receipt")
    normalized_compaction = None
    if compaction_receipt is not None:
        normalized_compaction = _validate_compaction(compaction_receipt, omitted=omitted, generation=generation, remaining_tokens=policy.max_context_tokens - total_tokens)
        total_tokens += normalized_compaction["summary_tokens"]
    body = {
        "schema": SCHEMA,
        "generation": generation,
        "observed_at": observed_at,
        "policy": {
            "max_context_tokens": policy.max_context_tokens,
            "max_items": policy.max_items,
            "minimum_trust_rank": policy.minimum_trust_rank,
            "allow_partial_context": policy.allow_partial_context,
        },
        "selected_item_ids": [item.item_id for item in selected],
        "selected_item_digests": [item.item_digest for item in selected],
        "omitted_item_ids": [item.item_id for item in omitted],
        "rejections": dict(sorted(rejected.items())),
        "compaction": normalized_compaction,
        "total_token_estimate": total_tokens,
        "complete_context": not omitted and not rejected,
        "authority": {
            "model_output_is_authority": False,
            "compaction_is_authority": False,
            "context_is_execution_authority": False,
            "production_approval": False,
        },
    }
    body["context_digest"] = digest(body)
    return body


def verify_plan(plan: Mapping[str, Any], *, expected_generation: int) -> dict[str, Any]:
    if not isinstance(plan, Mapping) or plan.get("schema") != SCHEMA:
        raise ContextError("context plan schema unsupported")
    _int(expected_generation, "expected_generation", 0, 2**63 - 1)
    if plan.get("generation") != expected_generation:
        raise ContextError("context plan generation mismatch")
    _authority(plan.get("authority"))
    declared = _sha(plan.get("context_digest"), "context_digest")
    unsigned = dict(plan)
    unsigned.pop("context_digest", None)
    if digest(unsigned) != declared:
        raise ContextError("context plan tamper detected")
    selected = plan.get("selected_item_ids")
    selected_digests = plan.get("selected_item_digests")
    omitted = plan.get("omitted_item_ids")
    if not isinstance(selected, list) or not isinstance(selected_digests, list) or len(selected) != len(selected_digests) or not isinstance(omitted, list):
        raise ContextError("context plan shape invalid")
    for item in selected_digests:
        _sha(item, "selected_item_digest")
    return {"verified": True, "generation": expected_generation, "context_digest": declared, "selected_count": len(selected), "omitted_count": len(omitted), "complete_context": plan.get("complete_context") is True}


__all__ = ["SCHEMA", "COMPACTION_SCHEMA", "ContextError", "ContextItem", "ContextPolicy", "ContextLedger", "plan_context", "verify_plan", "digest"]
