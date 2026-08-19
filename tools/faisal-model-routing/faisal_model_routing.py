#!/usr/bin/env python3
"""FAISAL deterministic model-routing and fallback contract.

This module plans routes only. It never calls a model, treats model output as
authority, or trusts endpoint/provider metadata without a caller-side policy.
"""
from __future__ import annotations

import copy
import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

MAX_ENDPOINTS = 256
MAX_FALLBACKS = 8
SCHEMA = "org.faisal.model-route.v1"
PRIVACY_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
CAPABILITIES = {"text", "reasoning", "coding", "vision", "audio", "embedding", "multimodal", "tool_calling"}
HEALTH_STATES = {"healthy", "degraded", "unhealthy", "unknown"}


class RoutingContractError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _require_text(value: Any, name: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise RoutingContractError(f"{name}: invalid")
    return value


@dataclass(frozen=True)
class Endpoint:
    endpoint_id: str
    model_id: str
    model_digest: str
    provider_class: str
    capabilities: frozenset[str]
    privacy_class: str
    region: str
    max_context_tokens: int
    estimated_cost_milli: int
    estimated_latency_ms: int
    health: str = "unknown"
    health_generation: int = 0
    active_requests: int = 0
    max_concurrency: int = 1
    cache_hit: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        _require_text(self.endpoint_id, "endpoint_id")
        _require_text(self.model_id, "model_id")
        _require_text(self.model_digest, "model_digest", 256)
        _require_text(self.provider_class, "provider_class")
        _require_text(self.region, "region")
        if not self.capabilities or not self.capabilities.issubset(CAPABILITIES):
            raise RoutingContractError("capabilities: unsupported or empty")
        if self.privacy_class not in PRIVACY_ORDER:
            raise RoutingContractError("privacy_class: invalid")
        if self.health not in HEALTH_STATES:
            raise RoutingContractError("health: invalid")
        if not isinstance(self.max_context_tokens, int) or self.max_context_tokens <= 0:
            raise RoutingContractError("max_context_tokens: invalid")
        for name in ("estimated_cost_milli", "estimated_latency_ms", "health_generation", "active_requests", "max_concurrency"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise RoutingContractError(f"{name}: invalid")
        if self.active_requests > self.max_concurrency:
            raise RoutingContractError("active_requests exceeds max_concurrency")

    def canonical(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "provider_class": self.provider_class,
            "capabilities": sorted(self.capabilities),
            "privacy_class": self.privacy_class,
            "region": self.region,
            "max_context_tokens": self.max_context_tokens,
            "estimated_cost_milli": self.estimated_cost_milli,
            "estimated_latency_ms": self.estimated_latency_ms,
            "health": self.health,
            "health_generation": self.health_generation,
            "active_requests": self.active_requests,
            "max_concurrency": self.max_concurrency,
            "cache_hit": self.cache_hit,
        }


@dataclass(frozen=True)
class RouteRequest:
    request_id: str
    required_capability: str
    privacy_class: str
    context_tokens: int
    max_cost_milli: int
    max_latency_ms: int
    region: str
    min_health: str = "degraded"
    preferred_models: tuple[str, ...] = ()
    allow_cross_region: bool = False
    max_fallbacks: int = 3
    generation: int = 0

    def __post_init__(self) -> None:
        _require_text(self.request_id, "request_id")
        if self.required_capability not in CAPABILITIES:
            raise RoutingContractError("required_capability: invalid")
        if self.privacy_class not in PRIVACY_ORDER:
            raise RoutingContractError("privacy_class: invalid")
        for name in ("context_tokens", "max_cost_milli", "max_latency_ms", "generation"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 0:
                raise RoutingContractError(f"{name}: invalid")
        if self.min_health not in {"healthy", "degraded"}:
            raise RoutingContractError("min_health: invalid")
        if not isinstance(self.max_fallbacks, int) or not 0 <= self.max_fallbacks <= MAX_FALLBACKS:
            raise RoutingContractError("max_fallbacks: invalid")


def _health_rank(health: str) -> int:
    return {"healthy": 0, "degraded": 1, "unknown": 2, "unhealthy": 3}[health]


def _eligible(endpoint: Endpoint, request: RouteRequest, trusted_provider_classes: frozenset[str]) -> tuple[bool, str]:
    if endpoint.provider_class not in trusted_provider_classes:
        return False, "provider_class_not_allowed"
    if request.required_capability not in endpoint.capabilities:
        return False, "capability_mismatch"
    if PRIVACY_ORDER[endpoint.privacy_class] > PRIVACY_ORDER[request.privacy_class]:
        return False, "endpoint_privacy_insufficient"
    if endpoint.max_context_tokens < request.context_tokens:
        return False, "context_limit"
    if endpoint.estimated_cost_milli > request.max_cost_milli:
        return False, "cost_limit"
    if endpoint.estimated_latency_ms > request.max_latency_ms:
        return False, "latency_limit"
    if _health_rank(endpoint.health) > _health_rank(request.min_health):
        return False, "health_below_minimum"
    if endpoint.active_requests >= endpoint.max_concurrency:
        return False, "concurrency_full"
    if not request.allow_cross_region and endpoint.region != request.region:
        return False, "region_mismatch"
    if endpoint.health_generation < request.generation:
        return False, "stale_health_generation"
    return True, "eligible"


def _score(endpoint: Endpoint, request: RouteRequest) -> tuple[Any, ...]:
    preferred = 0 if endpoint.model_id in request.preferred_models else 1
    cache = 0 if endpoint.cache_hit else 1
    health = _health_rank(endpoint.health)
    locality = 0 if endpoint.region == request.region else 1
    return (preferred, health, cache, locality, endpoint.estimated_latency_ms, endpoint.estimated_cost_milli, endpoint.active_requests, endpoint.endpoint_id)


def plan_route(endpoints: Sequence[Endpoint], request: RouteRequest, *, trusted_provider_classes: Iterable[str], observed_at: int | None = None) -> dict[str, Any]:
    if len(endpoints) == 0 or len(endpoints) > MAX_ENDPOINTS:
        raise RoutingContractError("endpoint inventory is outside bounds")
    trusted = frozenset(_require_text(x, "trusted_provider_class") for x in trusted_provider_classes)
    if not trusted:
        raise RoutingContractError("trusted provider policy is empty")
    eligible: list[Endpoint] = []
    rejections: dict[str, str] = {}
    seen: set[str] = set()
    for endpoint in endpoints:
        if endpoint.endpoint_id in seen:
            raise RoutingContractError("duplicate endpoint_id")
        seen.add(endpoint.endpoint_id)
        ok, reason = _eligible(endpoint, request, trusted)
        if ok:
            eligible.append(endpoint)
        else:
            rejections[endpoint.endpoint_id] = reason
    if not eligible:
        raise RoutingContractError("no eligible model endpoint")
    ordered = sorted(eligible, key=lambda endpoint: _score(endpoint, request))
    selected = ordered[: request.max_fallbacks + 1]
    route = {
        "schema": SCHEMA,
        "request_id": request.request_id,
        "generation": request.generation,
        "observed_at": int(time.time()) if observed_at is None else observed_at,
        "primary": selected[0].canonical(),
        "fallbacks": [endpoint.canonical() for endpoint in selected[1:]],
        "rejections": dict(sorted(rejections.items())),
        "selection_policy": {
            "trusted_provider_classes": sorted(trusted),
            "model_output_is_authority": False,
            "endpoint_metadata_is_authority": False,
            "fallbacks_are_plans_not_executions": True,
        },
    }
    route["route_digest"] = _digest(route)
    return route


class RoutePlanCache:
    """Bounded cache for deterministic route plans; health generation is part of the key."""

    def __init__(self, max_entries: int = 128):
        if not isinstance(max_entries, int) or max_entries <= 0 or max_entries > 1024:
            raise RoutingContractError("route cache size is outside bounds")
        self.max_entries = max_entries
        self._items: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def plan(self, endpoints: Sequence[Endpoint], request: RouteRequest, *, trusted_provider_classes: Iterable[str], observed_at: int | None = None) -> dict[str, Any]:
        trusted = tuple(sorted(set(trusted_provider_classes)))
        # Endpoint and request objects are immutable snapshots. Replacing a health
        # snapshot or request therefore changes identity and invalidates the cache.
        key = (tuple(id(endpoint) for endpoint in endpoints), id(request), trusted)
        cached = self._items.get(key)
        if cached is not None:
            self._items.move_to_end(key)
            return copy.deepcopy(cached)
        route = plan_route(endpoints, request, trusted_provider_classes=trusted, observed_at=observed_at)
        self._items[key] = route
        self._items.move_to_end(key)
        while len(self._items) > self.max_entries:
            self._items.popitem(last=False)
        return copy.deepcopy(route)

    def __len__(self) -> int:
        return len(self._items)


def verify_route(route: Mapping[str, Any], *, expected_request_id: str, expected_generation: int) -> dict[str, Any]:
    if not isinstance(route, Mapping) or route.get("schema") != SCHEMA:
        raise RoutingContractError("route schema unsupported")
    if route.get("request_id") != expected_request_id or route.get("generation") != expected_generation:
        raise RoutingContractError("route generation fence mismatch")
    if not isinstance(route.get("primary"), Mapping) or not isinstance(route.get("fallbacks"), list):
        raise RoutingContractError("route shape invalid")
    if len(route["fallbacks"]) > MAX_FALLBACKS:
        raise RoutingContractError("fallback list exceeds bound")
    ids = [route["primary"].get("endpoint_id")] + [item.get("endpoint_id") for item in route["fallbacks"]]
    if any(not isinstance(item, str) or not item for item in ids) or len(ids) != len(set(ids)):
        raise RoutingContractError("route endpoint ids are invalid or duplicated")
    unsigned = dict(route)
    declared = unsigned.pop("route_digest", None)
    if declared != _digest(unsigned):
        raise RoutingContractError("route digest mismatch")
    policy = route.get("selection_policy")
    if not isinstance(policy, Mapping) or policy.get("model_output_is_authority") is not False or policy.get("endpoint_metadata_is_authority") is not False:
        raise RoutingContractError("authority boundary missing")
    return {"verified": True, "request_id": expected_request_id, "generation": expected_generation, "endpoint_count": len(ids), "route_digest": declared}
