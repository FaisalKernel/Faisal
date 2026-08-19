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
MAX_OUTCOME_KEYS = 256
MAX_OUTCOME_SAMPLES = 4096
MAX_OUTCOME_AGE_SECONDS = 3600
COOLDOWN_FAILURE_THRESHOLD = 3
COOLDOWN_SECONDS = 30
SCHEMA = "org.faisal.model-route.v1"
OUTCOME_SCHEMA = "org.faisal.model-route-outcome.v1"
RUNTIME_PROFILE_SCHEMA = "org.faisal.model-runtime-profile.v1"
RUNTIME_PROFILE_ENGINES = {"vllm", "sglang", "tensorrt-llm", "llama.cpp", "custom", "unknown"}
RUNTIME_PROFILE_CACHE_MODES = {"none", "paged", "prefix", "kv", "unknown"}
RUNTIME_PROFILE_ACCELERATORS = {"cpu", "gpu", "npu", "tpu", "fpga", "unknown"}
RUNTIME_PROFILE_MODALITIES = {"text", "vision", "audio", "embedding", "multimodal"}
PRIVACY_ORDER = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
CAPABILITIES = {"text", "reasoning", "coding", "vision", "audio", "embedding", "multimodal", "tool_calling"}
HEALTH_STATES = {"healthy", "degraded", "unhealthy", "unknown"}


class RoutingContractError(ValueError):
    pass


@dataclass
class _OutcomeStats:
    attempts: int = 0
    successes: int = 0
    failures: int = 0
    failure_streak: int = 0
    ewma_latency_ms: int = 0
    last_observed_at: int = 0
    cooldown_until: int = 0


class OutcomeLedger:
    """Bounded caller-observed feedback; observations are never authorization."""

    def __init__(self, *, max_keys: int = MAX_OUTCOME_KEYS, max_samples: int = MAX_OUTCOME_SAMPLES, cooldown_seconds: int = COOLDOWN_SECONDS):
        if not 1 <= max_keys <= MAX_OUTCOME_KEYS or not 1 <= max_samples <= MAX_OUTCOME_SAMPLES:
            raise RoutingContractError("outcome ledger bounds are invalid")
        if not 1 <= cooldown_seconds <= 3600:
            raise RoutingContractError("cooldown_seconds is invalid")
        self.max_keys = max_keys
        self.max_samples = max_samples
        self.cooldown_seconds = cooldown_seconds
        self._stats: dict[tuple[str, str], _OutcomeStats] = {}
        self._bound_receipt_digests: set[str] = set()
        self._samples = 0
        self._version = 0

    @property
    def version(self) -> int:
        return self._version

    def record(self, *, endpoint_id: str, request_class: str, success: bool, latency_ms: int, observed_at: int, current_generation: int, sample_generation: int) -> dict[str, Any]:
        _require_text(endpoint_id, "endpoint_id")
        _require_text(request_class, "request_class")
        if not isinstance(success, bool):
            raise RoutingContractError("success must be boolean")
        if not isinstance(latency_ms, int) or not 0 <= latency_ms <= 86_400_000:
            raise RoutingContractError("latency_ms is outside bounds")
        if not isinstance(observed_at, int) or observed_at < 0:
            raise RoutingContractError("observed_at is invalid")
        if not isinstance(current_generation, int) or current_generation < 0 or not isinstance(sample_generation, int) or sample_generation < current_generation:
            raise RoutingContractError("outcome generation is stale")
        key = (endpoint_id, request_class)
        if key not in self._stats and len(self._stats) >= self.max_keys:
            raise RoutingContractError("outcome ledger key bound exceeded")
        if self._samples >= self.max_samples:
            raise RoutingContractError("outcome ledger sample bound exceeded")
        stats = self._stats.setdefault(key, _OutcomeStats())
        stats.attempts += 1
        if success:
            stats.successes += 1
            stats.failure_streak = 0
            stats.cooldown_until = 0
        else:
            stats.failures += 1
            stats.failure_streak += 1
            if stats.failure_streak >= COOLDOWN_FAILURE_THRESHOLD:
                stats.cooldown_until = observed_at + self.cooldown_seconds
        stats.ewma_latency_ms = latency_ms if stats.attempts == 1 else (stats.ewma_latency_ms * 3 + latency_ms) // 4
        stats.last_observed_at = observed_at
        self._samples += 1
        self._version += 1
        return self.stats(endpoint_id=endpoint_id, request_class=request_class, observed_at=observed_at)

    def record_bound_outcome(self, *, route: Mapping[str, Any], request: "RouteRequest", endpoint_id: str, success: bool, latency_ms: int, observed_at: int, current_generation: int, sample_generation: int, evidence_digest: str, max_age_seconds: int = 300, runtime_profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Record only a caller-observed result bound to one verified route snapshot.

        The receipt is an integrity record, not proof that a model was correct and
        not permission to execute a tool or side effect. Replay, stale-route,
        future-generation, endpoint-mismatch, and stale-observation inputs fail
        closed before they can influence adaptive routing.
        """
        verified = verify_route(route, expected_request_id=request.request_id, expected_generation=request.generation)
        if not isinstance(max_age_seconds, int) or not 0 <= max_age_seconds <= MAX_OUTCOME_AGE_SECONDS:
            raise RoutingContractError("max_age_seconds is outside bounds")
        if not isinstance(observed_at, int) or observed_at < 0:
            raise RoutingContractError("observed_at is invalid")
        if observed_at < int(route.get("observed_at", 0)):
            raise RoutingContractError("outcome predates route snapshot")
        if observed_at - int(route.get("observed_at", 0)) > max_age_seconds:
            raise RoutingContractError("outcome exceeds freshness window")
        if current_generation != request.generation or sample_generation != request.generation:
            raise RoutingContractError("bound outcome generation mismatch")
        _require_digest(evidence_digest, "evidence_digest")
        route_profile = route.get("runtime_profile")
        route_profile_digest = route.get("runtime_profile_digest")
        if route_profile is not None:
            normalized_profile, computed_profile_digest = validate_runtime_profile(route_profile)
            if route_profile_digest != computed_profile_digest:
                raise RoutingContractError("runtime profile digest mismatch")
            if runtime_profile is None:
                raise RoutingContractError("runtime profile is required for this route")
            supplied_profile, supplied_profile_digest = validate_runtime_profile(runtime_profile)
            if supplied_profile_digest != computed_profile_digest or supplied_profile != normalized_profile:
                raise RoutingContractError("runtime profile does not match route")
        elif runtime_profile is not None:
            raise RoutingContractError("runtime profile supplied for an unprofiled route")
        candidates = [route["primary"], *route["fallbacks"]]
        endpoint = next((item for item in candidates if item.get("endpoint_id") == endpoint_id), None)
        if endpoint is None:
            raise RoutingContractError("outcome endpoint is not in route")
        body = {
            "schema": OUTCOME_SCHEMA,
            "route_digest": verified["route_digest"],
            "request_id": request.request_id,
            "generation": request.generation,
            "endpoint_id": endpoint_id,
            "model_digest": endpoint.get("model_digest"),
            "request_class": self.route_class(request),
            "success": success,
            "latency_ms": latency_ms,
            "observed_at": observed_at,
            "sample_generation": sample_generation,
            "evidence_digest": evidence_digest,
            "runtime_profile_digest": route_profile_digest,
        }
        binding_digest = _digest(body)
        if binding_digest in self._bound_receipt_digests:
            raise RoutingContractError("bound outcome replay detected")
        self.record(endpoint_id=endpoint_id, request_class=self.route_class(request), success=success, latency_ms=latency_ms, observed_at=observed_at, current_generation=current_generation, sample_generation=sample_generation)
        self._bound_receipt_digests.add(binding_digest)
        return {**body, "binding_digest": binding_digest, "verified": True, "outcomes_are_authority": False, "runtime_profile_bound": route_profile_digest is not None}

    def stats(self, *, endpoint_id: str, request_class: str, observed_at: int | None = None) -> dict[str, Any]:
        stats = self._stats.get((endpoint_id, request_class))
        if stats is None:
            return {"attempts": 0, "successes": 0, "failures": 0, "failure_rate_permille": 500, "failure_streak": 0, "ewma_latency_ms": 0, "cooldown_until": 0}
        return {
            "attempts": stats.attempts,
            "successes": stats.successes,
            "failures": stats.failures,
            "failure_rate_permille": (stats.failures * 1000 + 500) // (stats.attempts + 1),
            "failure_streak": stats.failure_streak,
            "ewma_latency_ms": stats.ewma_latency_ms,
            "cooldown_until": stats.cooldown_until,
        }

    def is_cooled_down(self, endpoint_id: str, request_class: str, observed_at: int) -> bool:
        stats = self._stats.get((endpoint_id, request_class))
        return bool(stats and stats.cooldown_until > observed_at)

    def route_class(self, request: "RouteRequest") -> str:
        return request.required_capability + ":" + request.privacy_class

    def digest(self) -> str:
        rows = []
        for key in sorted(self._stats):
            rows.append([key[0], key[1], self.stats(endpoint_id=key[0], request_class=key[1])])
        return _digest({"version": self._version, "samples": self._samples, "bound_receipts": sorted(self._bound_receipt_digests), "rows": rows})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def _require_text(value: Any, name: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise RoutingContractError(f"{name}: invalid")
    return value


def _require_digest(value: Any, name: str) -> str:
    _require_text(value, name, 256)
    if not value.startswith("sha256:") or len(value) != 71:
        raise RoutingContractError(f"{name}: invalid digest")
    return value


def validate_runtime_profile(profile: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    """Validate a caller-supplied inference execution profile and return its digest.

    The profile describes runtime conditions only. It is not provider authority,
    hardware proof, model correctness, or permission to execute side effects.
    """
    if not isinstance(profile, Mapping) or profile.get("schema") != RUNTIME_PROFILE_SCHEMA:
        raise RoutingContractError("runtime profile schema unsupported")
    engine = _require_text(profile.get("engine"), "runtime_profile.engine", 64)
    if engine not in RUNTIME_PROFILE_ENGINES:
        raise RoutingContractError("runtime_profile.engine unsupported")
    engine_version = _require_text(profile.get("engine_version"), "runtime_profile.engine_version", 64)
    cache_mode = _require_text(profile.get("cache_mode"), "runtime_profile.cache_mode", 32)
    if cache_mode not in RUNTIME_PROFILE_CACHE_MODES:
        raise RoutingContractError("runtime_profile.cache_mode unsupported")
    accelerator_class = _require_text(profile.get("accelerator_class"), "runtime_profile.accelerator_class", 32)
    if accelerator_class not in RUNTIME_PROFILE_ACCELERATORS:
        raise RoutingContractError("runtime_profile.accelerator_class unsupported")
    modalities = profile.get("modalities")
    if not isinstance(modalities, (list, tuple)) or not modalities or len(modalities) > len(RUNTIME_PROFILE_MODALITIES):
        raise RoutingContractError("runtime_profile.modalities invalid")
    normalized_modalities = sorted({_require_text(item, "runtime_profile.modality", 32) for item in modalities})
    if not set(normalized_modalities).issubset(RUNTIME_PROFILE_MODALITIES):
        raise RoutingContractError("runtime_profile.modalities unsupported")
    parallelism = profile.get("parallelism", {})
    if not isinstance(parallelism, Mapping):
        raise RoutingContractError("runtime_profile.parallelism invalid")
    normalized_parallelism: dict[str, int] = {}
    for name in ("tensor", "pipeline", "data", "expert", "context"):
        value = parallelism.get(name, 1)
        if not isinstance(value, int) or not 1 <= value <= 1024:
            raise RoutingContractError(f"runtime_profile.parallelism.{name} invalid")
        normalized_parallelism[name] = value
    for name in ("tool_calling", "structured_output", "speculative_decoding"):
        if not isinstance(profile.get(name, False), bool):
            raise RoutingContractError(f"runtime_profile.{name} invalid")
    normalized = {
        "schema": RUNTIME_PROFILE_SCHEMA,
        "engine": engine,
        "engine_version": engine_version,
        "cache_mode": cache_mode,
        "parallelism": normalized_parallelism,
        "quantization": _require_text(profile.get("quantization", "none"), "runtime_profile.quantization", 64),
        "modalities": normalized_modalities,
        "accelerator_class": accelerator_class,
        "tool_calling": profile.get("tool_calling", False),
        "structured_output": profile.get("structured_output", False),
        "speculative_decoding": profile.get("speculative_decoding", False),
    }
    return normalized, _digest(normalized)


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


def _eligible(endpoint: Endpoint, request: RouteRequest, trusted_provider_classes: frozenset[str], outcome_ledger: OutcomeLedger | None, observed_at: int) -> tuple[bool, str]:
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
    if outcome_ledger is not None and outcome_ledger.is_cooled_down(endpoint.endpoint_id, outcome_ledger.route_class(request), observed_at):
        return False, "outcome_cooldown"
    return True, "eligible"


def _score(endpoint: Endpoint, request: RouteRequest, outcome_ledger: OutcomeLedger | None) -> tuple[Any, ...]:
    outcome = {"failure_rate_permille": 500, "ewma_latency_ms": 0, "attempts": 0}
    if outcome_ledger is not None:
        outcome = outcome_ledger.stats(endpoint_id=endpoint.endpoint_id, request_class=outcome_ledger.route_class(request))
    adaptive_latency = outcome["ewma_latency_ms"] if outcome["attempts"] else endpoint.estimated_latency_ms
    return (
        0 if endpoint.model_id in request.preferred_models else 1,
        _health_rank(endpoint.health),
        0 if endpoint.cache_hit else 1,
        outcome["failure_rate_permille"],
        0 if endpoint.region == request.region else 1,
        adaptive_latency,
        endpoint.estimated_cost_milli,
        endpoint.active_requests,
        endpoint.endpoint_id,
    )


def _legacy_score(endpoint: Endpoint, request: RouteRequest) -> tuple[Any, ...]:
    preferred = 0 if endpoint.model_id in request.preferred_models else 1
    cache = 0 if endpoint.cache_hit else 1
    health = _health_rank(endpoint.health)
    locality = 0 if endpoint.region == request.region else 1
    return (preferred, health, cache, locality, endpoint.estimated_latency_ms, endpoint.estimated_cost_milli, endpoint.active_requests, endpoint.endpoint_id)


def plan_route(endpoints: Sequence[Endpoint], request: RouteRequest, *, trusted_provider_classes: Iterable[str], observed_at: int | None = None, outcome_ledger: OutcomeLedger | None = None, runtime_profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if len(endpoints) == 0 or len(endpoints) > MAX_ENDPOINTS:
        raise RoutingContractError("endpoint inventory is outside bounds")
    trusted = frozenset(_require_text(x, "trusted_provider_class") for x in trusted_provider_classes)
    observed_time = int(time.time()) if observed_at is None else observed_at
    if not isinstance(observed_time, int) or observed_time < 0:
        raise RoutingContractError("observed_at is invalid")
    if not trusted:
        raise RoutingContractError("trusted provider policy is empty")
    normalized_profile = None
    profile_digest = None
    if runtime_profile is not None:
        normalized_profile, profile_digest = validate_runtime_profile(runtime_profile)
    eligible: list[Endpoint] = []
    rejections: dict[str, str] = {}
    seen: set[str] = set()
    for endpoint in endpoints:
        if endpoint.endpoint_id in seen:
            raise RoutingContractError("duplicate endpoint_id")
        seen.add(endpoint.endpoint_id)
        ok, reason = _eligible(endpoint, request, trusted, outcome_ledger, observed_time)
        if ok:
            eligible.append(endpoint)
        else:
            rejections[endpoint.endpoint_id] = reason
    if not eligible:
        raise RoutingContractError("no eligible model endpoint")
    ordered = sorted(eligible, key=lambda endpoint: _score(endpoint, request, outcome_ledger))
    selected = ordered[: request.max_fallbacks + 1]
    route = {
        "schema": SCHEMA,
        "request_id": request.request_id,
        "generation": request.generation,
        "observed_at": observed_time,
        "primary": selected[0].canonical(),
        "fallbacks": [endpoint.canonical() for endpoint in selected[1:]],
        "rejections": dict(sorted(rejections.items())),
        "runtime_profile": normalized_profile,
        "runtime_profile_digest": profile_digest,
        "selection_policy": {
            "trusted_provider_classes": sorted(trusted),
            "model_output_is_authority": False,
            "endpoint_metadata_is_authority": False,
            "outcome_observations_are_authority": False,
            "runtime_profile_is_caller_supplied": runtime_profile is not None,
            "fallbacks_are_plans_not_executions": True,
            "outcome_ledger_digest": outcome_ledger.digest() if outcome_ledger is not None else None,
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

    def plan(self, endpoints: Sequence[Endpoint], request: RouteRequest, *, trusted_provider_classes: Iterable[str], observed_at: int | None = None, outcome_ledger: OutcomeLedger | None = None, runtime_profile: Mapping[str, Any] | None = None) -> dict[str, Any]:
        trusted = tuple(sorted(set(trusted_provider_classes)))
        # Endpoint and request objects are immutable snapshots. Replacing a health
        # snapshot or request therefore changes identity and invalidates the cache.
        profile_key = _canonical(runtime_profile) if runtime_profile is not None else None
        key = (tuple(id(endpoint) for endpoint in endpoints), id(request), trusted, outcome_ledger.version if outcome_ledger is not None else -1, profile_key)
        cached = self._items.get(key)
        if cached is not None:
            self._items.move_to_end(key)
            return copy.deepcopy(cached)
        route = plan_route(endpoints, request, trusted_provider_classes=trusted, observed_at=observed_at, outcome_ledger=outcome_ledger, runtime_profile=runtime_profile)
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
    route_profile = route.get("runtime_profile")
    route_profile_digest = route.get("runtime_profile_digest")
    if route_profile is None:
        if route_profile_digest is not None:
            raise RoutingContractError("runtime profile digest without profile")
    else:
        _, computed_profile_digest = validate_runtime_profile(route_profile)
        if route_profile_digest != computed_profile_digest:
            raise RoutingContractError("runtime profile digest mismatch")
    if policy.get("runtime_profile_is_caller_supplied") is not (route_profile is not None):
        raise RoutingContractError("runtime profile authority boundary missing")
    return {"verified": True, "request_id": expected_request_id, "generation": expected_generation, "endpoint_count": len(ids), "route_digest": declared}
