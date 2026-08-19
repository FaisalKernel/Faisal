"""Fail-closed provider-neutral route budget admission for FAISAL.

The contract models the budget/rate-limit behavior exposed by current AI
 gateways while remaining independent of any provider. It reserves bounded
 estimated cost/tokens/concurrency for a verified route and settles only
 caller-observed usage. It never calls a model, chooses authority, or treats
 endpoint/provider metadata or model output as trusted authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

SCHEMA = "org.faisal.route-budget.v1"
DIGEST_PREFIX = "sha256:"
MAX_WINDOWS = 16
MAX_RESERVATIONS = 4096
MAX_COST_MILLI = 10**12
MAX_TOKENS = 10**9
MAX_CONCURRENCY = 65536


class BudgetError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: Any) -> str:
    return DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise BudgetError(f"{name} must be a non-empty bounded string")
    return value


def _digest_text(value: Any, name: str) -> str:
    value = _text(value, name, 80)
    if not value.startswith(DIGEST_PREFIX) or len(value) != 71:
        raise BudgetError(f"{name} must be a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise BudgetError(f"{name} must be a SHA-256 digest") from exc
    return value


def _bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise BudgetError(f"{name} is outside bounds")
    return value


@dataclass(frozen=True)
class BudgetWindow:
    window_id: str
    max_cost_milli: int
    max_input_tokens: int
    max_output_tokens: int
    max_concurrency: int

    def __post_init__(self) -> None:
        _text(self.window_id, "window_id", 64)
        _bounded_int(self.max_cost_milli, "max_cost_milli", 0, MAX_COST_MILLI)
        _bounded_int(self.max_input_tokens, "max_input_tokens", 0, MAX_TOKENS)
        _bounded_int(self.max_output_tokens, "max_output_tokens", 0, MAX_TOKENS)
        _bounded_int(self.max_concurrency, "max_concurrency", 1, MAX_CONCURRENCY)

    def canonical(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "max_cost_milli": self.max_cost_milli,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_concurrency": self.max_concurrency,
        }


@dataclass(frozen=True)
class BudgetRequest:
    reservation_id: str
    request_id: str
    route_digest: str
    generation: int
    estimated_cost_milli: int
    estimated_input_tokens: int
    estimated_output_tokens: int
    now: int
    ttl_seconds: int = 60

    def __post_init__(self) -> None:
        _text(self.reservation_id, "reservation_id", 128)
        _text(self.request_id, "request_id", 128)
        _digest_text(self.route_digest, "route_digest")
        _bounded_int(self.generation, "generation", 0, 2**63 - 1)
        _bounded_int(self.estimated_cost_milli, "estimated_cost_milli", 0, MAX_COST_MILLI)
        _bounded_int(self.estimated_input_tokens, "estimated_input_tokens", 0, MAX_TOKENS)
        _bounded_int(self.estimated_output_tokens, "estimated_output_tokens", 0, MAX_TOKENS)
        _bounded_int(self.now, "now", 0, 2**63 - 1)
        _bounded_int(self.ttl_seconds, "ttl_seconds", 1, 86400)

    def canonical(self) -> dict[str, Any]:
        return {
            "reservation_id": self.reservation_id,
            "request_id": self.request_id,
            "route_digest": self.route_digest,
            "generation": self.generation,
            "estimated_cost_milli": self.estimated_cost_milli,
            "estimated_input_tokens": self.estimated_input_tokens,
            "estimated_output_tokens": self.estimated_output_tokens,
            "now": self.now,
            "ttl_seconds": self.ttl_seconds,
        }


@dataclass(frozen=True)
class Usage:
    actual_cost_milli: int
    actual_input_tokens: int
    actual_output_tokens: int
    observed_at: int

    def __post_init__(self) -> None:
        _bounded_int(self.actual_cost_milli, "actual_cost_milli", 0, MAX_COST_MILLI)
        _bounded_int(self.actual_input_tokens, "actual_input_tokens", 0, MAX_TOKENS)
        _bounded_int(self.actual_output_tokens, "actual_output_tokens", 0, MAX_TOKENS)
        _bounded_int(self.observed_at, "observed_at", 0, 2**63 - 1)

    def canonical(self) -> dict[str, int]:
        return {
            "actual_cost_milli": self.actual_cost_milli,
            "actual_input_tokens": self.actual_input_tokens,
            "actual_output_tokens": self.actual_output_tokens,
            "observed_at": self.observed_at,
        }


class RouteBudgetLedger:
    def __init__(self, windows: tuple[BudgetWindow, ...], *, max_reservations: int = MAX_RESERVATIONS) -> None:
        if not windows or len(windows) > MAX_WINDOWS:
            raise BudgetError("at least one bounded budget window is required")
        if len({window.window_id for window in windows}) != len(windows):
            raise BudgetError("budget window identifiers must be unique")
        _bounded_int(max_reservations, "max_reservations", 1, MAX_RESERVATIONS)
        self.windows = tuple(windows)
        self.max_reservations = max_reservations
        self._reservations: dict[str, dict[str, Any]] = {}
        self._nonces: set[str] = set()
        self._settled: set[str] = set()
        self._version = 0

    def _usage_totals(self) -> dict[str, int]:
        totals = {"cost": 0, "input": 0, "output": 0, "concurrency": 0}
        for item in self._reservations.values():
            if item["status"] == "reserved":
                totals["cost"] += item["reserved"]["cost"]
                totals["input"] += item["reserved"]["input"]
                totals["output"] += item["reserved"]["output"]
                totals["concurrency"] += 1
        return totals

    def _check_capacity(self, request: BudgetRequest, totals: Mapping[str, int]) -> None:
        for window in self.windows:
            if totals["cost"] + request.estimated_cost_milli > window.max_cost_milli:
                raise BudgetError(f"budget window {window.window_id} cost capacity exceeded")
            if totals["input"] + request.estimated_input_tokens > window.max_input_tokens:
                raise BudgetError(f"budget window {window.window_id} input-token capacity exceeded")
            if totals["output"] + request.estimated_output_tokens > window.max_output_tokens:
                raise BudgetError(f"budget window {window.window_id} output-token capacity exceeded")
            if totals["concurrency"] + 1 > window.max_concurrency:
                raise BudgetError(f"budget window {window.window_id} concurrency capacity exceeded")

    def reserve(self, request: BudgetRequest, *, current_generation: int, nonce: str) -> dict[str, Any]:
        _bounded_int(current_generation, "current_generation", 0, 2**63 - 1)
        nonce = _text(nonce, "nonce", 128)
        if request.generation != current_generation:
            raise BudgetError("budget generation mismatch")
        if request.reservation_id in self._reservations or nonce in self._nonces:
            raise BudgetError("reservation replay")
        if len(self._reservations) >= self.max_reservations:
            raise BudgetError("reservation capacity exhausted")
        totals = self._usage_totals()
        self._check_capacity(request, totals)
        body = {
            "schema": SCHEMA,
            "status": "reserved",
            "reservation_id": request.reservation_id,
            "request_id": request.request_id,
            "route_digest": request.route_digest,
            "generation": request.generation,
            "issued_at": request.now,
            "expires_at": request.now + request.ttl_seconds,
            "reserved": {
                "cost": request.estimated_cost_milli,
                "input": request.estimated_input_tokens,
                "output": request.estimated_output_tokens,
            },
            "settled": None,
            "authority": {
                "model_output_is_authority": False,
                "provider_metadata_is_authority": False,
                "budget_is_execution": False,
                "production_approval": False,
            },
        }
        body["record_digest"] = _digest(body)
        self._reservations[request.reservation_id] = body
        self._nonces.add(nonce)
        self._version += 1
        return json.loads(json.dumps(body))

    def settle(self, reservation: Mapping[str, Any], usage: Usage, *, current_generation: int, nonce: str) -> dict[str, Any]:
        if not isinstance(reservation, Mapping) or reservation.get("schema") != SCHEMA:
            raise BudgetError("invalid budget reservation")
        reservation_id = _text(reservation.get("reservation_id"), "reservation_id", 128)
        stored = self._reservations.get(reservation_id)
        supplied = dict(reservation)
        claimed = supplied.pop("record_digest", None)
        stored_body = dict(stored) if stored is not None else None
        if stored_body is not None:
            stored_body.pop("record_digest", None)
        if stored is None or claimed != stored.get("record_digest") or supplied != stored_body:
            raise BudgetError("budget reservation missing or tampered")
        nonce = _text(nonce, "nonce", 128)
        if nonce in self._nonces or reservation_id in self._settled:
            raise BudgetError("settlement replay")
        _bounded_int(current_generation, "current_generation", 0, 2**63 - 1)
        if current_generation != stored["generation"]:
            raise BudgetError("settlement generation mismatch")
        if usage.observed_at < stored["issued_at"]:
            raise BudgetError("usage predates reservation")
        if usage.observed_at > stored["expires_at"]:
            raise BudgetError("reservation expired")
        reserved = stored["reserved"]
        if usage.actual_cost_milli > reserved["cost"] or usage.actual_input_tokens > reserved["input"] or usage.actual_output_tokens > reserved["output"]:
            raise BudgetError("actual usage exceeds reserved budget; fail closed")
        settled = usage.canonical()
        stored["status"] = "settled"
        stored["settled"] = settled
        stored["record_digest"] = _digest({k: v for k, v in stored.items() if k != "record_digest"})
        self._nonces.add(nonce)
        self._settled.add(reservation_id)
        self._version += 1
        return json.loads(json.dumps(stored))

    def release(self, reservation: Mapping[str, Any], *, now: int, current_generation: int, nonce: str) -> dict[str, Any]:
        if not isinstance(reservation, Mapping) or reservation.get("schema") != SCHEMA:
            raise BudgetError("invalid budget reservation")
        reservation_id = _text(reservation.get("reservation_id"), "reservation_id", 128)
        stored = self._reservations.get(reservation_id)
        if stored is None or stored.get("record_digest") != reservation.get("record_digest"):
            raise BudgetError("budget reservation missing or tampered")
        nonce = _text(nonce, "nonce", 128)
        if nonce in self._nonces or stored["status"] != "reserved":
            raise BudgetError("release replay or non-reserved state")
        _bounded_int(now, "now", 0, 2**63 - 1)
        _bounded_int(current_generation, "current_generation", 0, 2**63 - 1)
        if current_generation != stored["generation"]:
            raise BudgetError("release generation mismatch")
        if now < stored["issued_at"]:
            raise BudgetError("release predates reservation")
        stored["status"] = "released"
        stored["released_at"] = now
        stored["record_digest"] = _digest({k: v for k, v in stored.items() if k != "record_digest"})
        self._nonces.add(nonce)
        self._version += 1
        return json.loads(json.dumps(stored))

    def digest(self) -> str:
        return _digest({"schema": SCHEMA, "version": self._version, "windows": [w.canonical() for w in self.windows], "reservations": self._reservations, "settled": sorted(self._settled)})


__all__ = ["SCHEMA", "BudgetError", "BudgetWindow", "BudgetRequest", "Usage", "RouteBudgetLedger"]
