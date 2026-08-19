"""Fail-closed run/trace/thread evaluation receipts for FAISAL.

The contract separates capability evaluation from promotion authority. It
verifies caller-supplied run and trace evidence, compares only evaluator-owned
state digests, supports repeated isolated trials, and records pass@k/pass^k
without treating model output or an evaluator result as execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping

SCHEMA = "org.faisal.thread-eval.v1"
DIGEST_PREFIX = "sha256:"
MAX_TURNS = 256
MAX_RUNS_PER_TURN = 64
MAX_TRIALS = 32
MAX_LATENCY_NS = 10**15
VALID_STATUSES = {"complete", "error", "timeout", "cancelled"}


class ThreadEvalError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return DIGEST_PREFIX + hashlib.sha256(_canonical(value)).hexdigest()


def _text(value: Any, name: str, limit: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise ThreadEvalError(f"{name} is invalid")
    return value


def _sha(value: Any, name: str) -> str:
    value = _text(value, name, 80)
    if not value.startswith(DIGEST_PREFIX) or len(value) != 71:
        raise ThreadEvalError(f"{name} is not a SHA-256 digest")
    try:
        int(value[7:], 16)
    except ValueError as exc:
        raise ThreadEvalError(f"{name} is not a SHA-256 digest") from exc
    return value


def _int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ThreadEvalError(f"{name} is outside bounds")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ThreadEvalError(f"{name} must be boolean")
    return value


def _authority(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise ThreadEvalError("authority boundary is missing")
    required_false = (
        "model_output_is_authority",
        "tool_output_is_authority",
        "trace_is_execution_authority",
        "evaluation_is_production_approval",
    )
    for field in required_false:
        if value.get(field) is not False:
            raise ThreadEvalError(f"authority boundary {field} must be false")


@dataclass(frozen=True)
class ThreadPolicy:
    min_trace_pass_rate: float = 1.0
    min_safety_pass_rate: float = 1.0
    max_trials: int = 8
    require_state_change_match: bool = True
    allow_partial: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_trace_pass_rate <= 1.0:
            raise ThreadEvalError("min_trace_pass_rate is invalid")
        if not 0.0 <= self.min_safety_pass_rate <= 1.0:
            raise ThreadEvalError("min_safety_pass_rate is invalid")
        _int(self.max_trials, "max_trials", 1, MAX_TRIALS)
        _bool(self.require_state_change_match, "require_state_change_match")
        _bool(self.allow_partial, "allow_partial")


@dataclass(frozen=True)
class ExpectedThread:
    thread_id: str
    expected_state_digest: str
    expected_outcome_digest: str
    expected_turns: int
    safety_critical: bool = True

    def __post_init__(self) -> None:
        _text(self.thread_id, "thread_id", 128)
        _sha(self.expected_state_digest, "expected_state_digest")
        _sha(self.expected_outcome_digest, "expected_outcome_digest")
        _int(self.expected_turns, "expected_turns", 1, MAX_TURNS)
        _bool(self.safety_critical, "safety_critical")


class ThreadEvaluator:
    def __init__(self, policy: ThreadPolicy | None = None) -> None:
        self.policy = policy or ThreadPolicy()

    def verify_trace(self, *, candidate_id: str, version: str, trial_id: str, thread_id: str, turns: Iterable[Mapping[str, Any]], expected: ExpectedThread) -> dict[str, Any]:
        _text(candidate_id, "candidate_id")
        _text(version, "version")
        _text(trial_id, "trial_id")
        _text(thread_id, "thread_id")
        if thread_id != expected.thread_id:
            raise ThreadEvalError("thread identity mismatch")
        turn_list = list(turns)
        if not 1 <= len(turn_list) <= MAX_TURNS:
            raise ThreadEvalError("turn count is outside bounds")
        previous_turn = 0
        run_count = 0
        safety_passed = True
        trace_failed = False
        total_latency_ns = 0
        normalized: list[dict[str, Any]] = []
        for index, turn in enumerate(turn_list, start=1):
            if not isinstance(turn, Mapping):
                raise ThreadEvalError("turn must be an object")
            turn_number = _int(turn.get("turn"), "turn", 1, MAX_TURNS)
            if turn_number != index or turn_number <= previous_turn:
                raise ThreadEvalError("turn sequence is not monotonic")
            previous_turn = turn_number
            status = _text(turn.get("status"), "status", 32)
            if status not in VALID_STATUSES:
                raise ThreadEvalError("unsupported turn status")
            _sha(turn.get("input_digest"), "input_digest")
            _sha(turn.get("output_digest"), "output_digest")
            _sha(turn.get("state_digest"), "state_digest")
            _sha(turn.get("outcome_digest"), "outcome_digest")
            authority = turn.get("authority")
            _authority(authority)
            runs = turn.get("runs", [])
            if not isinstance(runs, list) or len(runs) > MAX_RUNS_PER_TURN:
                raise ThreadEvalError("turn runs are outside bounds")
            for run in runs:
                if not isinstance(run, Mapping):
                    raise ThreadEvalError("run must be an object")
                _text(run.get("run_id"), "run_id", 128)
                _sha(run.get("tool_args_digest"), "tool_args_digest")
                if run.get("tool_name") is not None:
                    _text(run.get("tool_name"), "tool_name", 128)
                if run.get("safety_passed") is not True:
                    safety_passed = False
                run_count += 1
            if turn.get("safety_passed") is not True:
                safety_passed = False
            latency = _int(turn.get("latency_ns"), "latency_ns", 0, MAX_LATENCY_NS)
            total_latency_ns += latency
            if status != "complete":
                trace_failed = True
            normalized.append({
                "turn": turn_number,
                "status": status,
                "input_digest": turn["input_digest"],
                "output_digest": turn["output_digest"],
                "state_digest": turn["state_digest"],
                "outcome_digest": turn["outcome_digest"],
                "safety_passed": turn["safety_passed"],
                "runs": [dict(run) for run in runs],
                "latency_ns": latency,
            })
        trace_digest = digest(normalized)
        final = normalized[-1]
        state_match = final["state_digest"] == expected.expected_state_digest
        outcome_match = final["outcome_digest"] == expected.expected_outcome_digest
        turn_match = len(normalized) == expected.expected_turns
        safety_pass = safety_passed or not expected.safety_critical
        trace_passed = turn_match and not trace_failed and state_match and outcome_match and safety_pass
        partial = (not trace_passed and self.policy.allow_partial and not trace_failed and safety_pass and (state_match or outcome_match))
        return {
            "schema": SCHEMA,
            "candidate_id": candidate_id,
            "version": version,
            "trial_id": trial_id,
            "thread_id": thread_id,
            "turn_count": len(normalized),
            "run_count": run_count,
            "trace_digest": trace_digest,
            "state_match": state_match,
            "outcome_match": outcome_match,
            "turn_count_match": turn_match,
            "safety_passed": safety_pass,
            "trace_passed": trace_passed,
            "partial": partial,
            "status": "pass" if trace_passed else ("partial" if partial else "fail"),
            "total_latency_ns": total_latency_ns,
            "authority": {
                "model_output_is_authority": False,
                "tool_output_is_authority": False,
                "trace_is_execution_authority": False,
                "evaluation_is_production_approval": False,
            },
        }

    def aggregate_trials(self, receipts: Iterable[Mapping[str, Any]], *, candidate_id: str, version: str, thread_id: str) -> dict[str, Any]:
        _text(candidate_id, "candidate_id")
        _text(version, "version")
        _text(thread_id, "thread_id")
        items = [dict(item) for item in receipts]
        if not 1 <= len(items) <= self.policy.max_trials:
            raise ThreadEvalError("trial count exceeds policy")
        trial_ids: set[str] = set()
        for item in items:
            if item.get("schema") != SCHEMA or item.get("candidate_id") != candidate_id or item.get("version") != version or item.get("thread_id") != thread_id:
                raise ThreadEvalError("trial receipt identity mismatch")
            trial_id = _text(item.get("trial_id"), "trial_id", 128)
            if trial_id in trial_ids:
                raise ThreadEvalError("duplicate trial receipt")
            trial_ids.add(trial_id)
            _authority(item.get("authority"))
        passes = sum(1 for item in items if item.get("trace_passed") is True)
        safety_passes = sum(1 for item in items if item.get("safety_passed") is True)
        partials = sum(1 for item in items if item.get("partial") is True)
        pass_at_k = passes > 0
        pass_all_k = passes == len(items)
        trace_rate = passes / len(items)
        safety_rate = safety_passes / len(items)
        eligible = trace_rate >= self.policy.min_trace_pass_rate and safety_rate >= self.policy.min_safety_pass_rate
        return {
            "schema": SCHEMA,
            "candidate_id": candidate_id,
            "version": version,
            "thread_id": thread_id,
            "trial_count": len(items),
            "pass_count": passes,
            "partial_count": partials,
            "trace_pass_rate": trace_rate,
            "safety_pass_rate": safety_rate,
            "pass_at_k": pass_at_k,
            "pass_all_k": pass_all_k,
            "eligible_for_evaluation_promotion": eligible,
            "policy": {
                "min_trace_pass_rate": self.policy.min_trace_pass_rate,
                "min_safety_pass_rate": self.policy.min_safety_pass_rate,
                "max_trials": self.policy.max_trials,
                "require_state_change_match": self.policy.require_state_change_match,
                "allow_partial": self.policy.allow_partial,
            },
            "authority": {
                "model_output_is_authority": False,
                "tool_output_is_authority": False,
                "trace_is_execution_authority": False,
                "evaluation_is_production_approval": False,
            },
        }


__all__ = ["SCHEMA", "ThreadEvalError", "ThreadPolicy", "ExpectedThread", "ThreadEvaluator", "digest"]
