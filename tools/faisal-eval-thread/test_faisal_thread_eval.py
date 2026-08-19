#!/usr/bin/env python3
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_thread_eval import ExpectedThread, ThreadEvalError, ThreadEvaluator, ThreadPolicy, digest


def turn(number: int, *, state: str, outcome: str, status: str = "complete", safety: bool = True, runs: list[dict] | None = None) -> dict:
    return {
        "turn": number,
        "status": status,
        "input_digest": digest({"input": number}),
        "output_digest": digest({"output": number}),
        "state_digest": digest({"state": state}),
        "outcome_digest": digest({"outcome": outcome}),
        "safety_passed": safety,
        "runs": runs or [{"run_id": f"run-{number}", "tool_name": "read_state", "tool_args_digest": digest({"arg": number}), "safety_passed": safety}],
        "latency_ns": 1000 + number,
        "authority": {
            "model_output_is_authority": False,
            "tool_output_is_authority": False,
            "trace_is_execution_authority": False,
            "evaluation_is_production_approval": False,
        },
    }


class ThreadEvalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.evaluator = ThreadEvaluator(ThreadPolicy(max_trials=3))
        self.expected = ExpectedThread("thread-1", digest({"state": "final"}), digest({"outcome": "done"}), 2, True)
        self.turns = [turn(1, state="intermediate", outcome="working"), turn(2, state="final", outcome="done")]

    def test_complete_trace_matches_state_and_outcome(self) -> None:
        receipt = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="trial-1", thread_id="thread-1", turns=self.turns, expected=self.expected)
        self.assertTrue(receipt["trace_passed"])
        self.assertTrue(receipt["state_match"])
        self.assertTrue(receipt["outcome_match"])
        self.assertFalse(receipt["authority"]["trace_is_execution_authority"])

    def test_partial_progress_is_not_a_pass(self) -> None:
        partial_expected = ExpectedThread("thread-1", digest({"state": "other"}), digest({"outcome": "done"}), 2, True)
        receipt = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="trial-1", thread_id="thread-1", turns=self.turns, expected=partial_expected)
        self.assertFalse(receipt["trace_passed"])
        self.assertTrue(receipt["partial"])

    def test_timeout_and_unsafe_trace_fail(self) -> None:
        timeout_turns = [turn(1, state="intermediate", outcome="working"), turn(2, state="final", outcome="done", status="timeout")]
        receipt = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="trial-timeout", thread_id="thread-1", turns=timeout_turns, expected=self.expected)
        self.assertFalse(receipt["trace_passed"])
        unsafe_turns = [turn(1, state="intermediate", outcome="working"), turn(2, state="final", outcome="done", safety=False)]
        receipt = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="trial-unsafe", thread_id="thread-1", turns=unsafe_turns, expected=self.expected)
        self.assertFalse(receipt["safety_passed"])

    def test_trial_aggregation_pass_at_k_and_pass_all_k(self) -> None:
        good = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="good", thread_id="thread-1", turns=self.turns, expected=self.expected)
        bad_turns = [turn(1, state="intermediate", outcome="working"), turn(2, state="wrong", outcome="wrong")]
        bad = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="bad", thread_id="thread-1", turns=bad_turns, expected=self.expected)
        aggregate = self.evaluator.aggregate_trials([good, bad], candidate_id="c1", version="v1", thread_id="thread-1")
        self.assertTrue(aggregate["pass_at_k"])
        self.assertFalse(aggregate["pass_all_k"])
        self.assertFalse(aggregate["eligible_for_evaluation_promotion"])

    def test_duplicate_and_tampered_receipts_fail(self) -> None:
        good = self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="good", thread_id="thread-1", turns=self.turns, expected=self.expected)
        with self.assertRaises(ThreadEvalError):
            self.evaluator.aggregate_trials([good, good], candidate_id="c1", version="v1", thread_id="thread-1")
        tampered = copy.deepcopy(good)
        tampered["authority"]["model_output_is_authority"] = True
        with self.assertRaises(ThreadEvalError):
            self.evaluator.aggregate_trials([tampered], candidate_id="c1", version="v1", thread_id="thread-1")

    def test_sequence_identity_and_authority_rejection(self) -> None:
        bad_sequence = [turn(2, state="intermediate", outcome="working"), turn(2, state="final", outcome="done")]
        with self.assertRaises(ThreadEvalError):
            self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="bad-sequence", thread_id="thread-1", turns=bad_sequence, expected=self.expected)
        bad_authority = copy.deepcopy(self.turns)
        bad_authority[0]["authority"]["tool_output_is_authority"] = True
        with self.assertRaises(ThreadEvalError):
            self.evaluator.verify_trace(candidate_id="c1", version="v1", trial_id="bad-authority", thread_id="thread-1", turns=bad_authority, expected=self.expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
