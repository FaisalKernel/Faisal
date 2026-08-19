#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_thread_eval import ExpectedThread, ThreadEvaluator, ThreadPolicy, digest


def make_turn(number: int) -> dict:
    return {
        "turn": number,
        "status": "complete",
        "input_digest": digest({"input": number}),
        "output_digest": digest({"output": number}),
        "state_digest": digest({"state": "final" if number == 3 else "intermediate"}),
        "outcome_digest": digest({"outcome": "done" if number == 3 else "working"}),
        "safety_passed": True,
        "runs": [{"run_id": f"run-{number}", "tool_name": "observe", "tool_args_digest": digest({"arg": number}), "safety_passed": True}],
        "latency_ns": 1000 + number,
        "authority": {
            "model_output_is_authority": False,
            "tool_output_is_authority": False,
            "trace_is_execution_authority": False,
            "evaluation_is_production_approval": False,
        },
    }


def main(iterations: int = 1000) -> None:
    evaluator = ThreadEvaluator(ThreadPolicy(max_trials=8))
    expected = ExpectedThread("thread-bench", digest({"state": "final"}), digest({"outcome": "done"}), 3, True)
    turns = [make_turn(1), make_turn(2), make_turn(3)]
    verify_ns: list[int] = []
    aggregate_ns: list[int] = []
    for i in range(iterations):
        start = time.perf_counter_ns()
        receipt = evaluator.verify_trace(candidate_id="c1", version="v1", trial_id=f"trial-{i}", thread_id="thread-bench", turns=turns, expected=expected)
        verify_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        evaluator.aggregate_trials([receipt], candidate_id="c1", version="v1", thread_id="thread-bench")
        aggregate_ns.append(time.perf_counter_ns() - start)
    print(f"FAISAL_THREAD_EVAL_BENCHMARK_ITERATIONS={iterations}")
    print(f"FAISAL_THREAD_EVAL_VERIFY_MEAN_NS={statistics.mean(verify_ns):.2f}")
    print(f"FAISAL_THREAD_EVAL_AGGREGATE_MEAN_NS={statistics.mean(aggregate_ns):.2f}")
    print(f"FAISAL_THREAD_EVAL_VERIFY_P95_NS={sorted(verify_ns)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_THREAD_EVAL_AGGREGATE_P95_NS={sorted(aggregate_ns)[int(iterations * 0.95) - 1]}")
    print("FAISAL_THREAD_EVAL_BENCHMARK_OK")
    print("FAISAL_THREAD_EVAL_BENCHMARK_SCOPE=local_python_receipt_integrity_not_model_quality_or_kernel_latency")


if __name__ == "__main__":
    main()
