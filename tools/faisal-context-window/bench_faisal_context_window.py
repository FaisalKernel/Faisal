#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_context_window import ContextItem, ContextLedger, ContextPolicy, digest, plan_context, verify_plan


def make_items(count: int = 32) -> list[ContextItem]:
    return [ContextItem(f"item-{i}", "memory", digest({"source": i}), 3, 2, 8 + i % 5, i % 10, i, 0, i == 0, False, False) for i in range(count)]


def main(iterations: int = 1000) -> None:
    items = make_items()
    policy = ContextPolicy(160, max_items=24, minimum_trust_rank=1)
    plan_ns: list[int] = []
    verify_ns: list[int] = []
    admit_ns: list[int] = []
    for i in range(iterations):
        start = time.perf_counter_ns()
        plan = plan_context(items, policy, generation=3, observed_at=100)
        plan_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        verify_plan(plan, expected_generation=3)
        verify_ns.append(time.perf_counter_ns() - start)
        ledger = ContextLedger()
        start = time.perf_counter_ns()
        ledger.admit(plan, current_generation=3, nonce=f"nonce-{i}")
        admit_ns.append(time.perf_counter_ns() - start)
    print(f"FAISAL_CONTEXT_WINDOW_BENCHMARK_ITERATIONS={iterations}")
    print(f"FAISAL_CONTEXT_WINDOW_PLAN_MEAN_NS={statistics.mean(plan_ns):.2f}")
    print(f"FAISAL_CONTEXT_WINDOW_VERIFY_MEAN_NS={statistics.mean(verify_ns):.2f}")
    print(f"FAISAL_CONTEXT_WINDOW_ADMIT_MEAN_NS={statistics.mean(admit_ns):.2f}")
    print(f"FAISAL_CONTEXT_WINDOW_PLAN_P95_NS={sorted(plan_ns)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_CONTEXT_WINDOW_VERIFY_P95_NS={sorted(verify_ns)[int(iterations * 0.95) - 1]}")
    print(f"FAISAL_CONTEXT_WINDOW_ADMIT_P95_NS={sorted(admit_ns)[int(iterations * 0.95) - 1]}")
    print("FAISAL_CONTEXT_WINDOW_BENCHMARK_OK")
    print("FAISAL_CONTEXT_WINDOW_BENCHMARK_SCOPE=local_python_context_receipts_not_model_context_quality_or_kernel_latency")


if __name__ == "__main__":
    main()
