#!/usr/bin/env python3
from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_route_budget import BudgetRequest, BudgetWindow, RouteBudgetLedger, Usage

ROUTE = "sha256:" + "1" * 64


def sample(iterations: int = 1000) -> dict[str, float | int | str]:
    windows = (
        BudgetWindow("hour", 10**9, 10**8, 10**8, 10000),
        BudgetWindow("day", 10**10, 10**9, 10**9, 20000),
    )
    reserve_ns: list[int] = []
    settle_ns: list[int] = []
    release_ns: list[int] = []
    for i in range(iterations):
        ledger = RouteBudgetLedger(windows, max_reservations=4)
        request = BudgetRequest(f"r-{i}", f"req-{i}", ROUTE, 7, 40, 300, 100, 100)
        start = time.perf_counter_ns()
        reservation = ledger.reserve(request, current_generation=7, nonce=f"a-{i}")
        reserve_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        ledger.settle(reservation, Usage(35, 280, 90, 110), current_generation=7, nonce=f"s-{i}")
        settle_ns.append(time.perf_counter_ns() - start)
        ledger2 = RouteBudgetLedger(windows, max_reservations=4)
        reservation2 = ledger2.reserve(request, current_generation=7, nonce=f"ar-{i}")
        start = time.perf_counter_ns()
        ledger2.release(reservation2, now=101, current_generation=7, nonce=f"rel-{i}")
        release_ns.append(time.perf_counter_ns() - start)
    return {
        "iterations": iterations,
        "reserve_mean_ns": round(statistics.mean(reserve_ns), 2),
        "settle_mean_ns": round(statistics.mean(settle_ns), 2),
        "release_mean_ns": round(statistics.mean(release_ns), 2),
        "reserve_p95_ns": sorted(reserve_ns)[int(iterations * 0.95) - 1],
        "settle_p95_ns": sorted(settle_ns)[int(iterations * 0.95) - 1],
        "release_p95_ns": sorted(release_ns)[int(iterations * 0.95) - 1],
        "scope": "local_python_budget_receipts_not_provider_network_model_or_kernel_latency",
    }


if __name__ == "__main__":
    result = sample()
    print("FAISAL_ROUTE_BUDGET_BENCHMARK_ITERATIONS=" + str(result["iterations"]))
    for key in ("reserve_mean_ns", "settle_mean_ns", "release_mean_ns", "reserve_p95_ns", "settle_p95_ns", "release_p95_ns"):
        print(f"FAISAL_ROUTE_BUDGET_{key.upper()}={result[key]}")
    print("FAISAL_ROUTE_BUDGET_BENCHMARK_OK")
    print("FAISAL_ROUTE_BUDGET_BENCHMARK_SCOPE=" + str(result["scope"]))
