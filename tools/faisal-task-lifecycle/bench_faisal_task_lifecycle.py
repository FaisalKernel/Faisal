#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_task_lifecycle import TaskEvent, TaskLifecycleAdmission, TaskPolicy


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def handoff(generation: int = 7) -> dict:
    request = {"source_agent": "planner", "target_agent": "executor", "generation": generation, "model_authority": False, "provider_authority": False}
    return {"schema": "org.faisal.handoff-receipt.v1", "status": "admitted", "handoff_digest": digest(request), "request": request}


def sample(iterations: int = 1000) -> dict[str, float | int | str]:
    policy = TaskPolicy(max_ttl_seconds=300)
    admission_ns: list[int] = []
    event_ns: list[int] = []
    terminal_ns: list[int] = []
    for i in range(iterations):
        control = TaskLifecycleAdmission(max_tasks=4)
        start = time.perf_counter_ns()
        record = control.admit(handoff(), task_id=f"task-{i}", now=100, current_generation=7, expires_at=200, policy=policy, nonce=f"a-{i}")
        admission_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        record = control.append(record, TaskEvent("run", "running", 101, 1, 0.2), now=101, current_generation=7, policy=policy, nonce=f"r-{i}")
        checkpoint = digest({"task": i, "state": "paused"})
        record = control.append(record, TaskEvent("pause", "paused", 102, 2, 0.5, checkpoint_digest=checkpoint), now=102, current_generation=7, policy=policy, nonce=f"p-{i}")
        record = control.append(record, TaskEvent("resume", "running", 103, 3, 0.5), now=103, current_generation=7, policy=policy, nonce=f"s-{i}")
        event_ns.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        result = digest({"task": i, "result": "verified"})
        record = control.append(record, TaskEvent("complete", "completed", 104, 4, 1.0, result_digest=result), now=104, current_generation=7, policy=policy, nonce=f"c-{i}")
        terminal_ns.append(time.perf_counter_ns() - start)
        control.verify(record, policy=policy)
    return {
        "iterations": iterations,
        "admission_mean_ns": round(statistics.mean(admission_ns), 2),
        "event_sequence_mean_ns": round(statistics.mean(event_ns), 2),
        "terminal_completion_mean_ns": round(statistics.mean(terminal_ns), 2),
        "admission_p95_ns": sorted(admission_ns)[int(iterations * 0.95) - 1],
        "event_sequence_p95_ns": sorted(event_ns)[int(iterations * 0.95) - 1],
        "terminal_completion_p95_ns": sorted(terminal_ns)[int(iterations * 0.95) - 1],
        "scope": "local_python_lifecycle_receipts_not_remote_agent_network_model_or_kernel_latency",
    }


if __name__ == "__main__":
    result = sample()
    print("FAISAL_TASK_LIFECYCLE_BENCHMARK_ITERATIONS=" + str(result["iterations"]))
    for key in ("admission_mean_ns", "event_sequence_mean_ns", "terminal_completion_mean_ns", "admission_p95_ns", "event_sequence_p95_ns", "terminal_completion_p95_ns"):
        print(f"FAISAL_TASK_LIFECYCLE_{key.upper()}={result[key]}")
    print("FAISAL_TASK_LIFECYCLE_BENCHMARK_OK")
    print("FAISAL_TASK_LIFECYCLE_BENCHMARK_SCOPE=" + str(result["scope"]))
