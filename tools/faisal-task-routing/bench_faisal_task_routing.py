from __future__ import annotations

import statistics
import time

from faisal_task_routing import TaskRouteLeaseRequest, TaskRoutingLedger, TaskRoutingPolicy, TaskTurnRequest, digest

AUTHORITY = {
    "model_output_is_authority": False,
    "endpoint_metadata_is_authority": False,
    "route_outcome_is_authority": False,
    "task_routing_receipt_is_execution_authority": False,
    "task_routing_receipt_is_production_authority": False,
}


def make_lease(i: int) -> TaskRouteLeaseRequest:
    return TaskRouteLeaseRequest(f"l-{i}", f"task-{i}", digest({"route": i}), ("model-a", "model-b"), "model-a", 7, 10, 100, digest({"context": i}), digest({"evidence": i}), 8)


def make_turn(i: int, seq: int, lease_id: str, task_id: str) -> TaskTurnRequest:
    return TaskTurnRequest(f"turn-{i}-{seq}", lease_id, task_id, digest({"request": (i, seq)}), "model-a", 7, seq, 20 + seq)


def measure(fn, count=1000):
    samples = []
    for i in range(count):
        started = time.perf_counter_ns()
        fn(i)
        samples.append(time.perf_counter_ns() - started)
    return statistics.mean(samples), statistics.quantiles(samples, n=20)[18]


def main():
    def baseline(i):
        return make_lease(i)

    def admit(i):
        l = TaskRoutingLedger(TaskRoutingPolicy("p", "v1", 7))
        return l.admit(make_lease(i), now=20, authority=AUTHORITY)

    def turn(i):
        l = TaskRoutingLedger(TaskRoutingPolicy("p", "v1", 7))
        lease = make_lease(i)
        l.admit(lease, now=20, authority=AUTHORITY)
        return l.admit_turn(make_turn(i, 1, lease.lease_id, lease.task_id), now=21, authority=AUTHORITY)

    def complete(i):
        l = TaskRoutingLedger(TaskRoutingPolicy("p", "v1", 7))
        lease = make_lease(i)
        l.admit(lease, now=20, authority=AUTHORITY)
        l.admit_turn(make_turn(i, 1, lease.lease_id, lease.task_id), now=21, authority=AUTHORITY)
        return l.complete(lease_id=lease.lease_id, success=True, quality_milli=900, latency_ms=100, evidence_digest=digest({"e": i}), terminal_trace_digest=digest({"t": i}), now=22, authority=AUTHORITY)

    for name, fn in (("baseline_ungoverned", baseline), ("lease_admit", admit), ("sticky_turn", turn), ("terminal_complete", complete)):
        mean, p95 = measure(fn)
        print(f"FAISAL_TASK_ROUTING_BENCHMARK name={name} iterations=1000 mean_ns={mean:.2f} p95_ns={p95:.2f}")


if __name__ == "__main__":
    main()
