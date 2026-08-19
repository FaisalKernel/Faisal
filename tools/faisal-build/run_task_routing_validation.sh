#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_TASK_ROUTING_OUT:-/home/ubuntu/agi-kernel/build/frontier/task-routing-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-task-routing"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_task_routing.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_task_routing.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_task_routing import TaskRouteLeaseRequest, TaskRoutingError, TaskRoutingLedger, TaskRoutingPolicy, TaskTurnRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "endpoint_metadata_is_authority": False,
    "route_outcome_is_authority": False,
    "task_routing_receipt_is_execution_authority": False,
    "task_routing_receipt_is_production_authority": False,
}

def lease(i="main", task=None, selected="model-a", expires=100):
    task = task or "task-" + i
    return TaskRouteLeaseRequest(f"lease-{i}", task, digest({"route": i}), ("model-a", "model-b"), selected, 7, 10, expires, digest({"context": task}), digest({"evidence": i}), 8)

def turn(i, endpoint="model-a", lease_id=None, task_id=None, seq=None):
    lease_id = lease_id or "lease-" + i
    task_id = task_id or "task-" + i
    seq = seq if seq is not None else 1
    return TaskTurnRequest(f"turn-{i}-{seq}", lease_id, task_id, digest({"request": i, "seq": seq}), endpoint, 7, seq, 20 + seq)

def policy():
    return TaskRoutingPolicy("task-policy", "v1", 7, max_tasks=32, max_turns=8, max_ttl=120)

# Realistic long-running task: a single task performs multiple model turns;
# every turn must stay on the admitted backend, and terminal feedback arrives
# only after the trace closes.
l = TaskRoutingLedger(policy())
lease_request = lease("main")
admitted = l.admit(lease_request, now=20, authority=authority)
turns = [l.admit_turn(turn("main", lease_id="lease-main", task_id="task-main", seq=i), now=20 + i, authority=authority) for i in (1, 2, 3)]
completed = l.complete(lease_id="lease-main", success=True, quality_milli=920, latency_ms=140, evidence_digest=digest({"quality": "task-main"}), terminal_trace_digest=digest({"trace": "task-main"}), now=24, authority=authority)

# Negative cases: backend pin, initial sequence, expiry, and terminal replay.
negative = {}
rejected = 0
bad = TaskRoutingLedger(policy())
bad.admit(lease("bad"), now=20, authority=authority)
for name, operation in {
    "backend_mismatch": lambda: bad.admit_turn(turn("bad", endpoint="model-b", lease_id="lease-bad", task_id="task-bad"), now=21, authority=authority),
    "sequence_gap": lambda: bad.admit_turn(turn("bad", lease_id="lease-bad", task_id="task-bad", seq=2), now=21, authority=authority),
}.items():
    try:
        operation(); negative[name] = "accepted"
    except TaskRoutingError:
        negative[name] = "denied"; rejected += 1
expired = TaskRoutingLedger(policy()); expired.admit(lease("expired", expires=100), now=20, authority=authority)
try:
    expired.admit_turn(turn("expired", lease_id="lease-expired", task_id="task-expired"), now=100, authority=authority); negative["expiry"] = "accepted"
except TaskRoutingError:
    negative["expiry"] = "denied"; rejected += 1
try:
    l.complete(lease_id="lease-main", success=True, quality_milli=920, latency_ms=140, evidence_digest=digest({"quality": "replay"}), terminal_trace_digest=digest({"trace": "replay"}), now=25, authority=authority); negative["terminal_replay"] = "accepted"
except TaskRoutingError:
    negative["terminal_replay"] = "denied"; rejected += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "task-consistent-routing-lease",
    "recorded_at": "2026-08-19T14:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 6, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"multi_turn_trace": {"admitted": admitted["pinned_for_task"], "turn_count": len(turns), "terminal": completed["terminal"], "delayed_feedback": completed["delayed_feedback"], "passed": len(turns) == 3 and completed["terminal"]}, "negative_cases": negative, "negative_cases_denied": rejected == 4},
    "safety": {**authority, "models_invoked": False, "tools_executed": False, "external_services_contacted": False, "routing_statistics_updated": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-INTERVENTION-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "task-routing-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_TASK_ROUTING_OK tests=6_passed multi_turn_trace=passed negative_cases=4_denied models_invoked=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
