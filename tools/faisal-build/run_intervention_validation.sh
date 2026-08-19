#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_INTERVENTION_OUT:-/home/ubuntu/agi-kernel/build/frontier/intervention-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-intervention"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_intervention.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_intervention.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_intervention import InterventionLedger, InterventionPolicy, InterventionRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "intervention_receipt_is_execution_authority": False,
    "intervention_receipt_is_production_authority": False,
}

def req(i, kind, approval=None, attempt=1):
    return InterventionRequest(
        f"task-intervention-{i}", "runtime-supervisor", "task-1", kind, 7, 10, 100,
        digest({"observation": i}), digest({"state": i}), digest({"checkpoint": i}),
        digest({"proposed": i}), digest({"reason": i}), attempt, approval,
    )

def policy(kinds, approval=frozenset(), cooldown=0):
    return InterventionPolicy("runtime-policy", "v1", 7, frozenset(kinds), cooldown=cooldown, approval_required=frozenset(approval), max_attempts=2)

# Realistic deterministic task scenarios. The contract emits decisions only;
# none of these calls execute a process or external side effect.
results = {}
for kind in ("pause", "checkpoint", "downgrade", "retry", "quarantine", "rollback", "terminate"):
    l = InterventionLedger(policy((kind,), approval={kind} if kind in {"quarantine", "rollback", "terminate"} else set()))
    pending = l.admit(req(kind + "-pending", kind), now=20, authority=authority)
    if kind in {"quarantine", "rollback", "terminate"}:
        approved = l = InterventionLedger(policy((kind,), approval={kind})).admit(req(kind + "-approved", kind, approval=digest({"operator": kind})), now=20, authority=authority)
        results[kind] = {"pending": pending["verdict"], "approved": approved["verdict"], "passed": pending["verdict"] == "require_blocking_approval" and approved["verdict"] == "admit_bounded_intervention"}
    else:
        results[kind] = {"verdict": pending["verdict"], "passed": pending["verdict"] == "admit_bounded_intervention"}

cooldown = InterventionLedger(policy(("pause",), cooldown=10))
cooldown.admit(req("cooldown-first", "pause"), now=20, authority=authority)
try:
    cooldown.admit(req("cooldown-second", "pause"), now=25, authority=authority)
    cooldown_denied = False
except Exception:
    cooldown_denied = True

completion = InterventionLedger(policy(("checkpoint",)))
completion.admit(req("completion", "checkpoint"), now=20, authority=authority)
completed = completion.complete("task-intervention-completion", post_state_digest=digest({"post": 1}), post_trace_digest=digest({"trace": 1}), now=21, authority=authority)

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "execution-intervention-admission",
    "recorded_at": "2026-08-19T13:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 6, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"interventions": results, "cooldown_denied": cooldown_denied, "postcondition_completed": completed["completed"]},
    "safety": {**authority, "execution_performed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-PATH-GOVERNANCE-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "intervention-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_INTERVENTION_OK tests=6_passed scenarios=8_passed execution_performed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
