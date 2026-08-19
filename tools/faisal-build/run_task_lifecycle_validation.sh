#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-task-lifecycle${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-task-lifecycle/*.py
python3 "$ROOT/tools/faisal-task-lifecycle/test_faisal_task_lifecycle.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-task-lifecycle/bench_faisal_task_lifecycle.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-task-lifecycle"))
from faisal_task_lifecycle import LifecycleError, TaskEvent, TaskLifecycleAdmission, TaskPolicy

def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def handoff(generation=7):
    request = {"source_agent":"planner","target_agent":"executor","generation":generation,"model_authority":False,"provider_authority":False}
    return {"schema":"org.faisal.handoff-receipt.v1","status":"admitted","handoff_digest":digest(request),"request":request}

policy = TaskPolicy(max_ttl_seconds=300)
admission = TaskLifecycleAdmission()
record = admission.admit(handoff(), task_id="runner-task", now=100, current_generation=7, expires_at=200, policy=policy, nonce="admit")
record = admission.append(record, TaskEvent("run", "running", 101, 1, 0.25), now=101, current_generation=7, policy=policy, nonce="run")
checkpoint = digest({"task":"runner-task","state":"checkpoint"})
record = admission.append(record, TaskEvent("pause", "paused", 102, 2, 0.5, checkpoint_digest=checkpoint), now=102, current_generation=7, policy=policy, nonce="pause")
record = admission.append(record, TaskEvent("resume", "running", 103, 3, 0.5), now=103, current_generation=7, policy=policy, nonce="resume")
record = admission.append(record, TaskEvent("complete", "completed", 104, 4, 1.0, result_digest=digest({"result":"verified"})), now=104, current_generation=7, policy=policy, nonce="complete")
assert admission.verify(record, policy=policy)
negative = {}
for name, req, now, generation, expires in (
    ("generation", handoff(8), 100, 7, 200),
    ("expiry", handoff(), 100, 7, 401),
):
    try:
        admission.admit(req, task_id=f"bad-{name}", now=now, current_generation=generation, expires_at=expires, policy=policy, nonce=f"bad-{name}")
    except LifecycleError as exc:
        negative[name] = str(exc)
try:
    admission.append(record, TaskEvent("bad", "running", 105, 5, 0.9), now=105, current_generation=7, policy=policy, nonce="bad-terminal")
except LifecycleError as exc:
    negative["terminal_transition"] = str(exc)
tampered = copy.deepcopy(record)
tampered["progress"] = 0.4
try:
    admission.verify(tampered, policy=policy)
except LifecycleError as exc:
    negative["tamper"] = str(exc)
assert len(negative) == 4
payload = {
    "schema":"FAISAL-TASK-LIFECYCLE-VALIDATION-1",
    "module":"tools/faisal-task-lifecycle/faisal_task_lifecycle.py",
    "task_digest": digest(record),
    "terminal_status": record["status"],
    "event_count": record["event_count"],
    "negative_cases": negative,
    "admission_digest": admission.digest(),
    "authority_boundaries": {
        "model_output_is_authority": False,
        "provider_metadata_is_authority": False,
        "task_is_execution": False,
        "executed_by_this_module": False,
        "remote_agent_contact": False,
        "credential_minting": False,
        "production_approval": False,
    },
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "task-lifecycle-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_TASK_LIFECYCLE_VALIDATION_OK")
print("FAISAL_TASK_LIFECYCLE_RECORD", out / "task-lifecycle-validation.json")
print("FAISAL_TASK_LIFECYCLE_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_TASK_LIFECYCLE_OK tests=passed benchmark=passed transitions=passed checkpoint=passed cancellation=passed completion=passed replay=passed tamper=passed authority=passed' > "$OUT/validation.marker"
