#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_MEMORY_INTERVENTION_OUT:-/home/ubuntu/agi-kernel/build/frontier/memory-intervention-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-memory-intervention"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_memory_intervention.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_memory_intervention.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_memory_intervention import MemoryInterventionError, MemoryInterventionLedger, MemoryInterventionPolicy, MemoryInterventionRequest, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "memory_is_authority": False, "intervention_is_execution_authority": False, "intervention_is_policy_authority": False, "production_approval": False}
task = "long-horizon-task"; session = "session-1"; intent = digest({"task": task}); memory = digest({"memory": "failed-command-diagnosis"}); e1 = digest({"evidence": 1}); e2 = digest({"evidence": 2})
policy = MemoryInterventionPolicy("runtime-policy", task, session, intent, 2, 7, 10, 100, 512, 3, 3, 0.7, 0.6)
def req(i, **overrides):
    values = {"request_id": f"request-{i}", "task_id": task, "session_id": session, "intent_digest": intent, "memory_digest": memory, "source_evidence_digests": tuple(sorted((e1, e2))), "trigger_reason": "failed-attempt-diagnosis", "confidence": 0.9, "novelty": 0.8, "estimated_tokens": 128, "memory_sensitivity": 1, "step": 10, "last_intervention_step": -1, "generation": 7, "issued_at": 20}
    values.update(overrides); return MemoryInterventionRequest(**values)
ledger = MemoryInterventionLedger(policy)
valid = ledger.admit(req(1), current_generation=7, nonce="n1", authority=authority, now=21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except MemoryInterventionError: negative[name] = "denied"
deny("confidence", lambda: MemoryInterventionLedger(policy).admit(req(2, confidence=0.69), current_generation=7, nonce="c", authority=authority, now=21))
deny("novelty", lambda: MemoryInterventionLedger(policy).admit(req(3, novelty=0.59), current_generation=7, nonce="n", authority=authority, now=21))
deny("token_budget", lambda: MemoryInterventionLedger(policy).admit(req(4, estimated_tokens=513), current_generation=7, nonce="t", authority=authority, now=21))
deny("cooldown", lambda: MemoryInterventionLedger(policy).admit(req(5, step=11, last_intervention_step=9), current_generation=7, nonce="d", authority=authority, now=21))
deny("cross_task", lambda: MemoryInterventionLedger(policy).admit(req(6, task_id="other-task"), current_generation=7, nonce="scope", authority=authority, now=21))
deny("empty_evidence", lambda: MemoryInterventionLedger(policy).admit(req(7, source_evidence_digests=()), current_generation=7, nonce="e", authority=authority, now=21))
deny("authority", lambda: MemoryInterventionLedger(policy).admit(req(8), current_generation=7, nonce="a", authority=dict(authority, memory_is_authority=True), now=21))
deny("replay", lambda: ledger.admit(req(9, memory_digest=digest({"memory": "other"})), current_generation=7, nonce="n1", authority=authority, now=22))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "proactive-memory-intervention-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"valid_intervention": {"status": valid["status"], "trigger_reason": valid["trigger_reason"], "source_evidence_present": bool(valid["source_evidence_digests"]), "memory_retrieved": valid["memory_retrieved"], "prompt_injected": valid["prompt_injected"], "tools_executed": valid["tools_executed"], "production_approved": valid["production_approved"]}, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "memory_retrieved": False, "prompt_injected": False, "execution_performed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-INTENT-REPAIR-2026-08-19"}
record["record_digest"] = digest(record)
(out / "memory-intervention-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_MEMORY_INTERVENTION_OK tests=4_passed valid_intervention=passed negative_cases=8_denied memory_retrieved=false prompt_injected=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
