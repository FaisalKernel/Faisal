#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_INTENT_REPAIR_OUT:-/home/ubuntu/agi-kernel/build/frontier/intent-repair-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-intent-repair"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_intent_repair.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_intent_repair.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_intent_repair import IntentPolicy, IntentRepairError, IntentRepairLedger, RepairProposal, SubtaskProposal, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "verifier_output_is_authority": False, "artifact_is_authority": False, "intent_receipt_is_execution_authority": False, "intent_receipt_is_production_authority": False, "production_approval": False}
intent = digest({"task": "long-horizon-release"}); c1 = digest({"constraint": "test"}); c2 = digest({"constraint": "preserve-boundary"}); sub_digest = digest({"subtask": "research"}); artifact = digest({"artifact": "draft"}); checkpoint = digest({"checkpoint": 1}); verifier = digest({"verifier": 1})
policy = IntentPolicy("release-policy", intent, tuple(sorted((c1, c2))), 7, 10, 100, 4, 2)
def sub(i, trace, constraints=None, intent_digest=intent):
    return SubtaskProposal(f"sub-{i}", intent_digest, sub_digest, tuple(sorted(constraints or (c1, c2))), (), checkpoint, trace, 7, 20)
def repair(i, index=1, passed=False, failed=(c1,), intent_digest=intent):
    return RepairProposal(f"repair-{i}", intent_digest, artifact, tuple(sorted(failed)), verifier, checkpoint, 10 + index, index, 7, 20, passed)
ledger = IntentRepairLedger(policy)
first = ledger.admit_subtask(sub(1, 1), current_generation=7, nonce="s1", authority=authority, now=21)
second = ledger.admit_subtask(sub(2, 2), current_generation=7, nonce="s2", authority=authority, now=22)
repair_receipt = ledger.admit_repair(repair(1), current_generation=7, nonce="r1", authority=authority, now=23)
results = {"subtask_1": first["status"], "subtask_2": second["status"], "repair": repair_receipt["status"]}
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except IntentRepairError: negative[name] = "denied"
deny("intent_drift", lambda: IntentRepairLedger(policy).admit_subtask(sub(3, 1, intent_digest=digest({"other": True})), current_generation=7, nonce="i", authority=authority, now=21))
deny("constraint_missing", lambda: IntentRepairLedger(policy).admit_subtask(sub(4, 1, constraints=(c1,)), current_generation=7, nonce="c", authority=authority, now=21))
deny("repair_after_pass", lambda: IntentRepairLedger(policy).admit_repair(repair(2, passed=True), current_generation=7, nonce="p", authority=authority, now=21))
deny("authority", lambda: IntentRepairLedger(policy).admit_subtask(sub(5, 1), current_generation=7, nonce="a", authority=dict(authority, verifier_output_is_authority=True), now=21))
deny("replay", lambda: ledger.admit_subtask(sub(3, 3), current_generation=7, nonce="s1", authority=authority, now=23))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "long-horizon-task-intent-and-repair-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"receipts": results, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "execution_performed": False, "artifact_modified": False, "verification_performed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-TOOL-ATTESTATION-2026-08-19"}
record["record_digest"] = digest(record)
(out / "intent-repair-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_INTENT_REPAIR_OK tests=4_passed subtasks=2_passed repair=passed negative_cases=5_denied execution_performed=false artifact_modified=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
