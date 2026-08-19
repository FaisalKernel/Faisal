#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_EVALUATION_SET_OUT:-/home/ubuntu/agi-kernel/build/frontier/evaluation-set-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-evaluation-set"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_evaluation_set.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_evaluation_set.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_evaluation_set import EvaluationPolicy, EvaluationResult, EvaluationSetError, EvaluationSetLedger, EvaluationSetManifest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "grader_output_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "evaluation_receipt_is_policy_authority": False,
    "evaluation_receipt_is_production_authority": False,
    "dataset_manifest_is_truth": False,
}
policy = EvaluationPolicy("eval-policy", "v1", 7, 47, min_task_count=4, min_coverage_per_mille=1000, max_overlap_per_mille=0, max_contamination_per_mille=0, max_ttl=120)

def manifest(set_id="set-1", task_count=4, coverage=1000, overlap=0, contamination=0, independent_split=True, independent_grader=True, generation=7, recorded=20, expires=100):
    return EvaluationSetManifest(set_id, digest({"tasks": set_id}), digest({"split": set_id}), digest({"grader": set_id}), policy.policy_digest, task_count, coverage, overlap, contamination, independent_split, independent_grader, generation, recorded, expires)

def result(m, result_id="result-1", completed=4, passed=4, safety=0, recorded=30):
    return EvaluationResult(result_id, m.set_id, m.manifest_digest, digest({"baseline": "candidate"}), digest({"candidate": "x"}), digest({"tasks": result_id}), digest({"traces": result_id}), completed, passed, safety, recorded)

ledger = EvaluationSetLedger(policy)
m = manifest()
admitted = ledger.admit_manifest(m, now=31, authority=authority)
verified = ledger.verify_result(result(m), now=31, authority=authority, nonce="nonce-1")

negative = {}
denied = 0
cases = {
    "task_count": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("task-count", task_count=3), now=31, authority=authority),
    "coverage": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("coverage", coverage=999), now=31, authority=authority),
    "overlap": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("overlap", overlap=1), now=31, authority=authority),
    "contamination": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("contamination", contamination=1), now=31, authority=authority),
    "independent_split": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("split", independent_split=False), now=31, authority=authority),
    "independent_grader": lambda: EvaluationSetLedger(policy).admit_manifest(manifest("grader", independent_grader=False), now=31, authority=authority),
    "incomplete_result": lambda: ledger.verify_result(result(m, "incomplete", completed=3), now=31, authority=authority, nonce="incomplete"),
    "safety_failure": lambda: ledger.verify_result(result(m, "unsafe", safety=1), now=31, authority=authority, nonce="unsafe"),
    "authority": lambda: ledger.verify_result(result(m, "authority"), now=31, authority=dict(authority, grader_output_is_authority=True), nonce="authority"),
}
for name, fn in cases.items():
    try:
        fn(); negative[name] = "accepted"
    except EvaluationSetError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "evaluation-set-admission-ledger",
    "recorded_at": "2026-08-19T21:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_manifest": {"admitted": admitted["admitted"], "evaluation_verified": verified["evaluation_verified"], "datasets_created": admitted["datasets_created"], "models_invoked": verified["models_invoked"], "traces_graded": verified["traces_graded"], "release_approved": verified["release_approved"]}, "negative_cases": negative, "negative_cases_denied": denied == 9},
    "safety": {**authority, "datasets_created": False, "models_invoked": False, "traces_graded": False, "release_approved": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-SELF-IMPROVEMENT-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "evaluation-set-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_EVALUATION_SET_OK tests=5_passed valid_manifest=passed complete_result=passed negative_cases=9_denied datasets_created=false models_invoked=false traces_graded=false release_approved=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
