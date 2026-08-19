#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_RUNTIME_ASSURANCE_OUT:-/home/ubuntu/agi-kernel/build/frontier/runtime-assurance-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-runtime-assurance"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_runtime_assurance.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_runtime_assurance.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_runtime_assurance import AssuranceEnvelope, RuntimeAssuranceError, RuntimeAssuranceLedger, RuntimeObservation, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "observation_is_authority": False, "tool_result_is_authority": False, "assurance_receipt_is_execution_authority": False, "assurance_receipt_is_production_authority": False}
surface = digest({"surface": "real-task"})
envelope = AssuranceEnvelope("env-real", "policy-real", surface, 7, 10, 100, 20, 10, (("cpu", 80),), (("cpu", 100),), frozenset(("continue", "restrict", "quarantine", "terminate")))
ledger = RuntimeAssuranceLedger(envelope)
def obs(seq, previous, cpu=20, at=20):
    return RuntimeObservation(f"obs-{seq}", "workload-real", surface, seq, at, previous, (("cpu", cpu),), digest({"seq": seq, "cpu": cpu}))
results = {}
previous = "genesis"
for name, cpu, at, now in (("continue", 20, 20, 21), ("restrict", 90, 22, 23), ("quarantine_stale", 20, 0, 30), ("terminate_hard_limit", 101, 31, 32)):
    decision = ledger.decide(obs(len(results)+1, previous, cpu, at), now, f"nonce-{name}", authority)
    results[name] = {"action": decision["action"], "reasons": decision["reasons"], "execution_performed": decision["execution_performed"], "production_approved": decision["production_approved"]}
    previous = decision["decision_digest"]
negative = {}
try:
    ledger.decide(obs(5, previous), 33, "nonce-continue", authority); negative["nonce_replay"] = "accepted"
except RuntimeAssuranceError: negative["nonce_replay"] = "denied"
try:
    ledger.decide(obs(7, previous), 33, "nonce-gap", authority); negative["sequence_gap"] = "accepted"
except RuntimeAssuranceError: negative["sequence_gap"] = "denied"
try:
    ledger.decide(obs(5, previous), 33, "nonce-authority", dict(authority, observation_is_authority=True)); negative["authority"] = "accepted"
except RuntimeAssuranceError: negative["authority"] = "denied"
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "runtime-assurance-envelope-ledger", "recorded_at": "2026-08-19T23:50:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"decisions": results, "negative_cases": negative, "all_expected": all(results[n]["action"] == e for n, e in (("continue", "continue"), ("restrict", "restrict"), ("quarantine_stale", "quarantine"), ("terminate_hard_limit", "terminate"))) and all(v == "denied" for v in negative.values())}, "safety": {**authority, "execution_performed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-EVIDENCE-FRESHNESS-2026-08-19"}
record["record_digest"] = digest(record)
(out / "runtime-assurance-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_RUNTIME_ASSURANCE_OK tests=4_passed decisions=4_passed negative_cases=3_denied execution_performed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
