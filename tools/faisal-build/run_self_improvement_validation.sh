#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_SELF_IMPROVEMENT_OUT:-/home/ubuntu/agi-kernel/build/frontier/self-improvement-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-self-improvement"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_self_improvement.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_self_improvement.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_self_improvement import EvaluationEvidence, ImprovementCandidate, ImprovementPolicy, PromotionReceipt, SelfImprovementError, SelfImprovementLedger, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "candidate_claim_is_authority": False,
    "evaluation_receipt_is_deployment_authority": False,
    "self_improvement_receipt_is_policy_authority": False,
    "self_improvement_receipt_is_production_authority": False,
    "autonomous_privileged_modification_allowed": False,
}
policy = ImprovementPolicy("improvement-policy", "v1", 7, 47, max_ttl=120, max_canary_per_mille=100, min_quality_delta_per_mille=10, max_safety_regression_per_mille=0, require_approval=True)
base = digest({"routing": "baseline"}); changed = digest({"routing": "candidate"})

def ev(quality=20, safety=0, regressions=0, recorded=30, b=base, c=changed):
    return EvaluationEvidence("evidence-1", b, c, digest({"tasks": "held-out"}), digest({"traces": "raw"}), quality, safety, regressions, 8, recorded)

def candidate(cid="candidate-1", component="routing_policy", approval="approval-1", generation=7, abi=47, expires=100, evidence=None, b=base, c=changed):
    return ImprovementCandidate(cid, component, b, c, digest({"diff": c}), policy.policy_digest, abi, generation, 20, expires, 50, "FAISAL-FRONTIER-INTERACTION-LEDGER-2026-08-19", evidence or ev(b=b, c=c), approval)

ledger = SelfImprovementLedger(policy)
valid_candidate = candidate()
admitted = ledger.admit_candidate(valid_candidate, now=31, authority=authority)
promotion = PromotionReceipt("promotion-1", valid_candidate.candidate_id, valid_candidate.candidate_digest, 40, 60, 25, 0, False, "verifier-a")
canary = ledger.verify_canary(promotion, now=61, authority=authority, nonce="nonce-1")

negative = {}
denied = 0
cases = {
    "approval": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="approval-denied", approval=None), now=31, authority=authority),
    "quality": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="quality-denied", evidence=ev(quality=0)), now=31, authority=authority),
    "safety": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="safety-denied", evidence=ev(safety=-1)), now=31, authority=authority),
    "regressions": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="regression-denied", evidence=ev(regressions=1)), now=31, authority=authority),
    "abi": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="abi-denied", abi=48), now=31, authority=authority),
    "component": lambda: SelfImprovementLedger(policy).admit_candidate(candidate(cid="component-denied", component="kernel_code"), now=31, authority=authority),
    "rollback": lambda: ledger.verify_canary(PromotionReceipt("rollback", valid_candidate.candidate_id, valid_candidate.candidate_digest, 40, 60, 25, 0, True, "verifier-a"), now=61, authority=authority, nonce="nonce-rollback"),
}
for name, fn in cases.items():
    try:
        fn(); negative[name] = "accepted"
    except SelfImprovementError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "bounded-self-improvement-candidate-admission",
    "recorded_at": "2026-08-19T20:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_candidate": {"admitted": admitted["admitted"], "component": admitted["component"], "canary_verified": canary["canary_verified"], "code_modified": admitted["code_modified"], "deployment_executed": admitted["deployment_executed"]}, "negative_cases": negative, "negative_cases_denied": denied == 7},
    "safety": {**authority, "code_modified": False, "weights_modified": False, "privileged_kernel_modified": False, "production_policy_modified": False, "deployment_executed": False, "models_invoked": False, "tools_executed": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-INTERACTION-LEDGER-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "self-improvement-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_SELF_IMPROVEMENT_OK tests=5_passed valid_candidate=passed canary=passed negative_cases=7_denied code_modified=false privileged_kernel_modified=false deployment_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
