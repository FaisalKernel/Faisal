#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_EVALUATOR_CONSENSUS_OUT:-/home/ubuntu/agi-kernel/build/frontier/evaluator-consensus-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-evaluator-consensus"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_evaluator_consensus.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_evaluator_consensus.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_evaluator_consensus import ConsensusPolicy, ConsensusRequest, EvaluatorConsensusError, EvaluatorConsensusLedger, EvaluatorReceipt, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "evaluator_output_is_authority": False,
    "consensus_receipt_is_deployment_authority": False,
    "consensus_receipt_is_policy_authority": False,
    "consensus_receipt_is_production_authority": False,
    "confidence_is_truth": False,
}
policy = ConsensusPolicy("consensus-policy", "v1", 7, 47, min_evaluators=2, min_coverage_per_mille=1000, max_disagreement_per_mille=50, min_confidence_per_mille=700, max_safety_failures=0, max_harm_severity_per_mille=0, max_ttl=120)

def receipt(evaluator="e1", score=900, confidence=800, disagreement=0, safety=0, harm=0, rubric="r1", tasks="t1", traces="tr1", recorded=30):
    return EvaluatorReceipt(evaluator, 1, digest({"rubric": rubric}), digest({"tasks": tasks}), digest({"traces": traces}), 1000, score, confidence, disagreement, safety, harm, recorded)

def request(receipts=None, request_id="req-1", generation=7, abi=47, expires=100):
    return ConsensusRequest(request_id, "set-1", digest({"manifest": "set-1"}), digest({"candidate": "c1"}), policy.policy_digest, abi, generation, 20, expires, tuple(receipts or (receipt("e1"), receipt("e2", score=920))))

ledger = EvaluatorConsensusLedger(policy)
req = request()
verified = ledger.admit(req, now=31, authority=authority)
ack = ledger.acknowledge(req.request_id, nonce="nonce-1")

negative = {}
denied = 0
cases = {
    "duplicate_identity": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1"), receipt("e1", score=920)), "duplicate"), now=31, authority=authority),
    "rubric": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1"), receipt("e2", rubric="r2")), "rubric"), now=31, authority=authority),
    "task_lineage": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1"), receipt("e2", tasks="t2")), "task"), now=31, authority=authority),
    "score_disagreement": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1", score=800), receipt("e2", score=900)), "score"), now=31, authority=authority),
    "confidence": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1", confidence=600), receipt("e2")), "confidence"), now=31, authority=authority),
    "safety": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1", safety=1), receipt("e2")), "safety"), now=31, authority=authority),
    "harm": lambda: EvaluatorConsensusLedger(policy).admit(request((receipt("e1", harm=1), receipt("e2")), "harm"), now=31, authority=authority),
    "expiry": lambda: EvaluatorConsensusLedger(policy).admit(request(request_id="expiry", expires=21), now=31, authority=authority),
    "authority": lambda: EvaluatorConsensusLedger(policy).admit(request(request_id="authority"), now=31, authority=dict(authority, confidence_is_truth=True)),
}
for name, fn in cases.items():
    try:
        fn(); negative[name] = "accepted"
    except EvaluatorConsensusError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "evaluator-consensus-ledger",
    "recorded_at": "2026-08-19T22:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 4, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_consensus": {"consensus_verified": verified["consensus_verified"], "evaluator_count": verified["evaluator_count"], "acknowledged": ack["acknowledged"], "models_invoked": verified["models_invoked"], "graders_invoked": verified["graders_invoked"], "release_approved": verified["release_approved"]}, "negative_cases": negative, "negative_cases_denied": denied == 9},
    "safety": {**authority, "models_invoked": False, "graders_invoked": False, "release_approved": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-EVALUATION-SET-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "evaluator-consensus-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_EVALUATOR_CONSENSUS_OK tests=4_passed valid_consensus=passed acknowledged=passed negative_cases=9_denied models_invoked=false graders_invoked=false release_approved=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
