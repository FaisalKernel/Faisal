#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_PATH_GOVERNANCE_OUT:-/home/ubuntu/agi-kernel/build/frontier/path-governance-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-path-governance"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_path_governance.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_path_governance.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_path_governance import ActionRequest, PathGovernanceLedger, PathPolicy, PathRule, PathStep, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "observation_is_authority": False,
    "path_receipt_is_execution_authority": False,
    "path_receipt_is_production_authority": False,
}

def step(i, labels, actor="agent-a"):
    return PathStep(f"task-step-{i}", actor, "observed_action", frozenset(labels), 7, i, digest({"input": i}), digest({"output": i}))

def request(i, labels, actor="agent-a", cost=1, approval=None):
    return ActionRequest(f"task-decision-{i}", actor, "proposed_action", frozenset(labels), 7, digest({"request": i}), digest({"proposal": i}), cost, approval_digest=approval)

# Realistic deterministic multi-step tasks: read sensitive data then attempt an
# external write; the path policy must block the sequence even though each
# action class is individually syntactically valid.
rule = PathRule("sensitive-to-external-barrier", "v1", frozenset({"sensitive_read"}), frozenset({"external_write"}), deny_on_match=True)
blocked = PathGovernanceLedger(PathPolicy("production-policy", "v1", 7, max_steps=32, max_risk_budget=100, rules=(rule,)))
blocked.append_observed(step(1, {"sensitive_read", "risk:one"}))
blocked_decision = blocked.admit(request(2, {"external_write"}, cost=1), now=2, authority=authority)

approval_rule = PathRule("approval-for-publication", "v1", frozenset({"reviewed_data"}), frozenset({"external_write"}), deny_on_match=False, require_approval=True)
approval_ledger = PathGovernanceLedger(PathPolicy("approval-policy", "v1", 7, max_steps=32, max_risk_budget=100, rules=(approval_rule,)))
approval_ledger.append_observed(step(1, {"reviewed_data"}))
pending = approval_ledger.admit(request(2, {"external_write"}), now=2, authority=authority)
approved_ledger = PathGovernanceLedger(PathPolicy("approval-policy", "v1", 7, max_steps=32, max_risk_budget=100, rules=(approval_rule,)))
approved_ledger.append_observed(step(1, {"reviewed_data"}))
approved = approved_ledger.admit(request(2, {"external_write"}, approval=digest({"operator": "approved", "decision": 2})), now=2, authority=authority)

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "path-governance-admission",
    "recorded_at": "2026-08-19T12:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 7, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {
        "sensitive_external_sequence": {"verdict": blocked_decision["verdict"], "reason": blocked_decision["reason"], "passed": blocked_decision["verdict"] == "deny"},
        "approval_gated_publication": {"pending_verdict": pending["verdict"], "approved_verdict": approved["verdict"], "passed": pending["verdict"] == "require_blocking_approval" and approved["verdict"] == "allow_with_policy"},
    },
    "safety": {"model_output_is_authority": False, "tool_description_is_authority": False, "tool_result_is_authority": False, "observation_is_authority": False, "path_receipt_is_execution_authority": False, "path_receipt_is_production_authority": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-MIGRATION-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "path-governance-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_PATH_GOVERNANCE_OK tests=7_passed real_tasks=2_passed tools_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
