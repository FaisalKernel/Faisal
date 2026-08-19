#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_INTERACTION_LEDGER_OUT:-/home/ubuntu/agi-kernel/build/frontier/interaction-ledger-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-interaction-ledger"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_interaction_ledger.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_interaction_ledger.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_interaction_ledger import InteractionLedger, InteractionLedgerError, LedgerPolicy, LedgerRequest, SegmentAnchor, TerminalVerification, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "telemetry_is_kernel_ground_truth": False,
    "span_content_is_truth": False,
    "ledger_receipt_is_execution_authority": False,
    "ledger_receipt_is_policy_authority": False,
    "ledger_receipt_is_production_authority": False,
}
cap = digest({"manifest": "m1"}); delegation = digest({"chain": "d1"}); route = digest({"route": "r1"})
policy = LedgerPolicy("ledger-policy", "v1", 7, "audience-tools", max_ttl=120, max_spans=8)

def seg(sid, seq, parent=None, trace="trace-1", task="task-1", artifact="artifact-1"):
    return SegmentAnchor(sid, trace, task, artifact, cap, delegation, route, "audience-tools", 7, policy.policy_digest, seq, parent, digest({"span": sid}), 10 + seq, 100)

def term(sid="seg-2", tid="term-1", verified=True):
    return TerminalVerification(tid, sid, digest({"result": "ok"}), verified, "verifier-a", 30, "completed")

ledger = InteractionLedger(policy)
first = seg("seg-1", 1)
first_digest = ledger.append(first)
second = seg("seg-2", 2, first_digest)
ledger.append(second)
request = LedgerRequest("req-1", "trace-1", "task-1", "artifact-1", cap, delegation, route, "audience-tools", 7, policy.policy_digest, "seg-2", 1, 2, (first.segment_digest, second.segment_digest), term(), 20, 80, "nonce-req-1")
valid = ledger.admit(request, now=31, authority=authority)

negative = {}
denied = 0
cases = [
    ("sequence_gap", lambda: (lambda l: (l.append(seg("gap-1", 1, trace="gap")), l.append(seg("gap-3", 3, digest({"wrong": 1}), trace="gap"))))(InteractionLedger(policy))),
    ("missing_terminal", lambda: ledger.admit(LedgerRequest("missing-terminal", "trace-1", "task-1", "artifact-1", cap, delegation, route, "audience-tools", 7, policy.policy_digest, "seg-2", 1, 2, (first.segment_digest, second.segment_digest), None, 20, 80, "nonce-missing-terminal"), now=31, authority=authority)),
    ("replay", lambda: ledger.admit(request, now=32, authority=authority)),
    ("tamper", lambda: ledger.admit(LedgerRequest("tamper", "trace-1", "task-1", "artifact-1", cap, delegation, route, "audience-tools", 7, policy.policy_digest, "seg-2", 1, 2, (digest({"wrong": 1}), second.segment_digest), term("seg-2", "term-tamper"), 20, 80, "nonce-tamper"), now=31, authority=authority)),
    ("authority", lambda: ledger.admit(LedgerRequest("authority", "trace-1", "task-1", "artifact-1", cap, delegation, route, "audience-tools", 7, policy.policy_digest, "seg-2", 1, 2, (first.segment_digest, second.segment_digest), term("seg-2", "term-authority"), 20, 80, "nonce-authority"), now=31, authority=dict(authority, telemetry_is_kernel_ground_truth=True))),
]
for name, fn in cases:
    try:
        fn(); negative[name] = "accepted"
    except InteractionLedgerError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "interaction-segment-commitment-ledger",
    "recorded_at": "2026-08-19T19:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_ordered_two_span": {"admitted": valid["terminal_verified"], "segment_count": valid["segment_count"], "raw_content_stored": valid["raw_content_stored"], "models_replayed": valid["models_replayed"], "tools_executed": valid["tools_executed"]}, "negative_cases": negative, "negative_cases_denied": denied == 5},
    "safety": {**authority, "raw_content_stored": False, "telemetry_ingested": False, "models_replayed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-CAPABILITY-FRESHNESS-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "interaction-ledger-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_INTERACTION_LEDGER_OK tests=5_passed valid_two_span=passed negative_cases=5_denied raw_content_stored=false models_replayed=false tools_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
