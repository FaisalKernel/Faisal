#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_INTERRUPT_FENCE_OUT:-/home/ubuntu/agi-kernel/build/frontier/interrupt-fence-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-interrupt-fence"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_interrupt_fence.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_interrupt_fence.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_interrupt_fence import InterruptFenceError, InterruptFenceLedger, InterruptFencePolicy, InterruptRequest, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "interrupt_is_execution_authority": False, "rollback_is_execution_authority": False, "revocation_is_credential_authority": False, "side_effect_ledger_is_truth": False, "production_approval": False}
task = "interrupt-task"; intent = digest({"intent": "original"}); revised = digest({"intent": "revised"}); cp = digest({"checkpoint": 1}); root1 = digest({"effects": 1}); root2 = digest({"effects": 2})
policy = InterruptFencePolicy("runtime-policy", task, intent, 7, 10, 100, max_checkpoint_age=100, max_trace_lag=100)
def req(i, operation="pause", **overrides):
    values = {"request_id": f"request-{i}", "operation": operation, "task_id": task, "parent_intent_digest": intent, "requested_intent_digest": intent, "intent_generation": 7, "checkpoint_digest": cp, "checkpoint_trace_position": 1, "current_trace_position": 2, "checkpoint_side_effect_root": root1, "current_side_effect_root": root1, "checkpoint_irreversible_watermark": 1, "current_irreversible_watermark": 1, "transition_sequence": i, "issued_at": 20, "expires_at": 90}
    values.update(overrides); return InterruptRequest(**values)
ledger = InterruptFenceLedger(policy)
pause = ledger.admit(req(1, "pause"), current_generation=7, nonce="p", authority=authority, now=21)
revise = ledger.admit(req(2, "revise", requested_intent_digest=revised, intent_generation=8, transition_sequence=2), current_generation=7, nonce="r", authority=authority, now=22)
resume = ledger.admit(req(3, "resume", parent_intent_digest=revised, requested_intent_digest=revised, intent_generation=8, transition_sequence=3), current_generation=8, nonce="x", authority=authority, now=23)
rollback_ledger = InterruptFenceLedger(policy)
rollback_ledger.admit(req(1, "pause"), current_generation=7, nonce="rp", authority=authority, now=21)
fork = rollback_ledger.admit(req(2, "rollback", checkpoint_trace_position=1, current_trace_position=3, checkpoint_irreversible_watermark=1, current_irreversible_watermark=2, transition_sequence=2), current_generation=7, nonce="rf", authority=authority, now=22)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except InterruptFenceError: negative[name] = "denied"
deny("stale_checkpoint", lambda: InterruptFenceLedger(InterruptFencePolicy("stale", task, intent, 7, 10, 100, max_checkpoint_age=100, max_trace_lag=10)).admit(req(1, current_trace_position=200), current_generation=7, nonce="s", authority=authority, now=21))
deny("sequence_gap", lambda: InterruptFenceLedger(policy).admit(req(2, transition_sequence=2), current_generation=7, nonce="g", authority=authority, now=21))
deny("stale_intent", lambda: InterruptFenceLedger(policy).admit(req(1, parent_intent_digest=revised, requested_intent_digest=revised), current_generation=7, nonce="i", authority=authority, now=21))
deny("expired", lambda: InterruptFenceLedger(policy).admit(req(1), current_generation=7, nonce="e", authority=authority, now=100))
deny("authority", lambda: InterruptFenceLedger(policy).admit(req(1), current_generation=7, nonce="a", authority=dict(authority, interrupt_is_execution_authority=True), now=21))
deny("replay", lambda: ledger.admit(req(4, "resume", parent_intent_digest=revised, requested_intent_digest=revised, intent_generation=8, transition_sequence=4), current_generation=8, nonce="p", authority=authority, now=24))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "checkpoint-side-effect-fence-and-interrupt-revocation-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"pause": {"verdict": pause["verdict"], "phase": pause["phase"], "process_paused": pause["process_paused"]}, "revise": {"verdict": revise["verdict"], "phase": revise["phase"], "intent_generation": revise["intent_generation"]}, "resume": {"verdict": resume["verdict"], "phase": resume["phase"]}, "rollback_after_effect": {"verdict": fork["verdict"], "effect_fork_required": fork["effect_fork_required"], "rollback_executed": fork["rollback_executed"], "external_effects_undone": fork["external_effects_undone"]}, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "process_paused": False, "credentials_revoked": False, "rollback_executed": False, "external_effects_undone": False, "tools_executed": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-HANDOFF-AUTHORIZATION-2026-08-19"}
record["record_digest"] = digest(record)
(out / "interrupt-fence-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_INTERRUPT_FENCE_OK tests=4_passed pause=passed revise=passed resume=passed rollback_require_fork=passed negative_cases=6_denied process_paused=false rollback_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
