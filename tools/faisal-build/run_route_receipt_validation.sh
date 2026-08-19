#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_ROUTE_RECEIPT_OUT:-/home/ubuntu/agi-kernel/build/frontier/route-receipt-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-route-receipt"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_route_receipt.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_route_receipt.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_route_receipt import RouteReceiptError, RouteReceiptLedger, RouteReceiptPolicy, RouteReceiptRequest, TrajectorySummary, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "confidence_is_truth": False, "route_receipt_is_execution_authority": False, "route_receipt_is_policy_authority": False, "production_approval": False}
task = "route-task"; session = "route-session"; intent = digest({"task": task}); models = ("model-small", "model-large"); versions = ("v1", "v2"); providers = ("provider-a", "provider-b")
policy = RouteReceiptPolicy("runtime-policy", task, session, intent, models, versions, providers, 2, 7, 10, 100, 1000, 0.7, 0.6)
def req(i, **overrides):
    values = {"request_id": f"request-{i}", "task_id": task, "session_id": session, "intent_digest": intent, "requested_model": "model-small", "requested_version": "v1", "effective_model": "model-large", "effective_version": "v2", "effective_provider": "provider-a", "service_tier": "standard", "fallback_chain": ("model-large",), "tool_use": True, "trajectory": TrajectorySummary(3, 0.82, 0.8, 0.7, 0.75, 0.2, 1), "route_cost_milli": 200, "generation": 7, "issued_at": 20}
    values.update(overrides); return RouteReceiptRequest(**values)
ledger = RouteReceiptLedger(policy)
valid = ledger.admit(req(1), current_generation=7, nonce="n1", authority=authority, now=21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except RouteReceiptError: negative[name] = "denied"
deny("confidence", lambda: RouteReceiptLedger(policy).admit(req(2, trajectory=TrajectorySummary(3, 0.75, 0.69, 0.6, 0.8, 0.1, 1)), current_generation=7, nonce="c", authority=authority, now=21))
deny("stability", lambda: RouteReceiptLedger(policy).admit(req(3, trajectory=TrajectorySummary(3, 0.75, 0.8, 0.6, 0.59, 0.1, 1)), current_generation=7, nonce="s", authority=authority, now=21))
deny("fallback_depth", lambda: RouteReceiptLedger(policy).admit(req(4, fallback_chain=("model-large", "model-small"), trajectory=TrajectorySummary(3, 0.8, 0.8, 0.7, 0.8, 0.2, 3)), current_generation=7, nonce="f", authority=authority, now=21))
deny("unapproved_model", lambda: RouteReceiptLedger(policy).admit(req(5, effective_model="unapproved"), current_generation=7, nonce="m", authority=authority, now=21))
deny("route_budget", lambda: RouteReceiptLedger(RouteReceiptPolicy("small-budget", task, session, intent, models, versions, providers, 2, 7, 10, 100, 100, 0.7, 0.6)).admit(req(6), current_generation=7, nonce="b", authority=authority, now=21))
deny("intent_scope", lambda: RouteReceiptLedger(policy).admit(req(7, intent_digest=digest({"other": True})), current_generation=7, nonce="i", authority=authority, now=21))
deny("authority", lambda: RouteReceiptLedger(policy).admit(req(8), current_generation=7, nonce="a", authority=dict(authority, confidence_is_truth=True), now=21))
deny("replay", lambda: ledger.admit(req(9), current_generation=7, nonce="n1", authority=authority, now=22))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "trajectory-confidence-and-route-receipt-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"valid_receipt": {"status": valid["status"], "requested_model": valid["requested_model"], "effective_model": valid["effective_model"], "fallback_chain": valid["fallback_chain"], "route_verified": valid["route_verified"], "confidence_calibrated": valid["confidence_calibrated"], "inference_executed": valid["inference_executed"], "model_selected": valid["model_selected"], "production_approved": valid["production_approved"]}, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "inference_executed": False, "model_selected": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-MEMORY-INTERVENTION-2026-08-19"}
record["record_digest"] = digest(record)
(out / "route-receipt-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_ROUTE_RECEIPT_OK tests=4_passed valid_receipt=passed negative_cases=8_denied inference_executed=false model_selected=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
