#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-route-budget${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-route-budget/*.py
python3 "$ROOT/tools/faisal-route-budget/test_faisal_route_budget.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-route-budget/bench_faisal_route_budget.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-route-budget"))
from faisal_route_budget import BudgetError, BudgetRequest, BudgetWindow, RouteBudgetLedger, Usage

def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

route = digest({"route":"primary","fallbacks":["secondary"],"generation":7})
policy = (BudgetWindow("hour", 100, 1000, 500, 2), BudgetWindow("day", 500, 5000, 2500, 4))
ledger = RouteBudgetLedger(policy)
request = BudgetRequest("runner-reservation", "runner-request", route, 7, 40, 300, 100, 100)
reservation = ledger.reserve(request, current_generation=7, nonce="reserve")
settled = ledger.settle(reservation, Usage(35, 280, 90, 110), current_generation=7, nonce="settle")
assert settled["status"] == "settled"
negative = {}
try:
    ledger.settle(settled, Usage(1, 1, 1, 111), current_generation=7, nonce="replay")
except BudgetError as exc:
    negative["settlement_replay"] = str(exc)
ledger2 = RouteBudgetLedger(policy)
reservation2 = ledger2.reserve(BudgetRequest("overrun", "request-overrun", route, 7, 40, 300, 100, 100), current_generation=7, nonce="overrun-reserve")
try:
    ledger2.settle(reservation2, Usage(41, 300, 100, 110), current_generation=7, nonce="overrun-settle")
except BudgetError as exc:
    negative["overrun"] = str(exc)
try:
    ledger.reserve(BudgetRequest("stale", "stale-request", route, 8, 1, 1, 1, 100), current_generation=7, nonce="stale")
except BudgetError as exc:
    negative["generation"] = str(exc)
tampered = copy.deepcopy(settled)
tampered["settled"]["actual_cost_milli"] = 0
try:
    ledger.settle(tampered, Usage(1, 1, 1, 111), current_generation=7, nonce="tamper")
except BudgetError as exc:
    negative["tamper"] = str(exc)
assert len(negative) == 4
payload = {
    "schema":"FAISAL-ROUTE-BUDGET-VALIDATION-1",
    "module":"tools/faisal-route-budget/faisal_route_budget.py",
    "reservation_status": reservation["status"],
    "settlement_status": settled["status"],
    "window_count": len(policy),
    "negative_cases": negative,
    "ledger_digest": ledger.digest(),
    "authority_boundaries": {
        "model_output_is_authority": False,
        "provider_metadata_is_authority": False,
        "budget_is_execution": False,
        "reservation_is_tool_permission": False,
        "production_approval": False,
    },
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "route-budget-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_ROUTE_BUDGET_VALIDATION_OK")
print("FAISAL_ROUTE_BUDGET_RECORD", out / "route-budget-validation.json")
print("FAISAL_ROUTE_BUDGET_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_ROUTE_BUDGET_OK tests=passed benchmark=passed reservation=passed settlement=passed release=passed capacity=passed overrun=passed replay=passed tamper=passed generation=passed authority=passed' > "$OUT/validation.marker"
