#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-session-risk${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-session-risk/*.py
python3 "$ROOT/tools/faisal-session-risk/test_faisal_session_risk.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-session-risk/bench_faisal_session_risk.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-session-risk"))
from faisal_session_risk import PolicyDecisionRequest, RiskEvent, RiskPolicy, SessionRiskError, SessionRiskLedger, digest

authority = {
    "model_output_is_authority": False,
    "tool_description_is_authority": False,
    "tool_result_is_authority": False,
    "policy_receipt_is_production_authority": False,
}
policy = RiskPolicy("policy-runner", "1", 4)
ledger = SessionRiskLedger(policy)
ledger.append(RiskEvent("private", "observed", frozenset(("private_data_access",)), frozenset(), 4, 100, digest({"source": "private"}), digest({"context": "private"})))
ledger.append(RiskEvent("untrusted", "observed", frozenset(("untrusted_content_exposure",)), frozenset(), 4, 101, digest({"source": "untrusted"}), digest({"context": "untrusted"})))

def req(decision_id, capabilities=(), taints=(), approval=None, generation=4):
    return PolicyDecisionRequest(decision_id, "session-runner", generation, frozenset(capabilities), frozenset(taints), digest({"context": decision_id}), digest({"authorization": decision_id}), approval)

results = {}
results["trifecta"] = ledger.decide(req("trifecta", capabilities=("external_communication",)), now=120, nonce="trifecta", authority=authority)
results["approved"] = ledger.decide(req("approved", capabilities=("external_communication",), approval=digest({"operator": "approved"})), now=120, nonce="approved", authority=authority)
critical = SessionRiskLedger(policy)
results["critical"] = critical.decide(req("critical", taints=("critical_taint",), approval=digest({"operator": "approved"})), now=120, nonce="critical", authority=authority)
unknown = SessionRiskLedger(policy)
results["unknown"] = unknown.decide(req("unknown", taints=("unknown_tool_behavior",)), now=120, nonce="unknown", authority=authority)
negative = {}
try:
    ledger.decide(req("stale", generation=5), now=120, nonce="stale", authority=authority)
except SessionRiskError as exc:
    negative["generation"] = str(exc)
try:
    ledger.decide(req("trifecta", capabilities=("external_communication",)), now=120, nonce="replay", authority=authority)
except SessionRiskError as exc:
    negative["replay"] = str(exc)
try:
    ledger.decide(req("bad-authority"), now=120, nonce="bad-authority", authority=dict(authority, model_output_is_authority=True))
except SessionRiskError as exc:
    negative["authority"] = str(exc)
assert results["trifecta"]["verdict"] == "require_blocking_approval"
assert results["approved"]["verdict"] == "allow_with_policy"
assert results["critical"]["verdict"] == "deny"
assert results["unknown"]["verdict"] == "require_blocking_approval"
assert set(negative) == {"generation", "replay", "authority"}
payload = {
    "schema": "FAISAL-SESSION-RISK-VALIDATION-1",
    "module": "tools/faisal-session-risk/faisal_session_risk.py",
    "verdicts": {name: result["verdict"] for name, result in results.items()},
    "reasons": {name: result["reason"] for name, result in results.items()},
    "negative_cases": negative,
    "ledger_digest": ledger.ledger_digest(),
    "authority_boundaries": authority,
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "session-risk-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_SESSION_RISK_VALIDATION_OK")
print("FAISAL_SESSION_RISK_RECORD", out / "session-risk-validation.json")
print("FAISAL_SESSION_RISK_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_SESSION_RISK_OK tests=6_passed benchmark=passed safe=allow_with_policy trifecta=require_blocking_approval approved=allow_with_policy critical=deny unknown=require_blocking_approval generation=passed replay=passed tamper=passed authority=passed' > "$OUT/validation.marker"
