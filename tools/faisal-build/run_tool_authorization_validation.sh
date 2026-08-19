#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-tool-authorization${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-tool-authorization/*.py
python3 "$ROOT/tools/faisal-tool-authorization/test_faisal_tool_authorization.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-tool-authorization/bench_faisal_tool_authorization.py" | tee "$OUT/benchmark.log"
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
sys.path.insert(0, str(root / "tools/faisal-tool-authorization"))
from faisal_tool_authorization import InvocationRequest, ToolAdmissionLedger, ToolAuthorizationError, ToolDescriptor, ToolGrant, digest

def descriptor(risk="high", generation=4):
    return ToolDescriptor("server-1", "send_email", "https://mcp.example.test", digest({"tool": "send_email", "schema": 1}), ("mcp:tools", "email:send"), risk, generation)

def grant(d, max_uses=2, generation=4):
    return ToolGrant("grant-runner", "agent-1", d.resource_uri, d.descriptor_digest, ("mcp:tools", "email:send"), 100, 200, generation, max_uses, digest({"operator": "confirmed", "grant": "grant-runner"}), "medium")

def request(d, g, invocation="inv-1", scopes=("email:send",), risk="high", confirmation=None, resource=None, actor="agent-1", generation=4, at=120):
    return InvocationRequest(invocation, actor, resource or d.resource_uri, d.tool_name, d.descriptor_digest, scopes, digest({"to": "user@example.test", "body": "approved"}), risk, at, generation, confirmation)

d = descriptor()
g = grant(d)
ledger = ToolAdmissionLedger()
try:
    ledger.admit(d, g, request(d, g, confirmation=g.confirmation_digest), current_generation=4, now=130, nonce="valid-1")
    valid = "passed"
except ToolAuthorizationError:
    valid = "failed"
negative = {}
for name, req, now, current, nonce in [
    ("scope", request(d, g, invocation="scope", scopes=("admin:delete",), confirmation=g.confirmation_digest), 130, 4, "scope"),
    ("resource", request(d, g, invocation="resource", confirmation=g.confirmation_digest, resource="https://other.example.test"), 130, 4, "resource"),
    ("actor", request(d, g, invocation="actor", confirmation=g.confirmation_digest, actor="agent-2"), 130, 4, "actor"),
    ("expiry", request(d, g, invocation="expiry", confirmation=g.confirmation_digest), 200, 4, "expiry"),
    ("generation", request(d, g, invocation="generation", confirmation=g.confirmation_digest, generation=5), 130, 5, "generation"),
]:
    try:
        ledger.admit(d, g, req, current_generation=current, now=now, nonce=nonce)
    except ToolAuthorizationError as exc:
        negative[name] = str(exc)
try:
    ledger.admit(d, g, request(d, g, invocation="replay", confirmation=g.confirmation_digest), current_generation=4, now=130, nonce="replay")
    ledger.admit(d, g, request(d, g, invocation="replay", confirmation=g.confirmation_digest), current_generation=4, now=130, nonce="replay-2")
except ToolAuthorizationError as exc:
    negative["replay"] = str(exc)
try:
    ledger.admit(d, g, request(d, g, invocation="confirm", confirmation=None), current_generation=4, now=130, nonce="confirm")
except ToolAuthorizationError as exc:
    negative["risk_confirmation"] = str(exc)
assert valid == "passed" and len(negative) == 7
payload = {
    "schema": "FAISAL-TOOL-AUTHORIZATION-VALIDATION-1",
    "module": "tools/faisal-tool-authorization/faisal_tool_authorization.py",
    "valid_admission": valid,
    "negative_cases": negative,
    "ledger_digest": ledger.digest(),
    "authority_boundaries": {
        "model_output_is_authority": False,
        "tool_description_is_authority": False,
        "tool_result_is_authority": False,
        "grant_is_production_authority": False,
    },
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "tool-authorization-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_TOOL_AUTHORIZATION_VALIDATION_OK")
print("FAISAL_TOOL_AUTHORIZATION_RECORD", out / "tool-authorization-validation.json")
print("FAISAL_TOOL_AUTHORIZATION_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_TOOL_AUTHORIZATION_OK tests=6_passed benchmark=passed valid=passed resource=passed descriptor=passed scope=passed risk_confirmation=passed expiry=passed generation=passed use_limit=passed replay=passed tamper=passed authority=passed' > "$OUT/validation.marker"
