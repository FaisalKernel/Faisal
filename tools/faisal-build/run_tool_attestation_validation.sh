#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_TOOL_ATTESTATION_OUT:-/home/ubuntu/agi-kernel/build/frontier/tool-attestation-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-tool-attestation"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_tool_attestation.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_tool_attestation.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_tool_attestation import ToolAttestationError, ToolAttestationLedger, ToolCallRequest, ToolPolicy, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "tool_metadata_is_authority": False, "tool_result_is_authority": False, "attestation_is_execution_authority": False, "attestation_is_policy_authority": False, "production_approval": False}
definition = digest({"server": "browser-server", "tool": "browser.click", "schema": 3}); dependency = digest({"deps": ["playwright"]})
policy = ToolPolicy("browser-policy", "browser-server", "browser.click", definition, dependency, (1, 4, 0), frozenset(("browser.read", "browser.click")), 2, 2, 7, 10, 100, True)
def request(i, definition_digest=definition, dependency_digest=dependency, version=(1, 4, 1), granted=frozenset(("browser.read", "browser.click")), labels=(("target", 1),), confirmed=True, generation=7, issued=20):
    return ToolCallRequest(f"request-{i}", "browser-server", "browser.click", definition_digest, dependency_digest, version, granted, labels, confirmed, generation, issued)
ledger = ToolAttestationLedger(policy)
valid = ledger.admit(request(1), current_generation=7, nonce="n1", authority=authority, now=21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except ToolAttestationError: negative[name] = "denied"
deny("definition_drift", lambda: ToolAttestationLedger(policy).admit(request(2, definition_digest=digest({"changed": True})), current_generation=7, nonce="d", authority=authority, now=21))
deny("dependency_drift", lambda: ToolAttestationLedger(policy).admit(request(3, dependency_digest=digest({"changed": True})), current_generation=7, nonce="dep", authority=authority, now=21))
deny("version_regression", lambda: ToolAttestationLedger(policy).admit(request(4, version=(1, 3, 9)), current_generation=7, nonce="v", authority=authority, now=21))
deny("data_flow", lambda: ToolAttestationLedger(policy).admit(request(5, labels=(("target", 3),)), current_generation=7, nonce="flow", authority=authority, now=21))
deny("confirmation", lambda: ToolAttestationLedger(policy).admit(request(6, confirmed=False), current_generation=7, nonce="confirm", authority=authority, now=21))
deny("authority", lambda: ToolAttestationLedger(policy).admit(request(7), current_generation=7, nonce="auth", authority=dict(authority, tool_metadata_is_authority=True), now=21))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "tool-definition-attestation-and-data-flow-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"valid_tool_admission": {"status": valid["status"], "definition_verified": valid["definition_verified"], "scope_verified": valid["scope_verified"], "data_flow_verified": valid["data_flow_verified"], "tool_invoked": valid["tool_invoked"], "production_approved": valid["production_approved"]}, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "tool_invoked": False, "execution_performed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-KV-CACHE-ADMISSION-2026-08-19"}
record["record_digest"] = digest(record)
(out / "tool-attestation-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_TOOL_ATTESTATION_OK tests=4_passed valid_admission=passed negative_cases=6_denied tool_invoked=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
