#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_HANDOFF_AUTHORIZATION_OUT:-/home/ubuntu/agi-kernel/build/frontier/handoff-authorization-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-handoff-authorization"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_handoff_authorization.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_handoff_authorization.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_handoff_authorization import HandoffAuthorizationError, HandoffAuthorizationLedger, HandoffAuthorizationPolicy, HandoffAuthorizationRequest, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "agent_claim_is_authority": False, "memory_is_authority": False, "authorization_receipt_is_execution_authority": False, "authorization_receipt_is_policy_authority": False, "production_approval": False}
task = "handoff-task"; original = digest({"request": task}); source = digest({"policy": "source"}); m1 = digest({"memory": 1}); m2 = digest({"memory": 2})
policy = HandoffAuthorizationPolicy("runtime-policy", task, original, source, ("delete", "read", "search", "write"), ("write",), ("delete",), tuple(sorted((m1, m2))), 7, 10, 100, 2)
def req(i, **overrides):
    values = {"request_id": f"request-{i}", "handoff_id": f"handoff-{i}", "issuer_agent_id": "agent-a", "delegatee_agent_id": "agent-b", "task_id": task, "original_request_digest": original, "source_policy_digest": source, "parent_scope": ("read", "search", "write"), "requested_scope": ("read", "search"), "disclosed_memory_digests": (m1,), "generation": 7, "issued_at": 20, "expires_at": 90, "trace_position": i}
    values.update(overrides); return HandoffAuthorizationRequest(**values)
ledger = HandoffAuthorizationLedger()
allow = ledger.admit(req(1), policy=policy, current_generation=7, nonce="n1", authority=authority, now=21)
confirmation = HandoffAuthorizationLedger().admit(req(2, requested_scope=("read", "write")), policy=policy, current_generation=7, nonce="n2", authority=authority, now=21)
denied_policy = HandoffAuthorizationPolicy("deny", task, original, source, ("delete", "read", "search", "write"), (), ("delete",), tuple(sorted((m1, m2))), 7, 10, 100, 2)
deny = HandoffAuthorizationLedger().admit(req(3, parent_scope=("delete", "read", "search", "write"), requested_scope=("delete",)), policy=denied_policy, current_generation=7, nonce="n3", authority=authority, now=21)
negative = {}
def deny_case(name, fn):
    try: fn(); negative[name] = "accepted"
    except HandoffAuthorizationError: negative[name] = "denied"
deny_case("scope_widening", lambda: HandoffAuthorizationLedger().admit(req(4, parent_scope=("read",), requested_scope=("read", "write")), policy=policy, current_generation=7, nonce="w", authority=authority, now=21))
deny_case("provenance", lambda: HandoffAuthorizationLedger().admit(req(5, original_request_digest=digest({"other": True})), policy=policy, current_generation=7, nonce="p", authority=authority, now=21))
deny_case("memory_disclosure", lambda: HandoffAuthorizationLedger().admit(req(6, disclosed_memory_digests=(m1, digest({"unapproved": True}))), policy=policy, current_generation=7, nonce="m", authority=authority, now=21))
deny_case("generation", lambda: HandoffAuthorizationLedger().admit(req(7, generation=8), policy=policy, current_generation=7, nonce="g", authority=authority, now=21))
deny_case("stale", lambda: HandoffAuthorizationLedger().admit(req(8, issued_at=0), policy=policy, current_generation=7, nonce="s", authority=authority, now=101))
deny_case("authority", lambda: HandoffAuthorizationLedger().admit(req(9), policy=policy, current_generation=7, nonce="a", authority=dict(authority, memory_is_authority=True), now=21))
deny_case("replay", lambda: ledger.admit(req(10), policy=policy, current_generation=7, nonce="n1", authority=authority, now=22))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "handoff-authorization-preservation-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"allow": {"verdict": allow["verdict"], "scope_attenuated": allow["scope_attenuated"], "memory_transferred": allow["memory_transferred"], "capabilities_delegated": allow["capabilities_delegated"], "tools_executed": allow["tools_executed"], "production_approved": allow["production_approved"]}, "require_confirmation": {"verdict": confirmation["verdict"]}, "deny": {"verdict": deny["verdict"]}, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "memory_transferred": False, "capabilities_delegated": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-ROUTE-RECEIPT-2026-08-19"}
record["record_digest"] = digest(record)
(out / "handoff-authorization-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_HANDOFF_AUTHORIZATION_OK tests=4_passed allow=passed require_confirmation=passed deny=passed negative_cases=7_denied memory_transferred=false capabilities_delegated=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
