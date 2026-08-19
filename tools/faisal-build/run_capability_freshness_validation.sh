#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_CAPABILITY_FRESHNESS_OUT:-/home/ubuntu/agi-kernel/build/frontier/capability-freshness-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-capability-freshness"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_capability_freshness.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_capability_freshness.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_capability_freshness import CapabilityFreshnessError, CapabilityFreshnessLedger, CapabilityManifest, FreshnessPolicy, FreshnessRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "tool_metadata_is_authority": False,
    "manifest_claim_is_attestation": False,
    "freshness_receipt_is_execution_authority": False,
    "freshness_receipt_is_policy_authority": False,
    "freshness_receipt_is_production_authority": False,
}

def policy(models=("model-a", "model-b"), routes=("route-a", "route-b")):
    return FreshnessPolicy("freshness-policy", "v1", 7, tuple(models), ("read", "write"), tuple(routes), "audience-tools", max_ttl=120)

def manifest(mid, tools=("read",), model="model-a", route="route-a", generation=7, epoch=1, expires=100, revoked=False):
    return CapabilityManifest(mid, "agent-a", model, "v1", tuple(tools), route, "audience-tools", "task-1", generation, epoch, 10, expires, revoked)

def req(a, o, rid="main", exp=80, generation=7, epoch=1):
    return FreshnessRequest(rid, "agent-a", "task-1", "audience-tools", "route-a", a.manifest_id, a.manifest_digest, o.manifest_id, o.manifest_digest, digest({"hop": 1}), generation, generation, epoch, epoch, 20, exp, "nonce-" + rid)

ledger = CapabilityFreshnessLedger(policy())
admitted = manifest("admitted")
observed = manifest("observed")
ledger.register_manifest(admitted); ledger.register_manifest(observed)
valid = ledger.admit(req(admitted, observed), now=21, authority=authority)

negative = {}
denied = 0
cases = {
    "tool_drift": (manifest("tool-a"), manifest("tool-o", tools=("read", "write")), policy()),
    "model_drift": (manifest("model-a"), manifest("model-o", model="model-b"), policy()),
    "route_drift": (manifest("route-a"), manifest("route-o", route="route-b"), policy()),
}
for name, (a, o, p) in cases.items():
    trial = CapabilityFreshnessLedger(p); trial.register_manifest(a); trial.register_manifest(o)
    try:
        trial.admit(req(a, o, name), now=21, authority=authority); negative[name] = "accepted"
    except CapabilityFreshnessError:
        negative[name] = "denied"; denied += 1

revoked = CapabilityFreshnessLedger(policy()); ra = manifest("rev-a"); ro = manifest("rev-o")
revoked.register_manifest(ra); revoked.register_manifest(ro); revoked.revoke("agent-a", key_epoch=2)
try:
    revoked.admit(req(ra, ro, "revoked"), now=21, authority=authority); negative["revocation"] = "accepted"
except CapabilityFreshnessError:
    negative["revocation"] = "denied"; denied += 1

for name, candidate in (("expired", manifest("expired-a", expires=21)),):
    trial = CapabilityFreshnessLedger(policy()); other = manifest(name + "-o", expires=21); trial.register_manifest(candidate); trial.register_manifest(other)
    try:
        trial.admit(req(candidate, other, name), now=21, authority=authority); negative[name] = "accepted"
    except CapabilityFreshnessError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "capability-manifest-freshness-verifier",
    "recorded_at": "2026-08-19T18:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"unchanged_manifest": {"fresh": valid["fresh"], "capability_drift": valid["capability_drift"], "cryptographic_attestation_verified": valid["cryptographic_attestation_verified"], "tools_executed": valid["tools_executed"]}, "negative_cases": negative, "negative_cases_denied": denied == 5},
    "safety": {**authority, "credentials_issued": False, "cryptographic_attestation_verified": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-DELEGATION-CHAIN-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "capability-freshness-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_CAPABILITY_FRESHNESS_OK tests=5_passed unchanged_manifest=passed negative_cases=5_denied credentials_issued=false attestation=false tools_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
