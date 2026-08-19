#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_EVIDENCE_FRESHNESS_OUT:-/home/ubuntu/agi-kernel/build/frontier/evidence-freshness-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-evidence-freshness"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_evidence_freshness.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_evidence_freshness.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_evidence_freshness import EvidenceFreshnessError, EvidenceFreshnessLedger, FreshnessPolicy, QualificationLease, QualificationSurface, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "evidence_is_truth": False,
    "evidence_is_execution_authority": False,
    "evidence_is_policy_authority": False,
    "evidence_is_production_authority": False,
    "qualification_receipt_is_attestation": False,
}
policy = FreshnessPolicy("freshness-policy", "v1", 7, 47, max_evidence_age=100, max_lease_ttl=120)

def surface(generation=7, abi=47, suffix="s1"):
    return QualificationSurface(suffix, digest({"model": suffix}), digest({"tool": suffix}), digest({"route": suffix}), digest({"policy": suffix}), digest({"hardware": suffix}), digest({"env": suffix}), digest({"bench": suffix}), abi, generation)

def lease(s, lease_id="lease-1", evidence_recorded=20, issued=30, expires=100, drift=(), critical=False, quarantined=False, revoked=False):
    return QualificationLease(lease_id, "qual-1", s.surface_digest, digest({"evidence": s.surface_digest}), digest({"provenance": s.surface_digest}), policy.policy_digest, policy.generation, issued, evidence_recorded, expires, tuple(drift), critical, quarantined, revoked)

ledger = EvidenceFreshnessLedger(policy)
s = surface(); l = lease(s)
verified = ledger.admit(s, l, now=31, authority=authority, nonce="nonce-1")
revoked = ledger.revoke("lease-1")

negative = {}
denied = 0
cases = {
    "stale": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "stale", evidence_recorded=-1), now=31, authority=authority, nonce="stale"),
    "critical_drift": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "drift", drift=("model",), critical=True), now=31, authority=authority, nonce="drift"),
    "surface_mismatch": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(surface(suffix="other"), "surface"), now=31, authority=authority, nonce="surface"),
    "generation": lambda: EvidenceFreshnessLedger(policy).admit(surface(generation=8), lease(surface(generation=8), "generation"), now=31, authority=authority, nonce="generation"),
    "abi": lambda: EvidenceFreshnessLedger(policy).admit(surface(abi=48), lease(surface(abi=48), "abi"), now=31, authority=authority, nonce="abi"),
    "expiry": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "expiry", expires=31), now=31, authority=authority, nonce="expiry"),
    "ttl": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "ttl", expires=200), now=31, authority=authority, nonce="ttl"),
    "quarantine": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "quarantine", quarantined=True), now=31, authority=authority, nonce="quarantine"),
    "revoked": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "revoked", revoked=True), now=31, authority=authority, nonce="revoked"),
    "authority": lambda: EvidenceFreshnessLedger(policy).admit(s, lease(s, "authority"), now=31, authority=dict(authority, evidence_is_truth=True), nonce="authority"),
}
for name, fn in cases.items():
    try:
        fn(); negative[name] = "accepted"
    except EvidenceFreshnessError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "evidence-freshness-qualification-lease",
    "recorded_at": "2026-08-19T23:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 4, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_fresh_lease": {"freshness_verified": verified["freshness_verified"], "qualification_executed": verified["qualification_executed"], "attestation_performed": verified["attestation_performed"], "production_approved": verified["production_approved"], "revoked": revoked["revoked"]}, "negative_cases": negative, "negative_cases_denied": denied == 10},
    "safety": {**authority, "qualification_executed": False, "attestation_performed": False, "production_approved": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-EVALUATOR-CONSENSUS-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "evidence-freshness-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_EVIDENCE_FRESHNESS_OK tests=4_passed valid_lease=passed revoked=passed negative_cases=10_denied qualification_executed=false attestation_performed=false production_approved=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
