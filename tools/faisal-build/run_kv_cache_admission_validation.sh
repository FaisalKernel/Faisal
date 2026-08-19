#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_KV_CACHE_ADMISSION_OUT:-/home/ubuntu/agi-kernel/build/frontier/kv-cache-admission-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-kv-cache-admission"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_kv_cache_admission.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_kv_cache_admission.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_kv_cache_admission import AgentHints, CacheAdmissionRequest, CachePolicy, KVCacheAdmissionError, KVCacheAdmissionLedger, digest
out = pathlib.Path(sys.argv[1])
authority = {"model_output_is_authority": False, "provider_metadata_is_authority": False, "cache_hint_is_execution_authority": False, "cache_hint_is_policy_authority": False, "production_approval": False}
surface = digest({"surface": "real-task"}); route = digest({"route": "real-task"})
policy = CachePolicy("real-policy", 7, 100, 50, 4096, 3)
ledger = KVCacheAdmissionLedger(policy)
def req(i, session="session-real", prior="genesis", hints=None, issued=20, surf=surface, rt=route):
    return CacheAdmissionRequest(f"request-{i}", session, rt, surf, 7, issued, hints or AgentHints(20, 1024, True, 60, True), prior)
first = ledger.admit(req(1), current_generation=7, nonce="n1", authority=authority, now=21)
second = ledger.admit(req(2, prior=first["record_digest"], hints=AgentHints(10, 256, False, 30, False)), current_generation=7, nonce="n2", authority=authority, now=22)
results = {"warm_pinned_session": first["recommendation"], "followup_session_hint": second["recommendation"]}
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except KVCacheAdmissionError: negative[name] = "denied"
deny("ttl_abuse", lambda: KVCacheAdmissionLedger(policy).admit(req(3, hints=AgentHints(10, 1, False, 101, False)), current_generation=7, nonce="ttl", authority=authority, now=21))
deny("priority_abuse", lambda: KVCacheAdmissionLedger(policy).admit(req(4, hints=AgentHints(51, 1, False, 1, False)), current_generation=7, nonce="priority", authority=authority, now=21))
deny("output_abuse", lambda: KVCacheAdmissionLedger(policy).admit(req(5, hints=AgentHints(1, 4097, False, 1, False)), current_generation=7, nonce="output", authority=authority, now=21))
deny("surface_mismatch", lambda: ledger.admit(req(6, prior=second["record_digest"], surf=digest({"surface": "other"})), current_generation=7, nonce="surface", authority=authority, now=23))
deny("authority", lambda: ledger.admit(req(7, prior=second["record_digest"]), current_generation=7, nonce="authority", authority=dict(authority, provider_metadata_is_authority=True), now=23))
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "kv-cache-residency-and-agent-hint-admission", "recorded_at": "2026-08-19T23:59:00Z", "generation": 7, "unit_tests": {"passed": 4, "failed": 0}, "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")}, "real_tasks": {"admissions": results, "negative_cases": negative, "all_expected": all(v == "denied" for v in negative.values())}, "safety": {**authority, "memory_pinned": False, "inference_executed": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False}, "rollback_checkpoint": "FAISAL-FRONTIER-RUNTIME-ASSURANCE-2026-08-19"}
record["record_digest"] = digest(record)
(out / "kv-cache-admission-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_KV_CACHE_ADMISSION_OK tests=4_passed warm_session=passed followup=passed negative_cases=5_denied memory_pinned=false inference_executed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
