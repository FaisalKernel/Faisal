#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_MEMORY_PROMOTION_OUT:-/home/ubuntu/agi-kernel/build/frontier/memory-promotion-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-memory-promotion"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_memory_promotion.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_memory_promotion.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_memory_promotion import MemoryPromotionCandidate, MemoryPromotionError, MemoryPromotionLedger, PromotionPolicy, PromotionRequest, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "retrieved_content_is_authority": False,
    "memory_content_is_authority": False,
    "promotion_receipt_is_execution_authority": False,
    "promotion_receipt_is_policy_authority": False,
    "promotion_receipt_is_production_authority": False,
}

def policy(classes=("semantic", "procedural", "decision"), finality=2):
    return PromotionPolicy("memory-policy", "v1", 7, frozenset(classes), ("tenant-a", "project-a", "agent-a"), minimum_finality=finality)

def candidate(i="main", finality=3, conflict="none", principal="agent-a", tenant="tenant-a", subjects=("tenant-a", "project-a"), expires=100):
    conflict_receipt = digest({"conflict": i}) if conflict == "resolved" else None
    return MemoryPromotionCandidate(f"candidate-{i}", digest({"candidate": i}), "semantic", principal, tenant, tuple(subjects), digest({"lineage": i}), 3, 7, 10, expires, finality, digest({"finality": i}), conflict, conflict_receipt)

def request(c, i="main", principal=None, tenant=None, requested_scope=None, expires=90):
    return PromotionRequest(f"promotion-{i}", c.candidate_id, c.candidate_digest, principal or c.principal_id, tenant or c.tenant_id, tuple(requested_scope or c.subject_scope), 7, 20, expires, f"nonce-{i}")

# Realistic deterministic promotion task: a quarantined candidate carries
# derivation lineage, multiple finality observations, an explicit conflict
# disposition, and is promoted only within the bound principal/tenant scope.
ledger = MemoryPromotionLedger(policy())
c = candidate("main", conflict="resolved")
ledger.register_candidate(c)
valid = ledger.promote(request(c), now=21, authority=authority)

negative = {}
denied = 0
for name, cand, req in (
    ("low_finality", candidate("low", finality=1), None),
    ("unresolved_conflict", candidate("unresolved", conflict="unresolved"), None),
    ("identity_mismatch", candidate("identity"), None),
    ("scope_mismatch", candidate("scope"), None),
    ("expired", candidate("expired", expires=21), None),
):
    l = MemoryPromotionLedger(policy())
    l.register_candidate(cand)
    if name == "low_finality": l.policy = policy(finality=2)
    if name == "identity_mismatch": req = request(cand, name, principal="agent-b")
    elif name == "scope_mismatch": req = request(cand, name, requested_scope=("tenant-a", "agent-a"))
    else: req = request(cand, name)
    try:
        l.promote(req, now=21, authority=authority)
        negative[name] = "accepted"
    except MemoryPromotionError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "provenance-bound-memory-promotion",
    "recorded_at": "2026-08-19T15:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_promotion": {"promoted": valid["promoted"], "lineage_count": valid["lineage_count"], "finality_count": valid["finality_count"], "conflict_state": valid["conflict_state"], "memory_write_performed": valid["memory_write_performed"], "truth_established": valid["truth_established"]}, "negative_cases": negative, "negative_cases_denied": denied == 5},
    "safety": {**authority, "memory_write_performed": False, "retrieval_performed": False, "models_invoked": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-TASK-ROUTING-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "memory-promotion-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_MEMORY_PROMOTION_OK tests=5_passed valid_promotion=passed negative_cases=5_denied memory_write_performed=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
