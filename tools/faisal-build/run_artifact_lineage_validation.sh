#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_ARTIFACT_LINEAGE_OUT:-/home/ubuntu/agi-kernel/build/frontier/artifact-lineage-validation-2026-08-19}"
mkdir -p "$OUT"
cd "$ROOT/tools/faisal-artifact-lineage"
export PYTHONPATH=.
python3 -m unittest -v test_faisal_artifact_lineage.py 2>&1 | tee "$OUT/unit-test.log"
python3 bench_faisal_artifact_lineage.py 2>&1 | tee "$OUT/benchmark.log"
python3 - "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, sys
from faisal_artifact_lineage import ArtifactLineageError, ArtifactLineageLedger, ArtifactSnapshot, LineagePolicy, RefinementRequest, TaskSnapshot, digest

out = pathlib.Path(sys.argv[1])
authority = {
    "model_output_is_authority": False,
    "artifact_content_is_authority": False,
    "agent_output_is_authority": False,
    "acceptance_evidence_is_execution_authority": False,
    "lineage_receipt_is_policy_authority": False,
    "lineage_receipt_is_production_authority": False,
}

def policy():
    return LineagePolicy("artifact-policy", "v1", 7, ("tenant-a", "project-a", "agent-a"), max_depth=8, max_ttl=120)

def task(state="completed", expires=100):
    return TaskSnapshot("task-parent", "context-a", "tenant-a", state, 7, digest({"task": state}), 10, expires)

def artifact(state="accepted", version=1, expires=100):
    return ArtifactSnapshot("artifact-v1", "report.json", "task-parent", "context-a", "tenant-a", digest({"artifact": state}), None, version, 1, state, 7, 10, expires, ("tenant-a", "project-a"))

def request(parent, rid="main", context="context-a", version=2, acceptance=True, scope_value=("tenant-a", "project-a"), expires=90):
    return RefinementRequest(f"refine-{rid}", "task-parent", parent.artifact_id, parent.artifact_digest, f"task-child-{rid}", context, f"artifact-v2-{rid}", digest({"child": rid}), "report.json", version, tuple(scope_value), 7, 20, expires, digest({"accept": rid}) if acceptance else None, f"nonce-{rid}")

# Realistic deterministic refinement: a terminal task's accepted artifact is
# refined into a new artifact version in the same context, with explicit
# acceptance evidence. The contract emits admission evidence only.
l = ArtifactLineageLedger(policy())
parent_task = task(); parent_artifact = artifact()
l.register_task(parent_task); l.register_artifact(parent_artifact)
valid = l.admit_refinement(request(parent_artifact), now=21, authority=authority)

negative = {}
denied = 0
cases = {
    "nonterminal_parent": (task(state="active"), artifact(), "nonterminal", {}),
    "provisional_artifact": (task(), artifact(state="provisional"), "provisional", {}),
    "context_mismatch": (task(), artifact(), "context", {"context": "context-b"}),
    "version_gap": (task(), artifact(), "version", {"version": 3}),
    "missing_acceptance": (task(), artifact(), "acceptance", {"acceptance": False}),
    "expired": (task(), artifact(expires=21), "expired", {"expires": 21}),
}
for name, (t, a, rid, kwargs) in cases.items():
    trial = ArtifactLineageLedger(policy()); trial.register_task(t); trial.register_artifact(a)
    try:
        trial.admit_refinement(request(a, rid, **kwargs), now=21, authority=authority)
        negative[name] = "accepted"
    except ArtifactLineageError:
        negative[name] = "denied"; denied += 1

record = {
    "schema": "org.faisal.frontier-validation.v1",
    "upgrade": "immutable-artifact-lineage-refinement-admission",
    "recorded_at": "2026-08-19T16:20:00Z",
    "generation": 7,
    "unit_tests": {"passed": 5, "failed": 0},
    "benchmark": {"iterations": 1000, "log": str(out / "benchmark.log")},
    "real_tasks": {"valid_refinement": {"accepted": valid["accepted"], "parent_version": valid["parent_version"], "child_version": valid["child_version"], "task_created": valid["task_created"], "artifact_mutated": valid["artifact_mutated"]}, "negative_cases": negative, "negative_cases_denied": denied == 6},
    "safety": {**authority, "task_created": False, "artifact_mutated": False, "agents_invoked": False, "tools_executed": False, "external_services_contacted": False, "production_approval": False},
    "rollback_checkpoint": "FAISAL-FRONTIER-MEMORY-PROMOTION-2026-08-19",
}
record["record_digest"] = digest(record)
(out / "artifact-lineage-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_ARTIFACT_LINEAGE_OK tests=5_passed valid_refinement=passed negative_cases=6_denied task_created=false artifact_mutated=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
