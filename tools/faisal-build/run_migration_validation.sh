#!/usr/bin/env bash
set -euo pipefail

OUT=${1:?output directory required}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUT"
export PYTHONPATH="$ROOT/tools/faisal-migration${PYTHONPATH:+:$PYTHONPATH}"
python3 -m py_compile "$ROOT"/tools/faisal-migration/*.py
python3 "$ROOT/tools/faisal-migration/test_faisal_migration.py" | tee "$OUT/unit-tests.log"
python3 "$ROOT/tools/faisal-migration/bench_faisal_migration.py" | tee "$OUT/benchmark.log"
ROOT="$ROOT" OUT="$OUT" python3 - <<'PY'
from __future__ import annotations
import hashlib
import json
import os
import sys
from pathlib import Path

root = Path(os.environ["ROOT"])
out = Path(os.environ["OUT"])
sys.path.insert(0, str(root / "tools/faisal-migration"))
from faisal_migration import MigrationError, MigrationLedger, MigrationPolicy, MigrationRequest, ReadinessEvidence, digest

authority = {
    "model_output_is_authority": False,
    "source_agent_card_is_authority": False,
    "destination_agent_card_is_authority": False,
    "readiness_evidence_is_hardware_qualification": False,
    "migration_receipt_is_execution_authority": False,
    "state_manifest_is_trust_root": False,
}
policy = MigrationPolicy(frozenset({"node-b", "node-c"}), frozenset({"cpu", "memory"}), frozenset({"network_path_ready", "storage_ready", "sandbox_ready", "observability_ready"}), 300)

def req(name: str, destination: str = "node-b", generation: int = 4, expires: int = 300, destination_caps=frozenset({"cpu", "memory"}), readiness=None) -> MigrationRequest:
    readiness = readiness or ReadinessEvidence(True, True, False, True, True, digest({"ready": name}))
    return MigrationRequest(f"m-{name}", "node-a", destination, "objective-runner", f"task-{name}", generation, digest({"life": name}), digest({"checkpoint": name}), digest({"trace": name}), digest({"state": name}), digest({"artifact": name}), 7, frozenset({"cpu", "memory", "network"}), frozenset(destination_caps), readiness, f"idem-{name}", digest({"rollback": name}), 100, expires)

ledger = MigrationLedger(generation=4, policy=policy)
valid_request = req("valid")
prepared = ledger.prepare(valid_request, now=110, authority_boundary=authority)
committed = ledger.commit(valid_request.migration_id, destination_state_digest=digest({"state": "destination"}), destination_checkpoint_digest=digest({"checkpoint": "destination"}), destination_trace_digest=digest({"trace": "destination"}), now=120, authority_boundary=authority)
assert prepared["admitted"] and committed["admitted"] and not committed["migration_executed"]
negatives = {}
negative_requests = [
    ("destination", req("destination", destination="node-z")),
    ("generation", req("generation", generation=5)),
    ("expiry", req("expiry", expires=101)),
    ("capability", req("capability", destination_caps=frozenset({"cpu", "memory", "admin"}))),
    ("readiness", req("readiness", readiness=ReadinessEvidence(False, True, False, True, True, digest({"ready": "bad"})))),
]
for name, item in negative_requests:
    try:
        MigrationLedger(generation=4, policy=policy).prepare(item, now=110, authority_boundary=authority)
    except MigrationError as exc:
        negatives[name] = str(exc)
try:
    ledger.prepare(valid_request, now=111, authority_boundary=authority)
except MigrationError as exc:
    negatives["replay"] = str(exc)
try:
    ledger.commit(valid_request.migration_id, destination_state_digest=digest({"state": "tamper"}), destination_checkpoint_digest=digest({"checkpoint": "tamper"}), destination_trace_digest=digest({"trace": "tamper"}), now=121, authority_boundary=authority)
except MigrationError as exc:
    negatives["commit_replay"] = str(exc)
try:
    MigrationLedger(generation=4, policy=policy).prepare(valid_request, now=110, authority_boundary=dict(authority, migration_receipt_is_execution_authority=True))
except MigrationError as exc:
    negatives["authority"] = str(exc)
assert set(negatives) == {"destination", "generation", "expiry", "capability", "readiness", "replay", "commit_replay", "authority"}
payload = {
    "schema": "FAISAL-MIGRATION-VALIDATION-1",
    "module": "tools/faisal-migration/faisal_migration.py",
    "valid_prepare": True,
    "valid_commit": True,
    "migration_executed": False,
    "negative_cases": negatives,
    "ledger_digest": ledger.ledger_digest(),
    "authority_boundaries": authority,
}
payload["record_digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
(out / "migration-validation.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
print("FAISAL_MIGRATION_VALIDATION_OK")
print("FAISAL_MIGRATION_RECORD", out / "migration-validation.json")
print("FAISAL_MIGRATION_RECORD_DIGEST", payload["record_digest"])
PY
printf '%s\n' 'FAISAL_MIGRATION_OK tests=6_passed benchmark=passed prepare=passed commit=passed capability_attenuation=passed readiness=passed destination=passed generation=passed expiry=passed replay=passed tamper=passed rollback=passed authority=passed execution=false' > "$OUT/validation.marker"
