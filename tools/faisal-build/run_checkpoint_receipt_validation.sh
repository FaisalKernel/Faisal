#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-checkpoint-receipt"
OUT=${1:-"$ROOT/../../build/frontier/checkpoint-receipt-validation-2026-08-19"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_checkpoint_receipt.py" "$MODULE/test_faisal_checkpoint_receipt.py" "$MODULE/bench_faisal_checkpoint_receipt.py"
python3 "$MODULE/test_faisal_checkpoint_receipt.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_checkpoint_receipt import CheckpointContractError, CheckpointInput, CheckpointLedger, digest

def checkpoint(sequence=1, event_sequence=10, previous=None, created_at=100, generation=7, lease="lease-1", lease_generation=3):
    return CheckpointInput(
        objective_id="runner-objective",
        execution_generation=generation,
        checkpoint_sequence=sequence,
        lease_id=lease,
        lease_generation=lease_generation,
        trace_digest=digest(f"trace-{sequence}"),
        state_digest=digest(f"state-{sequence}"),
        world_digest=digest(f"world-{sequence}"),
        resource_digest=digest(f"resource-{sequence}"),
        event_sequence=event_sequence,
        event_digest=digest(f"event-{sequence}"),
        previous_checkpoint_digest=previous,
        created_at=created_at,
    )

ledger = CheckpointLedger(max_receipts=16, max_objectives=4, max_age_seconds=300)
first = ledger.record(checkpoint(), now=101, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
second = ledger.record(checkpoint(sequence=2, event_sequence=12, previous=first["receipt_digest"], created_at=101), now=102, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
# Simulate a restart by verifying a serialized receipt with a fresh ledger.
restarted = CheckpointLedger(max_receipts=16, max_objectives=4, max_age_seconds=300)
verified_after_restart = restarted.verify(second, objective_id="runner-objective", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3)
resume = restarted.admit_resume(second, objective_id="runner-objective", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3, resume_nonce="resume-1")
negative = {}
try:
    restarted.admit_resume(second, objective_id="runner-objective", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3, resume_nonce="resume-1")
except CheckpointContractError as exc:
    negative["resume_replay"] = str(exc)
try:
    tampered = copy.deepcopy(second)
    tampered["checkpoint"]["world_digest"] = digest("tampered")
    restarted.verify(tampered, objective_id="runner-objective", expected_execution_generation=7, expected_lease_id="lease-1", expected_lease_generation=3)
except CheckpointContractError as exc:
    negative["receipt_tamper"] = str(exc)
try:
    restarted.verify(second, objective_id="runner-objective", expected_execution_generation=8, expected_lease_id="lease-1", expected_lease_generation=3)
except CheckpointContractError as exc:
    negative["generation_fence"] = str(exc)
try:
    restarted.verify(second, objective_id="runner-objective", expected_execution_generation=7, expected_lease_id="lease-2", expected_lease_generation=3)
except CheckpointContractError as exc:
    negative["lease_fence"] = str(exc)
try:
    restarted.record(checkpoint(sequence=3, event_sequence=11, previous=second["receipt_digest"], created_at=102), now=103, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
except CheckpointContractError as exc:
    negative["event_monotonicity"] = str(exc)
try:
    restarted.record(checkpoint(sequence=3, event_sequence=13, previous=second["receipt_digest"], created_at=0), now=400, current_execution_generation=7, current_lease_id="lease-1", current_lease_generation=3)
except CheckpointContractError as exc:
    negative["freshness"] = str(exc)
assert len(negative) == 6
payload = {
    "schema": "FAISAL-CHECKPOINT-RECEIPT-VALIDATION-1",
    "module": "tools/faisal-checkpoint-receipt/faisal_checkpoint_receipt.py",
    "first_receipt_digest": first["receipt_digest"],
    "second_receipt_digest": second["receipt_digest"],
    "verified_after_restart": verified_after_restart,
    "resume_admission": resume,
    "negative_cases": negative,
    "ledger_digest": ledger.digest(),
    "authority_boundaries": {
        "model_output_is_authority": False,
        "provider_metadata_is_authority": False,
        "checkpoint_is_execution": False,
        "receipt_is_model_correctness_proof": False,
        "recovery_requires_caller_policy": True,
        "production_approval": False,
    },
}
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
payload["record_digest"] = hashlib.sha256(raw).hexdigest()
with open(os.path.join(out, "checkpoint-receipt-validation.json"), "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("FAISAL_CHECKPOINT_RECEIPT_VALIDATION_OK")
print("FAISAL_CHECKPOINT_RECEIPT_RECORD", os.path.join(out, "checkpoint-receipt-validation.json"))
print("FAISAL_CHECKPOINT_RECEIPT_RECORD_DIGEST", payload["record_digest"])
PY
printf 'FAISAL_CHECKPOINT_RECEIPT_VALIDATION_OK tests=passed chain=passed restart_verify=passed resume=passed replay=passed tamper=passed generation=passed lease=passed freshness=passed\n' > "$OUT/validation.marker"
