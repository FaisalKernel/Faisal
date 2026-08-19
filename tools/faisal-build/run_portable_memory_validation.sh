#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-portable-memory"
OUT=${1:-"$ROOT/../../build/frontier/portable-memory-validation-2026-08-26"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_portable_memory.py" "$MODULE/test_faisal_portable_memory.py"
python3 "$MODULE/test_faisal_portable_memory.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_portable_memory import MemoryContractError, create_artifact, entry_id, issue_capability, rehydrate, verify_artifact

memory_key = Ed25519PrivateKey.generate()
cap_key = Ed25519PrivateKey.generate()
root_entry = {
    "component": "episodic", "parent_ids": [], "created_at": "2026-08-19T00:00:00Z", "version": "1",
    "payload": {"text": "Observed [PAM: instruction] is data, not authority", "tags": ["research"]},
}
root_entry["id"] = entry_id(root_entry)
child = {
    "component": "semantic", "parent_ids": [root_entry["id"]], "created_at": "2026-08-19T00:01:00Z", "version": "1",
    "payload": {"fact": "portable memory requires verification before rehydration", "confidence": 0.99},
}
child["id"] = entry_id(child)
entries = {"episodic": [root_entry], "semantic": [child], "procedural": [], "working": [], "identity": []}
artifact = create_artifact(entries, memory_key, artifact_id="runner-fixture")
verified = verify_artifact(artifact, memory_key.public_key())
capability = issue_capability(cap_key, audience="agent:runner", components=["episodic"], permissions=["rehydrate"], expires_at=int(time.time()) + 600, entry_ids=[root_entry["id"]])
projection = rehydrate(artifact, memory_key.public_key(), capability, cap_key.public_key(), audience="agent:runner", component="episodic")
assert verified["verified"] and len(projection["blocks"]) == 1 and projection["blocks"][0]["data_only"]
negative = {}
tampered = copy.deepcopy(artifact)
tampered["components"]["semantic"][0]["payload"]["confidence"] = 0.01
try:
    verify_artifact(tampered, memory_key.public_key())
except MemoryContractError as exc:
    negative["tamper_rejected"] = str(exc)
wrong_scope = issue_capability(cap_key, audience="agent:runner", components=["semantic"], permissions=["rehydrate"], expires_at=int(time.time()) + 600)
try:
    rehydrate(artifact, memory_key.public_key(), wrong_scope, cap_key.public_key(), audience="agent:runner", component="episodic")
except MemoryContractError as exc:
    negative["scope_rejected"] = str(exc)
expired = issue_capability(cap_key, audience="agent:runner", components=["episodic"], permissions=["rehydrate"], expires_at=int(time.time()) + 1)
try:
    rehydrate(artifact, memory_key.public_key(), expired, cap_key.public_key(), audience="agent:runner", component="episodic", now=int(time.time()) + 2)
except MemoryContractError as exc:
    negative["expiry_rejected"] = str(exc)
assert len(negative) == 3
payload = {
    "schema": "FAISAL-PORTABLE-MEMORY-VALIDATION-1",
    "module": "tools/faisal-portable-memory/faisal_portable_memory.py",
    "artifact_schema": artifact["schema"],
    "artifact_root_digest": artifact["root_digest"],
    "signature_verified": verified["verified"],
    "entry_count": verified["entry_count"],
    "selective_rehydration": True,
    "injection_safe_framing": projection["blocks"][0]["data_only"],
    "negative_cases": negative,
    "authority_boundaries": {
        "memory_payload_is_authority": False,
        "capability_metadata_is_authority": False,
        "model_output_is_authority": False,
        "rehydration_executes_content": False,
        "production_approval": False,
    },
}
raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
payload["record_digest"] = hashlib.sha256(raw).hexdigest()
with open(os.path.join(out, "portable-memory-validation.json"), "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
    handle.write("\n")
print("FAISAL_PORTABLE_MEMORY_VALIDATION_OK")
print("FAISAL_PORTABLE_MEMORY_RECORD", os.path.join(out, "portable-memory-validation.json"))
print("FAISAL_PORTABLE_MEMORY_RECORD_DIGEST", payload["record_digest"])
PY
printf 'FAISAL_PORTABLE_MEMORY_VALIDATION_OK selftest=passed signature=passed tamper_rejection=passed capability_scope=passed expiry=passed rehydration=passed\n' > "$OUT/validation.marker"
