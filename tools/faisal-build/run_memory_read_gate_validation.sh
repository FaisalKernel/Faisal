#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-memory-read-gate"
OUT=${1:-"$ROOT/../../build/frontier/memory-read-gate-validation-2026-08-19"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_memory_read_gate.py" "$MODULE/test_faisal_memory_read_gate.py" "$MODULE/bench_faisal_memory_read_gate.py"
python3 "$MODULE/test_faisal_memory_read_gate.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_memory_read_gate import MemoryEntry, MemoryReadError, MemoryReadGate, ReadPolicy, digest

def entry(memory_id="m1", trust="bounded", verification="verified", quarantined=False, injection=False, generation=7, created=100, expires=500, scope=("agent:1",), estimated=10, source_kind="verified_tool"):
    return MemoryEntry(memory_id=memory_id, candidate_digest=digest(f"candidate-{memory_id}"), memory_class="semantic", source_kind=source_kind, source_id="runner-source", content_digest=digest(f"content-{memory_id}"), provenance_digest=digest(f"provenance-{memory_id}"), scope=scope, trust=trust, verification=verification, generation=generation, created_at=created, expires_at=expires, quarantined=quarantined, injection_signaled=injection, estimated_bytes=estimated)
policy=ReadPolicy(context="execution", allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", max_entries=4, max_bytes=100, max_age_seconds=300)
audit_policy=ReadPolicy(context="audit", allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", max_entries=4, max_bytes=100, max_age_seconds=300)
gate=MemoryReadGate(max_entries=16)
trusted=gate.project([entry()], policy=policy, now=110, current_generation=7, nonce="trusted")
quarantined=gate.project([entry(memory_id="q", trust="untrusted", verification="unverified", quarantined=True, injection=True, source_kind="model_output")], policy=policy, now=110, current_generation=7, nonce="quarantine")
audit=gate.project([entry(memory_id="q-audit", trust="untrusted", verification="unverified", quarantined=True, injection=True, source_kind="browser_observation")], policy=audit_policy, now=110, current_generation=7, nonce="audit")
verified=gate.verify(trusted, expected_context="execution", expected_generation=7)
negative={}
for name, candidate, expected_reason in (
    ("scope", entry(memory_id="scope", scope=("agent:2",)), "scope_exceeds_policy"),
    ("generation", entry(memory_id="gen", generation=8), "generation_fence"),
    ("freshness", entry(memory_id="old", created=1, expires=10), "stale_or_expired"),
):
    filtered = gate.project([candidate], policy=policy, now=110, current_generation=7, nonce=f"negative-{name}")
    assert filtered["entries"] == []
    assert filtered["excluded"][0]["reason"] == expected_reason
    negative[name] = expected_reason
try:
    gate.project([entry()], policy=policy, now=110, current_generation=7, nonce="trusted")
except MemoryReadError as exc: negative["replay"]=str(exc)
try:
    tampered=copy.deepcopy(trusted); tampered["entries"][0]["instruction_authority"]=True
    gate.verify(tampered, expected_context="execution", expected_generation=7)
except MemoryReadError as exc: negative["data_only_tamper"]=str(exc)
try:
    gate.verify(trusted, expected_context="audit", expected_generation=7)
except MemoryReadError as exc: negative["context_mismatch"]=str(exc)
assert len(negative)==6
payload={"schema":"FAISAL-MEMORY-READ-GATE-VALIDATION-1","module":"tools/faisal-memory-read-gate/faisal_memory_read_gate.py","trusted_projection_digest":trusted["projection_digest"],"quarantined_execution_entry_count":len(quarantined["entries"]),"quarantined_execution_excluded_count":len(quarantined["excluded"]),"audit_entry_classification":audit["entries"][0]["classification"],"verified_projection":verified,"negative_cases":negative,"gate_digest":gate.digest(),"authority_boundaries":{"model_output_is_authority":False,"provider_metadata_is_authority":False,"memory_is_execution":False,"memory_is_instruction_authority":False,"projection_is_tool_permission":False,"production_approval":False}}
payload["record_digest"]=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
with open(os.path.join(out,"memory-read-gate-validation.json"),"w",encoding="utf-8") as handle: json.dump(payload,handle,indent=2,sort_keys=True); handle.write("\n")
print("FAISAL_MEMORY_READ_GATE_VALIDATION_OK")
print("FAISAL_MEMORY_READ_GATE_RECORD",os.path.join(out,"memory-read-gate-validation.json"))
print("FAISAL_MEMORY_READ_GATE_RECORD_DIGEST",payload["record_digest"])
PY
printf 'FAISAL_MEMORY_READ_GATE_OK tests=passed trusted=passed quarantine=passed audit=passed scope=passed freshness=passed generation=passed budgets=passed data_only=passed replay=passed tamper=passed\n' > "$OUT/validation.marker"
