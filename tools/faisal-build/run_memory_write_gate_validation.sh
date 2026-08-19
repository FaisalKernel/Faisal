#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-memory-write-gate"
OUT=${1:-"$ROOT/../../build/frontier/memory-write-gate-validation-2026-08-19"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_memory_write_gate.py" "$MODULE/test_faisal_memory_write_gate.py" "$MODULE/bench_faisal_memory_write_gate.py"
python3 "$MODULE/test_faisal_memory_write_gate.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_memory_write_gate import MemoryCandidate, MemoryWriteError, MemoryWriteGate, MemoryWritePolicy, VerificationReceipt, digest

def candidate(memory_class="working", source_kind="verified_tool", trust="bounded", verification="verified", injection=False, created=100, expires=500, generation=7, scope=("agent:1",)):
    return MemoryCandidate(memory_id=f"runner-{source_kind}-{memory_class}", memory_class=memory_class, source_kind=source_kind, source_id="runner-source", source_digest=digest("source"), content_digest=digest(f"content-{source_kind}-{memory_class}-{injection}"), provenance_digest=digest("provenance"), scope=scope, trust=trust, verification=verification, generation=generation, created_at=created, expires_at=expires, injection_signaled=injection)
policy=MemoryWritePolicy(allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", max_age_seconds=300)
gate=MemoryWriteGate(max_entries=16)
admitted=gate.admit(candidate(), policy=policy, now=110, current_generation=7, nonce="admit-1")
quarantined=gate.admit(candidate(memory_class="semantic", source_kind="model_output", trust="untrusted", verification="unverified"), policy=policy, now=110, current_generation=7, nonce="quarantine-1")
injection=gate.admit(candidate(source_kind="browser_observation", trust="untrusted", verification="unverified", injection=True), policy=policy, now=110, current_generation=7, nonce="injection-1")
verification=VerificationReceipt(candidate_digest=quarantined["candidate_digest"], verifier_id="runner-verifier", evidence_digest=digest("verification-evidence"), generation=7, verified_at=120)
promoted=gate.promote(quarantined, verification=verification, policy=policy, now=121, current_generation=7, nonce="promotion-1")
negative={}
for name, operation in {
    "scope": lambda: gate.admit(candidate(scope=("agent:2",)), policy=policy, now=110, current_generation=7, nonce="bad-scope"),
    "generation": lambda: gate.admit(candidate(generation=8), policy=policy, now=110, current_generation=7, nonce="bad-generation"),
    "freshness": lambda: gate.admit(candidate(created=1, expires=10), policy=policy, now=110, current_generation=7, nonce="bad-freshness"),
    "replay": lambda: gate.admit(candidate(), policy=policy, now=110, current_generation=7, nonce="replay"),
}.items():
    try: operation()
    except MemoryWriteError as exc: negative[name]=str(exc)
try:
    tampered=copy.deepcopy(quarantined); tampered["candidate"]["scope"]=["agent:2"]
    gate.promote(tampered, verification=verification, policy=policy, now=121, current_generation=7, nonce="bad-tamper")
except MemoryWriteError as exc: negative["tamper"]=str(exc)
try:
    gate.promote(quarantined, verification=verification, policy=policy, now=121, current_generation=7, nonce="promotion-1")
except MemoryWriteError as exc: negative["promotion_replay"]=str(exc)
assert len(negative)==6
payload={"schema":"FAISAL-MEMORY-WRITE-GATE-VALIDATION-1","module":"tools/faisal-memory-write-gate/faisal_memory_write_gate.py","admitted_candidate_digest":admitted["candidate_digest"],"quarantined_candidate_digest":quarantined["candidate_digest"],"injection_candidate_digest":injection["candidate_digest"],"promoted_candidate_digest":promoted["candidate_digest"],"negative_cases":negative,"gate_digest":gate.digest(),"authority_boundaries":{"model_output_is_authority":False,"provider_metadata_is_authority":False,"memory_is_execution":False,"memory_is_policy_authority":False,"quarantine_is_data_loss":False,"production_approval":False}}
payload["record_digest"]=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
with open(os.path.join(out,"memory-write-gate-validation.json"),"w",encoding="utf-8") as handle: json.dump(payload,handle,indent=2,sort_keys=True); handle.write("\n")
print("FAISAL_MEMORY_WRITE_GATE_VALIDATION_OK")
print("FAISAL_MEMORY_WRITE_GATE_RECORD",os.path.join(out,"memory-write-gate-validation.json"))
print("FAISAL_MEMORY_WRITE_GATE_RECORD_DIGEST",payload["record_digest"])
PY
printf 'FAISAL_MEMORY_WRITE_GATE_OK tests=passed admitted=passed quarantine=passed promotion=passed scope=passed freshness=passed generation=passed replay=passed tamper=passed\n' > "$OUT/validation.marker"
