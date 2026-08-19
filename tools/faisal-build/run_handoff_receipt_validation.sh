#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODULE="$ROOT/tools/faisal-handoff-receipt"
OUT=${1:-"$ROOT/../../build/frontier/handoff-receipt-validation-2026-08-19"}
mkdir -p "$OUT"
python3 -m py_compile "$MODULE/faisal_handoff_receipt.py" "$MODULE/test_faisal_handoff_receipt.py" "$MODULE/bench_faisal_handoff_receipt.py"
python3 "$MODULE/test_faisal_handoff_receipt.py" | tee "$OUT/selftest.log"
python3 - "$MODULE" "$OUT" <<'PY'
import copy
import hashlib
import json
import os
import sys
module, out = sys.argv[1:]
sys.path.insert(0, module)
from faisal_handoff_receipt import HandoffAdmission, HandoffError, HandoffPolicy, HandoffRequest, HandoffResult, digest

def request(*, handoff_id="h1", scope=("research:read",), approval="caller_approved", generation=7, issued=100, expires=500, model_authority=False):
    return HandoffRequest(handoff_id=handoff_id, issuer_agent_id="agent-a", delegatee_agent_id="agent-b", objective_digest=digest("objective"), parent_delegation_digest=digest("parent"), capability_scope=scope, trace_position=12, generation=generation, issued_at=issued, expires_at=expires, approval=approval, source_trust="bounded", model_output_authority=model_authority)

def result(handoff_digest, *, source_kind="delegatee", source_trust="bounded", trace=13, generation=7, observed=120, provider_authority=False):
    return HandoffResult(handoff_digest=handoff_digest, result_digest=digest(f"result-{source_kind}-{trace}"), result_provenance_digest=digest("result-provenance"), source_kind=source_kind, source_trust=source_trust, generation=generation, trace_position=trace, observed_at=observed, provider_metadata_authority=provider_authority)
policy=HandoffPolicy(allowed_scope=("research:read", "research:write", "deploy:staging"), minimum_trust="bounded", minimum_approval="caller_approved", require_operator_for_scope=("deploy:staging",), max_ttl_seconds=300)
admission=HandoffAdmission(max_handoffs=16)
admitted=admission.admit(request(), policy=policy, now=110, current_generation=7, nonce="admit")
operator=admission.admit(request(handoff_id="operator", scope=("deploy:staging",), approval="operator_approved"), policy=policy, now=110, current_generation=7, nonce="operator")
verified_result=admission.admit_result(admitted, result(admitted["handoff_digest"]), policy=policy, now=121, current_generation=7, nonce="result")
quarantined_result=admission.admit_result(operator, result(operator["handoff_digest"], source_kind="model_output", source_trust="untrusted", trace=13), policy=policy, now=121, current_generation=7, nonce="quarantine")
negative={}
for name, req, pol, now in (
    ("scope", request(scope=("admin:root",)), policy, 110),
    ("generation", request(generation=8), policy, 110),
    ("freshness", request(issued=1, expires=10), policy, 110),
    ("authority", request(handoff_id="authority", model_authority=True), policy, 110),
):
    try: admission.admit(req, policy=pol, now=now, current_generation=7, nonce=f"negative-{name}")
    except HandoffError as exc: negative[name]=str(exc)
try:
    admission.admit_result(admitted, result(admitted["handoff_digest"], trace=11), policy=policy, now=122, current_generation=7, nonce="trace")
except HandoffError as exc: negative["trace"] = str(exc)
try:
    admission.admit_result(admitted, result(admitted["handoff_digest"], provider_authority=True, trace=14), policy=policy, now=122, current_generation=7, nonce="result-authority")
except HandoffError as exc: negative["result_authority"] = str(exc)
try:
    admission.admit_result(admitted, result(admitted["handoff_digest"], trace=13), policy=policy, now=122, current_generation=7, nonce="result")
except HandoffError as exc: negative["replay"] = str(exc)
try:
    tampered=copy.deepcopy(admitted); tampered["request"]["capability_scope"]=["deploy:staging"]
    admission.admit_result(tampered, result(admitted["handoff_digest"], trace=14), policy=policy, now=122, current_generation=7, nonce="tamper")
except HandoffError as exc: negative["tamper"] = str(exc)
assert len(negative)==8
payload={"schema":"FAISAL-HANDOFF-RECEIPT-VALIDATION-1","module":"tools/faisal-handoff-receipt/faisal_handoff_receipt.py","admitted_handoff_digest":admitted["handoff_digest"],"operator_handoff_digest":operator["handoff_digest"],"verified_result_status":verified_result["status"],"quarantined_result_status":quarantined_result["status"],"negative_cases":negative,"admission_digest":admission.digest(),"authority_boundaries":{"model_output_is_authority":False,"provider_metadata_is_authority":False,"handoff_is_execution":False,"remote_result_is_authority":False,"production_approval":False}}
payload["record_digest"]=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
with open(os.path.join(out,"handoff-receipt-validation.json"),"w",encoding="utf-8") as handle: json.dump(payload,handle,indent=2,sort_keys=True); handle.write("\n")
print("FAISAL_HANDOFF_RECEIPT_VALIDATION_OK")
print("FAISAL_HANDOFF_RECEIPT_RECORD",os.path.join(out,"handoff-receipt-validation.json"))
print("FAISAL_HANDOFF_RECEIPT_RECORD_DIGEST",payload["record_digest"])
PY
printf 'FAISAL_HANDOFF_RECEIPT_OK tests=passed admitted=passed operator_approval=passed result=passed quarantine=passed scope=passed generation=passed freshness=passed trace=passed replay=passed tamper=passed authority=passed\n' > "$OUT/validation.marker"
