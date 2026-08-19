#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_handoff_receipt import HandoffAdmission, HandoffPolicy, HandoffRequest, HandoffResult, digest

ITERATIONS=1000
policy=HandoffPolicy(allowed_scope=("research:read", "research:write"), minimum_trust="bounded", minimum_approval="caller_approved", max_ttl_seconds=5000)

def request(index):
    return HandoffRequest(handoff_id=f"handoff-{index}", issuer_agent_id="agent-a", delegatee_agent_id="agent-b", objective_digest=digest(f"objective-{index}"), parent_delegation_digest=digest(f"parent-{index}"), capability_scope=("research:read",), trace_position=12, generation=7, issued_at=index, expires_at=index+1000, approval="caller_approved", source_trust="bounded")

raw=[]; handoffs=[]; results=[]; quarantines=[]
for index in range(1, ITERATIONS+1):
    request_item=request(index)
    start=time.perf_counter_ns(); raw_digest=digest(request_item.canonical()); raw.append(time.perf_counter_ns()-start)
    admission=HandoffAdmission(max_handoffs=4)
    start=time.perf_counter_ns(); handoff=admission.admit(request_item, policy=policy, now=index+1, current_generation=7, nonce=f"h-{index}"); handoffs.append(time.perf_counter_ns()-start)
    result=HandoffResult(handoff_digest=handoff["handoff_digest"], result_digest=digest(f"result-{index}"), result_provenance_digest=digest(f"result-provenance-{index}"), source_kind="delegatee", source_trust="bounded", generation=7, trace_position=13, observed_at=index+2)
    start=time.perf_counter_ns(); result_record=admission.admit_result(handoff, result, policy=policy, now=index+3, current_generation=7, nonce=f"r-{index}"); results.append(time.perf_counter_ns()-start)
    bad=HandoffResult(handoff_digest=handoff["handoff_digest"], result_digest=digest(f"bad-result-{index}"), result_provenance_digest=digest(f"bad-provenance-{index}"), source_kind="model_output", source_trust="untrusted", generation=7, trace_position=14, observed_at=index+2)
    start=time.perf_counter_ns(); quarantine_record=admission.admit_result(handoff, bad, policy=policy, now=index+3, current_generation=7, nonce=f"q-{index}"); quarantines.append(time.perf_counter_ns()-start)
p95=lambda values: sorted(values)[int(len(values)*0.95)-1]
mean=lambda values: statistics.mean(values)
print(f"FAISAL_HANDOFF_RECEIPT_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_HANDOFF_RECEIPT_RAW_DIGEST_MEAN_NS={mean(raw):.2f}")
print(f"FAISAL_HANDOFF_RECEIPT_ADMISSION_MEAN_NS={mean(handoffs):.2f}")
print(f"FAISAL_HANDOFF_RECEIPT_RESULT_ADMISSION_MEAN_NS={mean(results):.2f}")
print(f"FAISAL_HANDOFF_RECEIPT_QUARANTINE_MEAN_NS={mean(quarantines):.2f}")
print(f"FAISAL_HANDOFF_RECEIPT_ADMISSION_P95_NS={p95(handoffs)}")
print(f"FAISAL_HANDOFF_RECEIPT_RESULT_ADMISSION_P95_NS={p95(results)}")
print(f"FAISAL_HANDOFF_RECEIPT_QUARANTINE_P95_NS={p95(quarantines)}")
print(f"FAISAL_HANDOFF_RECEIPT_ADMISSION_OVERHEAD_RATIO={mean(handoffs)/mean(raw):.4f}")
print(f"FAISAL_HANDOFF_RECEIPT_RESULT_OVERHEAD_RATIO={mean(results)/mean(raw):.4f}")
print(f"FAISAL_HANDOFF_RECEIPT_QUARANTINE_OVERHEAD_RATIO={mean(quarantines)/mean(raw):.4f}")
print(f"FAISAL_HANDOFF_RECEIPT_RAW_RESULT={raw_digest}")
print(f"FAISAL_HANDOFF_RECEIPT_ADMISSION_RESULT={handoff['admitted']}")
print(f"FAISAL_HANDOFF_RECEIPT_RESULT_RESULT={result_record['admitted']}")
print(f"FAISAL_HANDOFF_RECEIPT_QUARANTINE_RESULT={quarantine_record['quarantined']}")
print("FAISAL_HANDOFF_RECEIPT_BENCHMARK_SCOPE=local_python_handoff_and_result_admission_not_network_remote_agent_model_or_kernel_latency")
