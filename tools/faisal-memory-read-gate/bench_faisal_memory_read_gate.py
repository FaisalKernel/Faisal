#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_memory_read_gate import MemoryEntry, MemoryReadGate, ReadPolicy, digest

ITERATIONS=1000
policy=ReadPolicy(context="execution", allowed_scope=("agent:1",), minimum_trust="bounded", minimum_verification="verified", max_entries=8, max_bytes=10000, max_age_seconds=1000)
audit_policy=ReadPolicy(context="audit", allowed_scope=("agent:1",), minimum_trust="bounded", minimum_verification="verified", max_entries=8, max_bytes=10000, max_age_seconds=1000)

def entry(index, *, quarantined=False, trust="bounded", verification="verified"):
    return MemoryEntry(memory_id=f"memory-{index}", candidate_digest=digest(f"candidate-{index}"), memory_class="semantic", source_kind="verified_tool" if not quarantined else "model_output", source_id=f"source-{index}", content_digest=digest(f"content-{index}"), provenance_digest=digest(f"provenance-{index}"), scope=("agent:1",), trust=trust, verification=verification, generation=7, created_at=index, expires_at=index+1000, quarantined=quarantined, injection_signaled=quarantined, estimated_bytes=100)

raw=[]; trusted=[]; quarantined=[]; audit=[]
for index in range(1, ITERATIONS+1):
    item=entry(index)
    start=time.perf_counter_ns(); raw_value=digest(item.canonical()); raw.append(time.perf_counter_ns()-start)
    start=time.perf_counter_ns(); trusted_result=MemoryReadGate(max_entries=8).project([item], policy=policy, now=index+1, current_generation=7, nonce=f"trusted-{index}"); trusted.append(time.perf_counter_ns()-start)
    bad=entry(index, quarantined=True, trust="untrusted", verification="unverified")
    start=time.perf_counter_ns(); quarantine_result=MemoryReadGate(max_entries=8).project([bad], policy=policy, now=index+1, current_generation=7, nonce=f"quarantine-{index}"); quarantined.append(time.perf_counter_ns()-start)
    start=time.perf_counter_ns(); audit_result=MemoryReadGate(max_entries=8).project([bad], policy=audit_policy, now=index+1, current_generation=7, nonce=f"audit-{index}"); audit.append(time.perf_counter_ns()-start)
p95=lambda values: sorted(values)[int(len(values)*0.95)-1]
mean=lambda values: statistics.mean(values)
print(f"FAISAL_MEMORY_READ_GATE_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_MEMORY_READ_GATE_RAW_DIGEST_MEAN_NS={mean(raw):.2f}")
print(f"FAISAL_MEMORY_READ_GATE_TRUSTED_PROJECTION_MEAN_NS={mean(trusted):.2f}")
print(f"FAISAL_MEMORY_READ_GATE_QUARANTINE_FILTER_MEAN_NS={mean(quarantined):.2f}")
print(f"FAISAL_MEMORY_READ_GATE_AUDIT_PROJECTION_MEAN_NS={mean(audit):.2f}")
print(f"FAISAL_MEMORY_READ_GATE_TRUSTED_PROJECTION_P95_NS={p95(trusted)}")
print(f"FAISAL_MEMORY_READ_GATE_QUARANTINE_FILTER_P95_NS={p95(quarantined)}")
print(f"FAISAL_MEMORY_READ_GATE_AUDIT_PROJECTION_P95_NS={p95(audit)}")
print(f"FAISAL_MEMORY_READ_GATE_TRUSTED_OVERHEAD_RATIO={mean(trusted)/mean(raw):.4f}")
print(f"FAISAL_MEMORY_READ_GATE_QUARANTINE_OVERHEAD_RATIO={mean(quarantined)/mean(raw):.4f}")
print(f"FAISAL_MEMORY_READ_GATE_AUDIT_OVERHEAD_RATIO={mean(audit)/mean(raw):.4f}")
print(f"FAISAL_MEMORY_READ_GATE_RAW_RESULT={raw_value}")
print(f"FAISAL_MEMORY_READ_GATE_TRUSTED_ENTRY_COUNT={len(trusted_result['entries'])}")
print(f"FAISAL_MEMORY_READ_GATE_QUARANTINED_EXECUTION_ENTRY_COUNT={len(quarantine_result['entries'])}")
print(f"FAISAL_MEMORY_READ_GATE_AUDIT_ENTRY_COUNT={len(audit_result['entries'])}")
print("FAISAL_MEMORY_READ_GATE_BENCHMARK_SCOPE=local_python_projection_filtering_and_data_only_framing_not_database_network_model_or_kernel_latency")
