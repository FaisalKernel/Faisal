#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_memory_write_gate import MemoryCandidate, MemoryWriteGate, MemoryWritePolicy, VerificationReceipt, digest

ITERATIONS = 1000
policy = MemoryWritePolicy(allowed_scope=("agent:1", "team:research"), minimum_trust="bounded", minimum_verification="verified", max_age_seconds=5000)

def candidate(index, *, source_kind="verified_tool", trust="bounded", verification="verified"):
    return MemoryCandidate(
        memory_id=f"memory-{index}",
        memory_class="working",
        source_kind=source_kind,
        source_id=f"source-{index}",
        source_digest=digest(f"source-{index}"),
        content_digest=digest(f"content-{index}"),
        provenance_digest=digest(f"provenance-{index}"),
        scope=("agent:1",),
        trust=trust,
        verification=verification,
        generation=7,
        created_at=index,
        expires_at=index + 1000,
    )

raw_samples=[]
admit_samples=[]
quarantine_samples=[]
promotion_samples=[]
raw_mean_value=None
admit_result=None
quarantine_result=None
promotion_result=None
for index in range(1, ITERATIONS + 1):
    item = candidate(index)
    start=time.perf_counter_ns(); raw_mean_value=digest(item.canonical()); raw_samples.append(time.perf_counter_ns()-start)
    gate=MemoryWriteGate(max_entries=4)
    start=time.perf_counter_ns(); admit_result=gate.admit(item, policy=policy, now=index+1, current_generation=7, nonce=f"n-{index}"); admit_samples.append(time.perf_counter_ns()-start)
    gate=MemoryWriteGate(max_entries=4)
    quarantined=candidate(index, source_kind="model_output", trust="untrusted", verification="unverified")
    start=time.perf_counter_ns(); quarantine_result=gate.admit(quarantined, policy=policy, now=index+1, current_generation=7, nonce=f"q-{index}"); quarantine_samples.append(time.perf_counter_ns()-start)
    verification=VerificationReceipt(candidate_digest=quarantine_result["candidate_digest"], verifier_id="benchmark-verifier", evidence_digest=digest(f"evidence-{index}"), generation=7, verified_at=index+2)
    start=time.perf_counter_ns(); promotion_result=gate.promote(quarantine_result, verification=verification, policy=policy, now=index+3, current_generation=7, nonce=f"p-{index}"); promotion_samples.append(time.perf_counter_ns()-start)
p95=lambda values: sorted(values)[int(len(values)*0.95)-1]
mean=lambda values: statistics.mean(values)
print(f"FAISAL_MEMORY_WRITE_GATE_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_MEMORY_WRITE_GATE_RAW_DIGEST_MEAN_NS={mean(raw_samples):.2f}")
print(f"FAISAL_MEMORY_WRITE_GATE_ADMIT_MEAN_NS={mean(admit_samples):.2f}")
print(f"FAISAL_MEMORY_WRITE_GATE_QUARANTINE_MEAN_NS={mean(quarantine_samples):.2f}")
print(f"FAISAL_MEMORY_WRITE_GATE_PROMOTION_MEAN_NS={mean(promotion_samples):.2f}")
print(f"FAISAL_MEMORY_WRITE_GATE_ADMIT_P95_NS={p95(admit_samples)}")
print(f"FAISAL_MEMORY_WRITE_GATE_QUARANTINE_P95_NS={p95(quarantine_samples)}")
print(f"FAISAL_MEMORY_WRITE_GATE_PROMOTION_P95_NS={p95(promotion_samples)}")
print(f"FAISAL_MEMORY_WRITE_GATE_ADMIT_OVERHEAD_RATIO={mean(admit_samples)/mean(raw_samples):.4f}")
print(f"FAISAL_MEMORY_WRITE_GATE_QUARANTINE_OVERHEAD_RATIO={mean(quarantine_samples)/mean(raw_samples):.4f}")
print(f"FAISAL_MEMORY_WRITE_GATE_PROMOTION_OVERHEAD_RATIO={mean(promotion_samples)/mean(raw_samples):.4f}")
print(f"FAISAL_MEMORY_WRITE_GATE_RAW_RESULT={raw_mean_value}")
print(f"FAISAL_MEMORY_WRITE_GATE_ADMIT_RESULT={admit_result['admitted']}")
print(f"FAISAL_MEMORY_WRITE_GATE_QUARANTINE_RESULT={quarantine_result['quarantined']}")
print(f"FAISAL_MEMORY_WRITE_GATE_PROMOTION_RESULT={promotion_result['admitted']}")
print("FAISAL_MEMORY_WRITE_GATE_BENCHMARK_SCOPE=local_python_canonical_digest_admission_quarantine_and_verified_promotion_not_database_network_model_or_kernel_latency")
