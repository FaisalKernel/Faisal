#!/usr/bin/env python3
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from faisal_checkpoint_receipt import CheckpointInput, CheckpointLedger, digest

ITERATIONS = 1000

def checkpoint(sequence, previous, event_sequence):
    return CheckpointInput(
        objective_id="bench-objective",
        execution_generation=7,
        checkpoint_sequence=sequence,
        lease_id="bench-lease",
        lease_generation=3,
        trace_digest=digest(f"trace-{sequence}"),
        state_digest=digest(f"state-{sequence}"),
        world_digest=digest(f"world-{sequence}"),
        resource_digest=digest(f"resource-{sequence}"),
        event_sequence=event_sequence,
        event_digest=digest(f"event-{sequence}"),
        previous_checkpoint_digest=previous,
        created_at=sequence,
    )

raw_samples = []
record_samples = []
verify_samples = []
resume_samples = []
raw_result = None
record_result = None
verify_result = None
resume_result = None
ledger = CheckpointLedger(max_receipts=ITERATIONS + 2, max_objectives=2, max_age_seconds=ITERATIONS + 2)
previous = None
receipts = []
for index in range(1, ITERATIONS + 1):
    item = checkpoint(index, previous, index * 2)
    start = time.perf_counter_ns()
    raw_result = digest(item.canonical())
    raw_samples.append(time.perf_counter_ns() - start)
    start = time.perf_counter_ns()
    receipt = ledger.record(item, now=index, current_execution_generation=7, current_lease_id="bench-lease", current_lease_generation=3)
    record_samples.append(time.perf_counter_ns() - start)
    previous = receipt["receipt_digest"]
    receipts.append(receipt)

for index, receipt in enumerate(receipts, start=1):
    start = time.perf_counter_ns()
    verify_result = ledger.verify(receipt, objective_id="bench-objective", expected_execution_generation=7, expected_lease_id="bench-lease", expected_lease_generation=3)
    verify_samples.append(time.perf_counter_ns() - start)
    start = time.perf_counter_ns()
    resume_result = ledger.admit_resume(receipt, objective_id="bench-objective", expected_execution_generation=7, expected_lease_id="bench-lease", expected_lease_generation=3, resume_nonce=f"resume-{index}")
    resume_samples.append(time.perf_counter_ns() - start)

p95 = lambda values: sorted(values)[int(len(values) * 0.95) - 1]
print(f"FAISAL_CHECKPOINT_RECEIPT_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RAW_DIGEST_MEAN_NS={statistics.mean(raw_samples):.2f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RECORD_MEAN_NS={statistics.mean(record_samples):.2f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_VERIFY_MEAN_NS={statistics.mean(verify_samples):.2f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RESUME_MEAN_NS={statistics.mean(resume_samples):.2f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RECORD_P95_NS={p95(record_samples)}")
print(f"FAISAL_CHECKPOINT_RECEIPT_VERIFY_P95_NS={p95(verify_samples)}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RESUME_P95_NS={p95(resume_samples)}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RECORD_OVERHEAD_RATIO={statistics.mean(record_samples) / statistics.mean(raw_samples):.4f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_VERIFY_OVERHEAD_RATIO={statistics.mean(verify_samples) / statistics.mean(raw_samples):.4f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RESUME_OVERHEAD_RATIO={statistics.mean(resume_samples) / statistics.mean(raw_samples):.4f}")
print(f"FAISAL_CHECKPOINT_RECEIPT_FINAL_LEDGER_DIGEST={ledger.digest()}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RAW_RESULT={raw_result}")
print(f"FAISAL_CHECKPOINT_RECEIPT_VERIFY_RESULT={verify_result['verified']}")
print(f"FAISAL_CHECKPOINT_RECEIPT_RESUME_RESULT={resume_result['admitted']}")
print("FAISAL_CHECKPOINT_RECEIPT_BENCHMARK_SCOPE=local_python_digest_chain_record_offline_verify_and_resume_admission_not_storage_network_model_or_kernel_latency")
