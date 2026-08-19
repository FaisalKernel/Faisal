#!/usr/bin/env python3
from __future__ import annotations

import statistics
import time

from faisal_physical_hardware_matrix import AUTHORITY_KEYS, CAPABILITIES, REQUIRED_TESTS, HardwareEvidence, HardwareMatrixLedger, MatrixPolicy, digest

ITERATIONS = 1000
AUTH = {key: False for key in AUTHORITY_KEYS}
POLICY = MatrixPolicy("matrix-bench", "FAISAL-HARDWARE-BENCH", "a" * 40, digest({"artifact": "fixture"}), CAPABILITIES, REQUIRED_TESTS, 1, 10, 100, "observer-bench")

def evidence(capability: str, index: int) -> HardwareEvidence:
    return HardwareEvidence(
        evidence_id=f"bench-{capability}", capability=capability, origin="external_reference",
        release_tag=POLICY.release_tag, release_head=POLICY.release_head, artifact_digest=POLICY.artifact_digest,
        device_identity={"model": f"fixture-{capability}", "pci_bdf": f"0000:00:{index:02x}.0"},
        firmware_digest=digest({"firmware": capability}), driver_digest=digest({"driver": capability}), topology_digest=digest({"topology": capability}),
        test_results={test: "pass" for test in REQUIRED_TESTS}, benchmark_digest=digest({"benchmark": capability}), fault_recovery_digest=digest({"recovery": capability}),
        external_report_digest=digest({"report": capability}), verification_reference=f"verifier-{capability}", observed_at=20, expires_at=90, nonce=f"nonce-{capability}", synthetic_fixture=True,
    )

def baseline_digest():
    return digest({"release": POLICY.release_tag, "head": POLICY.release_head, "capabilities": CAPABILITIES})

def admission():
    ledger = HardwareMatrixLedger(POLICY)
    for sequence, capability in enumerate(CAPABILITIES, 1):
        item = evidence(capability, sequence)
        ledger.record(item, sequence, item.nonce, 21, AUTH)

def status():
    ledger = HardwareMatrixLedger(POLICY)
    for sequence, capability in enumerate(CAPABILITIES, 1):
        item = evidence(capability, sequence)
        ledger.record(item, sequence, item.nonce, 21, AUTH)
    ledger.status(21, AUTH)

def sample(fn):
    values = []
    for _ in range(ITERATIONS):
        start = time.perf_counter_ns(); fn(); values.append(time.perf_counter_ns() - start)
    values.sort()
    return statistics.mean(values), values[int(ITERATIONS * .95) - 1]

for name, fn in (("baseline_manifest_digest", baseline_digest), ("nine_capability_admission", admission), ("nine_capability_status", status)):
    mean, p95 = sample(fn)
    print(f"FAISAL_PHYSICAL_MATRIX_BENCHMARK name={name} iterations={ITERATIONS} mean_ns={mean:.2f} p95_ns={p95:.2f}")
print("FAISAL_PHYSICAL_MATRIX_BENCHMARK_SCOPE=local_structural_contract_overhead_without_real_devices_or_vendor_workloads")
