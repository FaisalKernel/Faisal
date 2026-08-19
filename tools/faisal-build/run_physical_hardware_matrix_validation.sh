#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${FAISAL_PHYSICAL_HARDWARE_OUT:-/home/ubuntu/agi-kernel/build/frontier/physical-hardware-matrix-2026-08-19}"
KERNEL_CONFIG="${FAISAL_KERNEL_CONFIG:-/home/ubuntu/agi-kernel/build/faisal-lts-6.18.44/.config}"
rm -rf "$OUT"
mkdir -p "$OUT"
cd "$ROOT"
FAISAL_HARDWARE_OUT="$OUT/host-observation" tools/faisal-build/run_hardware_qualification.sh | tee "$OUT/host-run.log"
cd "$ROOT/tools/faisal-hardware-qualify"
PYTHONPATH=. python3 -m unittest -v test_faisal_physical_hardware_matrix.py 2>&1 | tee "$OUT/matrix-unit-test.log"
PYTHONPATH=. python3 bench_faisal_physical_hardware_matrix.py 2>&1 | tee "$OUT/matrix-benchmark.log"
python3 - "$ROOT" "$OUT" <<'PY'
from __future__ import annotations
import json, pathlib, re, subprocess, sys
root = pathlib.Path(sys.argv[1]); out = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(root / "tools/faisal-hardware-qualify"))
from faisal_hardware_qualify import CAPABILITIES as OBS_CAPABILITIES
from faisal_physical_hardware_matrix import AUTHORITY_KEYS, CAPABILITIES, REQUIRED_TESTS, HardwareEvidence, HardwareMatrixError, HardwareMatrixLedger, MatrixPolicy, digest, observation_status

authority = {key: False for key in AUTHORITY_KEYS}
head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
release_tag = "FAISAL-FRONTIER-PHYSICAL-HARDWARE-MATRIX-2026-08-19"
policy = MatrixPolicy("physical-matrix-2026-08-19", release_tag, head, digest({"artifact": "FAISAL-LTS-6.18.44-bzImage"}), CAPABILITIES, REQUIRED_TESTS, 1, 10, 100, "independent-hardware-observer-required")
def make_evidence(capability, index, origin="external_reference", **overrides):
    values = dict(evidence_id=f"fixture-{capability}", capability=capability, origin=origin, release_tag=policy.release_tag, release_head=policy.release_head, artifact_digest=policy.artifact_digest, device_identity={"model": f"fixture-{capability}", "pci_bdf": f"0000:00:{index:02x}.0", "serial": f"fixture-serial-{capability}"}, firmware_digest=digest({"firmware": capability}), driver_digest=digest({"driver": capability}), topology_digest=digest({"topology": capability}), test_results={test: "pass" for test in REQUIRED_TESTS}, benchmark_digest=digest({"benchmark": capability}), fault_recovery_digest=digest({"recovery": capability}), external_report_digest=digest({"report": capability}), verification_reference=f"external-reference-verifier-{capability}", observed_at=20, expires_at=90, nonce=f"fixture-nonce-{capability}", synthetic_fixture=True)
    values.update(overrides)
    return HardwareEvidence(**values)
ledger = HardwareMatrixLedger(policy)
for sequence, capability in enumerate(CAPABILITIES, 1):
    item = make_evidence(capability, sequence)
    ledger.record(item, sequence, item.nonce, 21, authority)
external_status = ledger.status(21, authority)
host_record = json.loads((out / "host-observation/live-host-observation.json").read_text())
local_status = observation_status(policy, host_record, 21)
negative = {}
def deny(name, fn):
    try: fn(); negative[name] = "accepted"
    except HardwareMatrixError: negative[name] = "denied"
deny("release_head_mismatch", lambda: HardwareMatrixLedger(policy).record(make_evidence("gpu", 1, release_head="b" * 40), 1, "fixture-nonce-gpu", 21, authority))
deny("missing_test", lambda: HardwareMatrixLedger(policy).record(make_evidence("gpu", 1, test_results={"enumeration": "pass"}), 1, "fixture-nonce-gpu", 21, authority))
deny("replay_nonce", lambda: (lambda l, e: (l.record(e, 1, e.nonce, 21, authority), l.record(make_evidence("npu", 2, nonce=e.nonce), 2, e.nonce, 21, authority)))(HardwareMatrixLedger(policy), make_evidence("gpu", 1)))
deny("authority_violation", lambda: HardwareMatrixLedger(policy).record(make_evidence("gpu", 1), 1, "fixture-nonce-gpu", 21, dict(authority, production_approval=True)))
bench = {}
for line in (out / "matrix-benchmark.log").read_text().splitlines():
    match = re.match(r"FAISAL_PHYSICAL_MATRIX_BENCHMARK name=(\S+) iterations=(\d+) mean_ns=([0-9.]+) p95_ns=([0-9.]+)", line)
    if match: bench[match.group(1)] = {"iterations": int(match.group(2)), "mean_ns": float(match.group(3)), "p95_ns": float(match.group(4))}
record = {"schema": "org.faisal.frontier-validation.v1", "upgrade": "physical-hardware-qualification-matrix", "recorded_at": "2026-08-19T23:59:00Z", "policy": {"matrix_id": policy.matrix_id, "release_tag": policy.release_tag, "release_head": policy.release_head, "artifact_digest": policy.artifact_digest, "required_capabilities": list(policy.required_capabilities), "required_tests": list(policy.required_tests), "trusted_observer_id": policy.trusted_observer_id}, "research_provenance": [{"source": "https://csrc.nist.gov/pubs/sp/800/193/final", "scope": "platform firmware protection, detection, recovery, and roots of trust; not physical device qualification"}, {"source": "https://docs.kernel.org/userspace-api/iommufd.html", "scope": "userspace I/O page tables, DMA mappings, device objects, and IOMMU fault/isolation semantics"}, {"source": "https://pcisig.com/developers/compliance-program", "scope": "PCIe interoperability and compliance test areas and external compliance distinction"}, {"source": "https://docs.kernel.org/driver-api/cxl/index.html", "scope": "CXL bus, firmware/ACPI handoff, topology, decoders, memory hotplug, and NUMA evidence"}], "live_host_observation": {"path": str(out / "host-observation/live-host-observation.json"), "capabilities": {name: host_record.get("devices", {}).get(name, {}).get("state", "unknown") for name in CAPABILITIES}, "record_digest": host_record.get("record_digest"), "physical_qualification": False}, "external_reference_fixture": {"records": len(CAPABILITIES), "structurally_complete": external_status["structurally_complete"], "external_hardware_evidence_structurally_complete": external_status["external_hardware_evidence_structurally_complete"], "physical_qualification_completed": external_status["physical_qualification_completed"], "production_approval": external_status["production_approval"], "blockers": external_status["blockers"], "synthetic_fixture": True}, "local_observation_fixture": {"structurally_complete": local_status["structurally_complete"], "external_hardware_evidence_structurally_complete": local_status["external_hardware_evidence_structurally_complete"], "physical_qualification_completed": local_status["physical_qualification_completed"], "production_approval": local_status["production_approval"], "blockers": local_status["blockers"]}, "negative_cases": negative, "all_negative_cases_denied": all(value == "denied" for value in negative.values()), "benchmark": bench, "boundary": {"physical_gpu_qualification": False, "physical_npu_qualification": False, "physical_iommu_dma_qualification": False, "physical_rdma_cxl_nvme_qualification": False, "physical_numa_tpm_qualification": False, "physical_power_thermal_qualification": False, "independent_hardware_review": False, "production_approval": False}, "security_boundaries": {**authority, "hardware_observation_is_qualification": False, "physical_qualification_completed": False, "production_approval": False, "synthetic_fixture_authority": False}, "limitations": ["The external-reference fixture validates structure only and contains no real devices, operators, labs, signatures, firmware measurements, driver results, power measurements, thermal traces, or independent review.", "Host observation proves only what this sandbox exposes; it cannot qualify absent GPU, NPU, IOMMU, DMA, RDMA, CXL, NVMe, or TPM hardware.", "PCI-SIG compliance, vendor tool output, kernel API availability, and provider metadata are not FAISAL physical qualification authority.", "Physical qualification remains blocked until exact hardware, firmware, driver, topology, functional, isolation, performance, fault-recovery, power/thermal, and independent-review evidence is supplied."], "rollback_checkpoint": "FAISAL-FRONTIER-SIGNING-CEREMONY-2026-08-19"}
record["record_digest"] = digest(record)
(out / "physical-hardware-matrix-validation.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
print("FAISAL_PHYSICAL_HARDWARE_MATRIX_OK unit_tests=4 external_fixture=9_capabilities_structurally_complete local_observation_blocked=true negative_cases=4_denied physical_qualification=false production_approval=false")
print("record_digest=" + record["record_digest"])
PY
