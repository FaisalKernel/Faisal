#!/usr/bin/env python3
"""Fail-closed physical GPU/NPU qualification gate for FAISAL.

A signed JSON report is accepted only when the device, driver, VRAM, DMA,
IOMMU-group isolation, firmware, and physical evidence are all explicit. The
synthetic fixtures used by the unit tests are not production evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCHEMA = "org.faisal.physical-accelerator-qualification.v2"
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
BDF_RE = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read qualification JSON: {exc}") from exc
    require(isinstance(value, dict), "qualification root must be an object")
    return value


def verify_signature(report: Path, signature: Path, public_key: Path) -> None:
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature), str(report)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(proc.returncode == 0, "accelerator qualification signature mismatch")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_digest(value: Any, field: str) -> None:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value), f"invalid SHA256: {field}")


def require_pass(value: Any, field: str) -> None:
    require(value == "pass", f"{field} must be pass")


def verify_evidence_items(items: Any, field: str) -> None:
    require(isinstance(items, list) and items, f"{field} is missing")
    for index, item in enumerate(items):
        require(isinstance(item, dict), f"{field}[{index}] must be an object")
        require(isinstance(item.get("type"), str) and item["type"], f"{field}[{index}].type missing")
        require(isinstance(item.get("path"), str) and item["path"], f"{field}[{index}].path missing")
        require_digest(item.get("sha256"), f"{field}[{index}].sha256")


def verify_device(device: dict[str, Any], require_hardware: bool) -> None:
    for field in ("pci_bdf", "vendor_id", "device_id", "device_type"):
        require(isinstance(device.get(field), str) and device[field], f"device.{field} missing")
    require(BDF_RE.fullmatch(device["pci_bdf"]), "invalid PCI BDF")
    require(device["device_type"] in {"gpu", "npu", "accelerator"}, "unsupported accelerator device_type")
    identity = device.get("stable_identity")
    require(isinstance(identity, dict), "device.stable_identity missing")
    require(isinstance(identity.get("method"), str) and identity["method"], "stable identity method missing")
    require_digest(identity.get("sha256"), "device.stable_identity.sha256")

    driver = device.get("driver")
    require(isinstance(driver, dict), "device.driver missing")
    for field in ("name", "version", "source", "module"):
        require(isinstance(driver.get(field), str) and driver[field], f"device.driver.{field} missing")
    require(driver.get("source") in {"upstream", "vendor", "open_source_vendor"}, "invalid driver source")
    require(driver.get("module_sig_verified") is True, "vendor-driver module signature not verified")
    require_digest(driver.get("module_sha256"), "device.driver.module_sha256")
    require(isinstance(driver.get("firmware"), list) and driver["firmware"], "firmware provenance missing")
    for firmware in driver["firmware"]:
        require(isinstance(firmware, dict), "firmware entry must be an object")
        require(isinstance(firmware.get("name"), str) and firmware["name"], "firmware name missing")
        require(isinstance(firmware.get("version"), str) and firmware["version"], "firmware version missing")
        require_digest(firmware.get("sha256"), "firmware.sha256")

    iommu = device.get("iommu")
    require(isinstance(iommu, dict), "device.iommu missing")
    require(iommu.get("enabled") is True, "IOMMU is not enabled")
    require(isinstance(iommu.get("driver"), str) and iommu["driver"], "IOMMU driver missing")
    require(isinstance(iommu.get("group_id"), int) and iommu["group_id"] >= 0, "IOMMU group_id missing")
    group_devices = iommu.get("group_devices")
    require(isinstance(group_devices, list) and group_devices, "IOMMU group device list missing")
    require(device["pci_bdf"] in group_devices, "device is absent from its declared IOMMU group")
    require_pass(iommu.get("group_isolation_test"), "IOMMU group isolation test")
    require_pass(iommu.get("dma_protection_test"), "IOMMU DMA protection test")
    require(iommu.get("acs_or_topology_review") == "pass", "PCIe ACS/topology review missing")

    memory = device.get("memory")
    require(isinstance(memory, dict), "device.memory missing")
    total = memory.get("vram_total_bytes")
    free = memory.get("vram_free_bytes")
    require(isinstance(total, int) and total > 0, "physical VRAM/device-memory total missing")
    require(isinstance(free, int) and 0 <= free <= total, "physical VRAM/device-memory free value invalid")
    require(isinstance(memory.get("source"), str) and memory["source"], "VRAM source missing")
    for field in ("allocation_test", "reclamation_test", "accounting_test", "isolation_test"):
        require_pass(memory.get(field), f"VRAM {field}")
    require(memory.get("host_ram_substitution") is False, "host RAM substitution cannot satisfy VRAM qualification")

    dma = device.get("dma")
    require(isinstance(dma, dict), "device.dma missing")
    require(isinstance(dma.get("dma_mask_bits"), int) and dma["dma_mask_bits"] >= 32, "DMA mask evidence missing")
    for field in ("mapping_test", "sync_test", "unmap_test", "fault_containment_test"):
        require_pass(dma.get(field), f"DMA {field}")
    require(dma.get("iommu_translation_used") is True, "DMA qualification did not use IOMMU translation")
    require(dma.get("arbitrary_physical_access_blocked") is True, "arbitrary physical DMA access was not blocked")

    tests = device.get("tests")
    require(isinstance(tests, dict), "device.tests missing")
    for field in ("reset_recovery", "stress", "multi_tenant_isolation", "driver_error_recovery"):
        require_pass(tests.get(field), f"device test {field}")
    if require_hardware:
        require(tests.get("physical_workload") == "pass", "physical accelerator workload test missing")


def validate(report: Path, public_key: Path, expected_revision: str, require_hardware: bool, now: int, max_age: int) -> tuple[int, list[str]]:
    require(report.suffix.lower() == ".json", "structured JSON physical accelerator evidence is required")
    signature = Path(f"{report}.sig")
    require(report.is_file(), "accelerator evidence unreadable")
    require(signature.is_file(), "accelerator evidence signature missing")
    require(public_key.is_file(), "public key unreadable")
    verify_signature(report, signature, public_key)
    data = load_json(report)
    require(data.get("schema") == SCHEMA, "accelerator qualification schema mismatch")
    require(data.get("product") == "FAISAL", "accelerator qualification product mismatch")
    require(data.get("source_revision") == expected_revision, "accelerator source revision mismatch")
    require(COMMIT_RE.fullmatch(expected_revision), "invalid expected source revision")
    reviewed = data.get("reviewed_epoch")
    require(isinstance(reviewed, int) and reviewed <= now, "invalid/future accelerator evidence review")
    require(now - reviewed <= max_age, "accelerator evidence is stale")
    require(data.get("qualification_status") == "pass", "accelerator qualification status is not pass")
    mode = data.get("qualification_mode")
    require(mode in {"hardware", "qemu"}, "invalid accelerator qualification mode")
    if require_hardware:
        require(mode == "hardware", "physical hardware qualification required")
        require(data.get("physical_observation") is True, "physical observation confirmation missing")
        require(data.get("operator_confirmed") is True, "operator confirmation missing")
        require(data.get("hardware_attestation") in {"operator_observed", "provider_attested", "trusted_lab_attested"},
                "physical hardware attestation class missing")
    else:
        require(data.get("physical_observation") is False, "non-hardware report cannot claim physical observation")
    environment = data.get("environment")
    require(isinstance(environment, dict), "accelerator environment block missing")
    for field in ("host_identity", "kernel_release", "pci_snapshot_sha256", "iommu_cmdline"):
        require(isinstance(environment.get(field), str) and environment[field], f"environment.{field} missing")
    require_digest(environment.get("pci_snapshot_sha256"), "environment.pci_snapshot_sha256")
    require(isinstance(environment.get("iommu_enabled"), bool), "environment.iommu_enabled missing")
    require(environment.get("iommu_enabled") is True, "environment IOMMU is disabled")
    devices = data.get("devices")
    require(isinstance(devices, list) and devices, "no accelerator devices qualified")
    bdfs: set[str] = set()
    for device in devices:
        require(isinstance(device, dict), "device record must be an object")
        verify_device(device, require_hardware)
        require(device["pci_bdf"] not in bdfs, "duplicate PCI device record")
        bdfs.add(device["pci_bdf"])
    verify_evidence_items(data.get("evidence"), "evidence")
    release = data.get("release_decision")
    require(isinstance(release, dict), "release decision block missing")
    require(release.get("authority") in {"security_owner", "release_owner", "joint_owner_approval"},
            "accelerator release authority is not an accountable owner")
    require(release.get("model_output_is_authority") is False, "model output cannot authorize accelerator release")
    return len(devices), [f"mode={mode}", f"devices={len(devices)}", "iommu=pass", "dma=pass", "vram=pass", "driver=pass"]


def main() -> int:
    report = Path(os.environ.get("FAISAL_ACCELERATOR_EVIDENCE", ""))
    public_key = Path(os.environ.get("FAISAL_PUBLIC_KEY", ""))
    expected = os.environ.get("FAISAL_EXPECTED_SOURCE_REV", "")
    output = Path(os.environ.get("FAISAL_ACCELERATOR_VERIFY_REPORT", f"{report}.verification.tsv"))
    require_hardware = os.environ.get("FAISAL_REQUIRE_ACCELERATOR_HARDWARE", "0") == "1"
    try:
        max_age = int(os.environ.get("FAISAL_ACCELERATOR_MAX_AGE_SECONDS", str(30 * 24 * 60 * 60)))
        now = int(os.environ.get("FAISAL_ACCELERATOR_NOW_EPOCH", str(int(time.time()))))
        count, checks = validate(report, public_key, expected, require_hardware, now, max_age)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text("check\tstatus\tdetail\n" + "\n".join(f"{c}\tpass\tverified" for c in checks) + "\n")
        print(f"FAISAL_ACCELERATOR_QUALIFICATION_OK devices={count} report={output}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"check\tstatus\tdetail\nqualification\tblocked\t{exc}\n")
        print(f"FAISAL_ACCELERATOR_QUALIFICATION_BLOCKED reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
