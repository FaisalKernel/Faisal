#!/usr/bin/env python3
"""FAISAL provider-neutral hardware qualification evidence collector.

This tool observes the host. It never invents devices or upgrades absent
capabilities. Missing hardware is recorded as absent/unknown and required
capabilities cause a non-zero exit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

SCHEMA = "org.faisal.hardware-qualification.v1"
CAPABILITIES = ("gpu", "npu", "iommu", "dma", "rdma", "cxl", "nvme", "numa", "tpm")
KERNEL_FEATURES = {
    "CONFIG_IOMMU_API": "iommu",
    "CONFIG_IOMMUFD": "iommu",
    "CONFIG_DMA_SHARED_BUFFER": "dma",
    "CONFIG_INFINIBAND": "rdma",
    "CONFIG_CXL_BUS": "cxl",
    "CONFIG_BLK_DEV_NVME": "nvme",
    "CONFIG_NUMA": "numa",
    "CONFIG_TCG_TPM": "tpm",
}


def canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return None


def exists(path: Path) -> bool:
    try:
        return path.exists()
    except OSError:
        return False


def state(present: bool | None) -> str:
    if present is True:
        return "present"
    if present is False:
        return "absent"
    return "unknown"


def list_dirs(path: Path) -> list[Path]:
    try:
        return sorted((p for p in path.iterdir() if p.is_dir()), key=lambda p: p.name)
    except OSError:
        return []


def symlink_target(path: Path) -> str | None:
    try:
        return os.path.realpath(path) if path.is_symlink() else None
    except OSError:
        return None


def collect_dev_nodes(dev_root: Path) -> dict[str, list[str]]:
    patterns = {
        "gpu_render": "dri/renderD*",
        "gpu_card": "dri/card*",
        "tpm": "tpm*",
        "tpm_resource": "tpmrm*",
        "nvme": "nvme*",
        "rdma": "infiniband/*",
        "cxl": "cxl/*",
        "dma_heap": "dma_heap/*",
    }
    result: dict[str, list[str]] = {}
    for key, pattern in patterns.items():
        try:
            result[key] = sorted(str(path.relative_to(dev_root)) for path in dev_root.glob(pattern) if path.exists())
        except OSError:
            result[key] = []
    return result


def collect_kernel_features(kernel_config: Path | None) -> dict[str, Any]:
    if kernel_config is None:
        return {"state": "unknown", "path": None, "options": {key: "unknown" for key in KERNEL_FEATURES}}
    text = read_text(kernel_config)
    if text is None:
        return {"state": "absent", "path": str(kernel_config), "options": {key: "unknown" for key in KERNEL_FEATURES}}
    values: dict[str, str] = {}
    for option in KERNEL_FEATURES:
        match = re.search(rf"^(?:# )?{re.escape(option)}(?:=(y|m|n)| is not set)$", text, flags=re.MULTILINE)
        values[option] = match.group(1) if match and match.group(1) else ("n" if match else "unknown")
    return {"state": "present", "path": str(kernel_config), "digest": digest(text), "options": values}


def capability_quality(name: str, item: dict[str, Any]) -> dict[str, Any]:
    observed = item.get("state") == "present"
    physical_signal = bool(item.get("pci_devices")) or bool(item.get("group_count")) or bool(item.get("class_devices")) or bool(item.get("devices")) or bool(item.get("nodes"))
    if not observed:
        status = "blocked_absent_or_unobservable"
    elif name in {"gpu", "npu"} and not item.get("pci_devices"):
        status = "observed_non_pci_signal_physical_qualification_pending"
    else:
        status = "observed_candidate_physical_qualification_pending" if physical_signal else "observed_without_physical_signal"
    return {"status": status, "physical_signal": physical_signal, "qualified": False}


def readiness_summary(devices: dict[str, Any]) -> dict[str, Any]:
    observed = sorted(name for name, item in devices.items() if item.get("state") == "present")
    blocked = sorted(name for name, item in devices.items() if item.get("state") != "present")
    pending = sorted(name for name, item in devices.items() if item.get("qualification", {}).get("qualified") is not True)
    return {
        "observed_capabilities": observed,
        "blocked_capabilities": blocked,
        "physical_qualification_pending": pending,
        "all_declared_capabilities_present": not blocked,
        "physical_qualification": False,
        "production_approval": False,
    }


def software_fallbacks(devices: dict[str, Any]) -> dict[str, Any]:
    absent = [name for name, item in devices.items() if item.get("state") != "present"]
    return {
        "cpu_execution": {"status": "available", "basis": "host_cpu_observation"},
        "host_memory": {"status": "available", "basis": "host_meminfo_observation"},
        "accelerator_free_path": {"status": "available", "basis": "provider_neutral_cpu_or_host_memory_fallback", "does_not_emulate_hardware": True},
        "blocked_physical_capabilities": absent,
        "model_output_is_authority": False,
        "production_approval": False,
    }


def command_version(command: str, argv: list[str]) -> dict[str, Any]:
    resolved = shutil.which(command)
    if not resolved:
        return {"command": command, "state": "absent"}
    try:
        proc = subprocess.run([resolved, *argv], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=3, check=False)
        output = proc.stdout.decode(errors="replace")[:4096]
        return {"command": command, "state": "present", "path": resolved, "returncode": proc.returncode, "output_digest": digest(output)}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"command": command, "state": "unknown", "error": type(exc).__name__}


def collect_pci(sys_root: Path) -> list[dict[str, Any]]:
    devices = []
    for dev in list_dirs(sys_root / "bus/pci/devices"):
        item: dict[str, Any] = {"bdf": dev.name}
        for name in ("vendor", "device", "class", "subsystem_vendor", "subsystem_device", "numa_node"):
            item[name] = read_text(dev / name)
        item["driver"] = symlink_target(dev / "driver")
        item["iommu_group"] = symlink_target(dev / "iommu_group")
        item["state"] = "observed"
        devices.append(item)
    return devices


def collect(sys_root: Path, proc_root: Path, dev_root: Path, no_commands: bool = False, kernel_config: Path | None = None) -> dict[str, Any]:
    pci = collect_pci(sys_root)
    iommu_groups = list_dirs(sys_root / "kernel/iommu_groups")
    infiniband = list_dirs(sys_root / "class/infiniband")
    drm = list_dirs(sys_root / "class/drm")
    dma = list_dirs(sys_root / "class/dma")
    cxl = list_dirs(sys_root / "bus/cxl/devices")
    nvme = list_dirs(sys_root / "class/nvme")
    numa = [p for p in list_dirs(sys_root / "devices/system/node") if re.fullmatch(r"node[0-9]+", p.name)]
    tpm = list_dirs(sys_root / "class/tpm")
    gpu_pci = [x for x in pci if isinstance(x.get("class"), str) and x["class"].lower().startswith("0x03")]
    npu_pci = [x for x in pci if isinstance(x.get("class"), str) and x["class"].lower().startswith(("0x12", "0x0b"))]
    devices = {
        "gpu": {"state": state(bool(gpu_pci or drm)), "pci_devices": gpu_pci, "drm_devices": [x.name for x in drm]},
        "npu": {"state": state(bool(npu_pci)), "pci_devices": npu_pci},
        "iommu": {"state": state(bool(iommu_groups)), "group_count": len(iommu_groups), "groups": [x.name for x in iommu_groups]},
        "dma": {"state": state(bool(dma or pci)), "class_devices": [x.name for x in dma], "pci_device_count": len(pci)},
        "rdma": {"state": state(bool(infiniband)), "devices": [x.name for x in infiniband]},
        "cxl": {"state": state(bool(cxl)), "devices": [x.name for x in cxl]},
        "nvme": {"state": state(bool(nvme)), "devices": [x.name for x in nvme]},
        "numa": {"state": state(bool(numa)), "nodes": [x.name for x in numa]},
        "tpm": {"state": state(bool(tpm)), "devices": [x.name for x in tpm]},
    }
    for name, item in devices.items():
        item["qualification"] = capability_quality(name, item)
    dev_nodes = collect_dev_nodes(dev_root)
    kernel_features = collect_kernel_features(kernel_config)
    host = {
        "kernel_release": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "cpuinfo_digest": digest(read_text(proc_root / "cpuinfo") or ""),
        "meminfo_digest": digest(read_text(proc_root / "meminfo") or ""),
        "cmdline_digest": digest(read_text(proc_root / "cmdline") or ""),
    }
    provider_commands = [] if no_commands else [
        command_version("nvidia-smi", ["--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"]),
        command_version("rocminfo", ["--help"]),
        command_version("xpu-smi", ["version"]),
        command_version("rdma", ["link"]),
    ]
    return {
        "schema": SCHEMA,
        "collection_mode": "host_observation",
        "claim_boundary": {
            "fake_hardware_evidence": False,
            "physical_qualification": False,
            "provider_metadata_is_authority": False,
            "production_approval": False,
        },
        "host": host,
        "pci_devices": pci,
        "devices": devices,
        "provider_commands": provider_commands,
        "dev_nodes": dev_nodes,
        "kernel_features": kernel_features,
        "readiness_summary": readiness_summary(devices),
        "software_fallbacks": software_fallbacks(devices),
        "source_roots": {"proc": str(proc_root), "sys": str(sys_root), "dev": str(dev_root)},
        "collected_at_ns": time.time_ns(),
    }


def validate(record: dict[str, Any], required: list[str]) -> dict[str, Any]:
    if record.get("schema") != SCHEMA:
        raise ValueError("schema mismatch")
    if record.get("collection_mode") != "host_observation":
        raise ValueError("unsupported collection mode")
    boundary = record.get("claim_boundary", {})
    for key in ("fake_hardware_evidence", "physical_qualification", "provider_metadata_is_authority", "production_approval"):
        if boundary.get(key) is not False:
            raise ValueError(f"boundary violation: {key}")
    devices = record.get("devices", {})
    missing = [name for name in required if devices.get(name, {}).get("state") != "present"]
    return {"required": required, "missing": missing, "pass": not missing}


def write_record(record: dict[str, Any], output: Path) -> None:
    body = dict(record)
    body["record_digest"] = digest(body)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require", action="append", choices=CAPABILITIES, default=[])
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--proc-root", type=Path, default=Path("/proc"))
    parser.add_argument("--sys-root", type=Path, default=Path("/sys"))
    parser.add_argument("--dev-root", type=Path, default=Path("/dev"))
    parser.add_argument("--no-commands", action="store_true")
    parser.add_argument("--kernel-config", type=Path)
    args = parser.parse_args()
    if args.verify:
        record = json.loads(args.verify.read_text())
        stored = record.pop("record_digest", None)
        if stored is None or digest(record) != stored:
            print("FAISAL_HARDWARE_VERIFY_BLOCKED reason=digest_mismatch")
            return 1
        result = validate(record, args.require)
        if not result["pass"]:
            print(f"FAISAL_HARDWARE_VERIFY_BLOCKED missing={','.join(result['missing'])}")
            return 1
        print(f"FAISAL_HARDWARE_VERIFY_OK required={len(args.require)}")
        return 0
    if args.output is None:
        parser.error("--output is required when collecting")
    record = collect(args.sys_root, args.proc_root, args.dev_root, args.no_commands, args.kernel_config)
    result = validate(record, args.require)
    write_record(record, args.output)
    present = sum(1 for value in record["devices"].values() if value["state"] == "present")
    print(f"FAISAL_HARDWARE_OBSERVATION_READY present_capabilities={present} required={len(args.require)} output={args.output}")
    if not result["pass"]:
        print(f"FAISAL_HARDWARE_QUALIFICATION_BLOCKED missing={','.join(result['missing'])}")
        return 2
    print(f"FAISAL_HARDWARE_QUALIFICATION_OK required={len(args.require)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
