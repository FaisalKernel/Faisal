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


def collect(sys_root: Path, proc_root: Path, dev_root: Path, no_commands: bool = False) -> dict[str, Any]:
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
    record = collect(args.sys_root, args.proc_root, args.dev_root, args.no_commands)
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
