#!/usr/bin/env python3
"""Collect read-only physical accelerator inventory for qualification review."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path


def read_text(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def digest(value: str | None) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest() if value is not None else None


def symlink_target(path: Path) -> str | None:
    try:
        return os.path.realpath(path)
    except OSError:
        return None


def pci_snapshot() -> list[dict]:
    devices: list[dict] = []
    for path in sorted(Path("/sys/bus/pci/devices").glob("*")):
        class_code = read_text(path / "class")
        if class_code is None:
            continue
        entry = {
            "bdf": path.name,
            "vendor": read_text(path / "vendor"),
            "device": read_text(path / "device"),
            "subsystem_vendor": read_text(path / "subsystem_vendor"),
            "subsystem_device": read_text(path / "subsystem_device"),
            "class": class_code,
            "driver": symlink_target(path / "driver"),
            "iommu_group": symlink_target(path / "iommu_group"),
            "iommu_group_devices": sorted(str(x) for x in (Path(symlink_target(path / "iommu_group")) / "devices").glob("*") ) if symlink_target(path / "iommu_group") else [],
            "resource_sha256": digest(read_text(path / "resource")),
        }
        if class_code.startswith(("0x03", "0x12")) or "accelerator" in str(entry["driver"]).lower():
            devices.append(entry)
    return devices


def command_exists(command: str) -> bool:
    return subprocess.run(["sh", "-c", f"command -v {command} >/dev/null 2>&1"], check=False).returncode == 0


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/faisal-physical-accelerator-inventory.json")
    cmdline = read_text(Path("/proc/cmdline")) or ""
    groups = []
    for group in sorted(Path("/sys/kernel/iommu_groups").glob("*")):
        devices = sorted(str(x) for x in (group / "devices").glob("*"))
        groups.append({"group": group.name, "devices": devices})
    data = {
        "schema": "org.faisal.physical-accelerator-inventory.v1",
        "recorded_epoch": int(time.time()),
        "host": {
            "hostname_sha256": digest(socket.gethostname()),
            "machine_id_sha256": digest(read_text(Path("/etc/machine-id"))),
            "kernel_release": platform.release(),
            "architecture": platform.machine(),
            "cmdline_sha256": digest(cmdline),
            "iommu_cmdline_tokens": [token for token in cmdline.split() if "iommu" in token.lower() or "amd_iommu" in token.lower()],
        },
        "device_nodes": {
            "dev_dri_exists": Path("/dev/dri").exists(),
            "dev_kfd_exists": Path("/dev/kfd").exists(),
            "vfio_exists": Path("/dev/vfio").exists(),
        },
        "tools": {name: command_exists(name) for name in ("lspci", "modinfo", "nvidia-smi", "rocminfo", "xpu-smi")},
        "iommu_groups": groups,
        "accelerator_pci_devices": pci_snapshot(),
        "qualification_claim": "inventory_only_not_a_physical_qualification_result",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"FAISAL_PHYSICAL_ACCELERATOR_INVENTORY_WRITTEN path={output} devices={len(data['accelerator_pci_devices'])} iommu_groups={len(groups)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
