#!/usr/bin/env python3
"""Prepare a physical GPU/NPU qualification handoff; never claims local hardware evidence."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(os.environ.get("FAISAL_ROOT", "/home/ubuntu/agi-kernel"))
REPO = ROOT / "linux"
LTS = Path(os.environ.get("FAISAL_LTS_SOURCE", str(ROOT / "upstream/6.18.44/linux-6.18.44")))
BUILD = Path(os.environ.get("FAISAL_LTS_BUILD", str(ROOT / "build/faisal-lts-6.18.44")))
OUT = Path(os.environ.get("FAISAL_ACCELERATOR_BUNDLE", str(ROOT / "build/m175-physical-accelerator")))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(LTS), *args], text=True).strip()

required = [
    LTS / ".git",
    BUILD / ".config",
    BUILD / "arch/x86/boot/bzImage",
    REPO / "tools/faisal-build/collect_physical_accelerator_inventory.py",
    REPO / "tools/faisal-build/verify_physical_accelerator_qualification.py",
    REPO / "FAISAL-ACCELERATOR-QUALIFICATION.md",
]
for path in required:
    if not path.exists():
        raise SystemExit(f"required input missing: {path}")

OUT.mkdir(parents=True, exist_ok=True)
source_revision = git("rev-parse", "HEAD")
source_epoch = git("show", "-s", "--format=%ct", "HEAD")
config = OUT / "faisal-lts.config"
artifact = OUT / "faisal-lts-bzImage"
collector = OUT / "collect_physical_accelerator_inventory.py"
validator = OUT / "verify_physical_accelerator_qualification.py"
runbook = OUT / "FAISAL-ACCELERATOR-QUALIFICATION.md"
shutil.copy2(BUILD / ".config", config)
shutil.copy2(BUILD / "arch/x86/boot/bzImage", artifact)
shutil.copy2(REPO / "tools/faisal-build/collect_physical_accelerator_inventory.py", collector)
shutil.copy2(REPO / "tools/faisal-build/verify_physical_accelerator_qualification.py", validator)
shutil.copy2(REPO / "FAISAL-ACCELERATOR-QUALIFICATION.md", runbook)
manifest = {
    "schema": "org.faisal.physical-accelerator-handoff.v1",
    "generated_epoch": int(time.time()),
    "source_revision": source_revision,
    "source_date_epoch": int(source_epoch),
    "kernel_artifact": {"name": "bzImage", "sha256": sha256(artifact), "bytes": artifact.stat().st_size},
    "configuration": {"sha256": sha256(config), "required": ["CONFIG_CFS_BANDWIDTH=y"]},
    "qualification_tools": {
        "inventory_sha256": sha256(collector),
        "validator_sha256": sha256(validator),
        "runbook_sha256": sha256(runbook),
    },
    "required_physical_evidence": [
        "PCI identity and stable hardware identity",
        "signed vendor/upstream driver and firmware provenance",
        "VRAM/device-memory allocation, reclamation, accounting, and isolation",
        "IOMMU driver, group membership, group isolation, ACS/topology review",
        "DMA mask, mapping, synchronization, unmap, and fault-containment tests",
        "device reset/recovery, stress, multi-tenant isolation, and driver-error recovery",
        "physical workload execution on the real GPU/NPU",
        "operator-confirmed observation and trusted qualification signature",
    ],
    "accepted_attestation_classes": ["operator_observed", "provider_attested", "trusted_lab_attested"],
    "rejected_substitutes": ["qemu", "host_ram", "synthetic_fixture", "device_count_only", "model_output", "container_identity"],
    "external_operator_requirement": "Run on a real device host with independently reviewable evidence; this sandbox cannot satisfy physical qualification.",
}
manifest_path = OUT / "physical-accelerator-handoff.json"
manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
instructions = OUT / "PHYSICAL-ACCELERATOR-INSTRUCTIONS.md"
instructions.write_text(f"""# FAISAL physical accelerator qualification handoff\n\nTarget source revision: `{source_revision}`. Target `bzImage` SHA-256: `{manifest['kernel_artifact']['sha256']}`. Target configuration SHA-256: `{manifest['configuration']['sha256']}`.\n\nTransfer this package to an operator-controlled host with a real GPU/NPU. Boot or install the exact candidate, confirm the source and configuration digests, run the inventory collector, and execute the physical workload and isolation tests described by the runbook. Record PCI BDF/vendor/device IDs, stable identity, driver/module and firmware digests, VRAM measurements, IOMMU group/topology, DMA tests, reset/recovery, stress, and multi-tenant results.\n\nThe final signed JSON must use `org.faisal.physical-accelerator-qualification.v2`, set `qualification_mode` to `hardware`, set `physical_observation` and `operator_confirmed` to true, use an approved hardware-attestation class, and bind the exact source revision and artifact. QEMU, host RAM, synthetic fixtures, device counts, or model output cannot satisfy this gate.\n\nThis package is a qualification handoff. It is not hardware evidence and must not be signed as if it were collected on this sandbox.\n""")
tar_path = OUT / "faisal-m175-physical-accelerator-handoff.tar.gz"
with tarfile.open(tar_path, "w:gz") as archive:
    for path in (artifact, config, collector, validator, runbook, manifest_path, instructions):
        archive.add(path, arcname=path.name)
print(f"FAISAL_PHYSICAL_ACCELERATOR_HANDOFF_READY path={tar_path} source={source_revision}")
print(f"manifest={manifest_path}")
print(f"bundle_sha256={sha256(tar_path)}")
