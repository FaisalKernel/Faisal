#!/usr/bin/env python3
"""Synthetic tests for the physical accelerator qualification gate.

The positive fixture is cryptographically signed test data only. It is not a
physical device observation and must never be used as release evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import verify_physical_accelerator_qualification as validator

REVISION = "1" * 40
NOW = 1800000000


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def keypair(directory: Path) -> tuple[Path, Path]:
    private = directory / "private.pem"
    public = directory / "public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return private, public


def base_report() -> dict:
    bdf = "0000:01:00.0"
    return {
        "schema": validator.SCHEMA,
        "product": "FAISAL",
        "source_revision": REVISION,
        "reviewed_epoch": NOW,
        "qualification_status": "pass",
        "qualification_mode": "hardware",
        "physical_observation": True,
        "operator_confirmed": True,
        "hardware_attestation": "trusted_lab_attested",
        "environment": {
            "host_identity": "synthetic-host-fixture",
            "kernel_release": "6.18.44-faisal",
            "pci_snapshot_sha256": digest("pci-snapshot"),
            "iommu_cmdline": "intel_iommu=on",
            "iommu_enabled": True,
        },
        "devices": [{
            "pci_bdf": bdf,
            "vendor_id": "0x1234",
            "device_id": "0x5678",
            "device_type": "gpu",
            "stable_identity": {"method": "pci-id-and-serial", "sha256": digest("device")},
            "driver": {
                "name": "synthetic-gpu-driver",
                "version": "test-1",
                "source": "upstream",
                "module": "synthetic_gpu",
                "module_sig_verified": True,
                "module_sha256": digest("driver-module"),
                "firmware": [{"name": "synthetic-fw", "version": "1", "sha256": digest("firmware")}],
            },
            "iommu": {
                "enabled": True,
                "driver": "synthetic-iommu",
                "group_id": 7,
                "group_devices": [bdf],
                "group_isolation_test": "pass",
                "dma_protection_test": "pass",
                "acs_or_topology_review": "pass",
            },
            "memory": {
                "vram_total_bytes": 8 * 1024 * 1024 * 1024,
                "vram_free_bytes": 7 * 1024 * 1024 * 1024,
                "source": "synthetic-device-query",
                "allocation_test": "pass",
                "reclamation_test": "pass",
                "accounting_test": "pass",
                "isolation_test": "pass",
                "host_ram_substitution": False,
            },
            "dma": {
                "dma_mask_bits": 48,
                "mapping_test": "pass",
                "sync_test": "pass",
                "unmap_test": "pass",
                "fault_containment_test": "pass",
                "iommu_translation_used": True,
                "arbitrary_physical_access_blocked": True,
            },
            "tests": {
                "reset_recovery": "pass",
                "stress": "pass",
                "multi_tenant_isolation": "pass",
                "driver_error_recovery": "pass",
                "physical_workload": "pass",
            },
        }],
        "evidence": [
            {"type": "pci-snapshot", "path": "synthetic-pci.json", "sha256": digest("pci")},
            {"type": "iommu-test", "path": "synthetic-iommu.log", "sha256": digest("iommu")},
            {"type": "vram-test", "path": "synthetic-vram.log", "sha256": digest("vram")},
            {"type": "dma-test", "path": "synthetic-dma.log", "sha256": digest("dma")},
        ],
        "release_decision": {
            "authority": "joint_owner_approval",
            "model_output_is_authority": False,
        },
    }


def signed_report(directory: Path, data: dict, private: Path) -> tuple[Path, Path]:
    report = directory / "accelerator.json"
    signature = Path(f"{report}.sig")
    report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(report)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return report, signature


def expect_failure(data: dict, private: Path, public: Path, directory: Path, label: str) -> None:
    report, _ = signed_report(directory, data, private)
    try:
        validator.validate(report, public, REVISION, True, NOW, 30 * 24 * 60 * 60)
    except ValueError:
        return
    raise AssertionError(f"expected failure: {label}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="faisal-accelerator-test-") as raw:
        directory = Path(raw)
        private, public = keypair(directory)
        good = base_report()
        report, signature = signed_report(directory, good, private)
        count, checks = validator.validate(report, public, REVISION, True, NOW, 30 * 24 * 60 * 60)
        assert count == 1 and len(checks) == 6

        cli_env = os.environ.copy()
        cli_env.update({
            "FAISAL_ACCELERATOR_EVIDENCE": str(report),
            "FAISAL_PUBLIC_KEY": str(public),
            "FAISAL_EXPECTED_SOURCE_REV": REVISION,
            "FAISAL_REQUIRE_ACCELERATOR_HARDWARE": "1",
            "FAISAL_ACCELERATOR_NOW_EPOCH": str(NOW),
            "FAISAL_ACCELERATOR_VERIFY_REPORT": str(directory / "verification.tsv"),
        })
        cli = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_physical_accelerator_qualification.py"))],
                             env=cli_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        assert cli.returncode == 0 and "FAISAL_ACCELERATOR_QUALIFICATION_OK" in cli.stdout
        shell_cli = subprocess.run([str(Path(__file__).with_name("verify_accelerator_qualification.sh"))],
                                   env=cli_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        assert shell_cli.returncode == 0 and "FAISAL_ACCELERATOR_QUALIFICATION_OK" in shell_cli.stdout

        qemu = copy.deepcopy(good)
        qemu["qualification_mode"] = "qemu"
        qemu["physical_observation"] = False
        expect_failure(qemu, private, public, directory, "qemu-only")

        no_iommu = copy.deepcopy(good)
        no_iommu["environment"]["iommu_enabled"] = False
        expect_failure(no_iommu, private, public, directory, "disabled iommu")

        host_ram = copy.deepcopy(good)
        host_ram["devices"][0]["memory"]["host_ram_substitution"] = True
        expect_failure(host_ram, private, public, directory, "host ram substitution")

        unsigned = copy.deepcopy(good)
        unsigned["devices"][0]["driver"]["module_sig_verified"] = False
        expect_failure(unsigned, private, public, directory, "unsigned driver")

        tampered = json.loads(report.read_text())
        tampered["devices"][0]["dma"]["arbitrary_physical_access_blocked"] = False
        report.write_text(json.dumps(tampered))
        try:
            validator.verify_signature(report, signature, public)
        except ValueError:
            pass
        else:
            raise AssertionError("tampered accelerator evidence was accepted")

    print("FAISAL_PHYSICAL_ACCELERATOR_VERIFIER_TEST_OK synthetic_hardware_pass_qemu_iommu_vram_dma_driver_tamper_denied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
