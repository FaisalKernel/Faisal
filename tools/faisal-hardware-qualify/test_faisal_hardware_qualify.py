#!/usr/bin/env python3
import json
import os
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve()
TOOL = HERE.parent / "faisal_hardware_qualify.py"


def run(*args):
    return subprocess.run(["python3", str(TOOL), *map(str, args)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def synthetic_roots(root):
    proc = root / "proc"
    sys = root / "sys"
    dev = root / "dev"
    (proc).mkdir(); (sys / "bus/pci/devices/0000:00:01.0").mkdir(parents=True)
    (sys / "kernel/iommu_groups/0").mkdir(parents=True)
    (sys / "class/drm/card0").mkdir(parents=True)
    (sys / "class/nvme/nvme0").mkdir(parents=True)
    (sys / "devices/system/node/node0").mkdir(parents=True)
    (sys / "devices/system/node/node1").mkdir(parents=True)
    (sys / "class/tpm/tpm0").mkdir(parents=True)
    (dev / "dri").mkdir(parents=True)
    (dev / "dri/renderD128").touch()
    (sys / "bus/pci/devices/0000:00:01.0/class").write_text("0x030000\n")
    (sys / "bus/pci/devices/0000:00:01.0/vendor").write_text("0x1234\n")
    (proc / "cpuinfo").write_text("fixture cpu\n")
    (proc / "meminfo").write_text("MemTotal: 1 kB\n")
    (proc / "cmdline").write_text("fixture\n")
    return proc, sys, dev


def main():
    with tempfile.TemporaryDirectory(prefix="faisal-hw-test-") as tmp:
        root = Path(tmp)
        proc, sys, dev = synthetic_roots(root)
        config = root / "kernel.config"
        config.write_text("CONFIG_IOMMU_API=y\nCONFIG_IOMMUFD=m\n# CONFIG_INFINIBAND is not set\nCONFIG_NUMA=y\n")
        output = root / "observation.json"
        result = run("--output", output, "--proc-root", proc, "--sys-root", sys, "--dev-root", dev, "--kernel-config", config, "--no-commands", "--require", "gpu", "--require", "iommu", "--require", "nvme", "--require", "numa", "--require", "tpm")
        assert result.returncode == 0, result.stdout
        record = json.loads(output.read_text())
        assert record["claim_boundary"]["fake_hardware_evidence"] is False
        assert record["devices"]["gpu"]["state"] == "present"
        assert record["devices"]["iommu"]["state"] == "present"
        assert record["devices"]["numa"]["state"] == "present"
        assert record["devices"]["gpu"]["qualification"]["physical_signal"] is True
        assert record["dev_nodes"]["gpu_render"] == ["dri/renderD128"]
        assert record["kernel_features"]["options"]["CONFIG_IOMMU_API"] == "y"
        assert record["kernel_features"]["options"]["CONFIG_IOMMUFD"] == "m"
        assert record["software_fallbacks"]["accelerator_free_path"]["does_not_emulate_hardware"] is True
        assert record["readiness_summary"]["all_declared_capabilities_present"] is False
        assert "rdma" in record["readiness_summary"]["blocked_capabilities"]
        assert record["readiness_summary"]["physical_qualification"] is False
        verified = run("--verify", output, "--require", "gpu", "--require", "iommu")
        assert verified.returncode == 0, verified.stdout
        tampered = root / "tampered.json"
        altered = json.loads(output.read_text())
        altered["devices"]["gpu"]["state"] = "absent"
        tampered.write_text(json.dumps(altered))
        rejected = run("--verify", tampered)
        assert rejected.returncode != 0
        missing = run("--output", root / "missing.json", "--proc-root", proc, "--sys-root", sys, "--dev-root", dev, "--kernel-config", config, "--no-commands", "--require", "rdma")
        assert missing.returncode == 2, missing.stdout
        missing_record = json.loads((root / "missing.json").read_text())
        assert "rdma" in missing_record["readiness_summary"]["physical_qualification_pending"]
    print("FAISAL_HARDWARE_SELFTEST_OK cases=4 synthetic_only=true")


if __name__ == "__main__":
    main()
