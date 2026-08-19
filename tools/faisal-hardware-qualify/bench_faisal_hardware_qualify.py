#!/usr/bin/env python3
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from faisal_hardware_qualify import collect

ITERATIONS = 500
SYS_ROOT = Path("/sys")
PROC_ROOT = Path("/proc")
DEV_ROOT = Path("/dev")
KERNEL_CONFIG = Path("/home/ubuntu/agi-kernel/build/faisal-lts-6.18.44/.config")


def minimal_probe():
    for path in (
        SYS_ROOT / "bus/pci/devices",
        SYS_ROOT / "kernel/iommu_groups",
        SYS_ROOT / "class/infiniband",
        SYS_ROOT / "bus/cxl/devices",
        SYS_ROOT / "class/nvme",
        SYS_ROOT / "class/tpm",
        SYS_ROOT / "devices/system/node",
        DEV_ROOT / "dri",
    ):
        try:
            list(path.iterdir())
        except OSError:
            pass
    return True


def full_collection():
    return collect(SYS_ROOT, PROC_ROOT, DEV_ROOT, no_commands=True, kernel_config=KERNEL_CONFIG)["readiness_summary"]["observed_capabilities"]


def measure(fn):
    samples = []
    result = None
    for _ in range(ITERATIONS):
        started = time.perf_counter_ns()
        result = fn()
        samples.append(time.perf_counter_ns() - started)
    return samples, result


minimal, minimal_result = measure(minimal_probe)
full, full_result = measure(full_collection)
print(f"FAISAL_HARDWARE_BENCHMARK_ITERATIONS={ITERATIONS}")
print(f"FAISAL_HARDWARE_MINIMAL_PROBE_MEAN_NS={statistics.mean(minimal):.2f}")
print(f"FAISAL_HARDWARE_FULL_COLLECTOR_MEAN_NS={statistics.mean(full):.2f}")
print(f"FAISAL_HARDWARE_MINIMAL_PROBE_P95_NS={sorted(minimal)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_HARDWARE_FULL_COLLECTOR_P95_NS={sorted(full)[int(ITERATIONS * .95) - 1]}")
print(f"FAISAL_HARDWARE_FULL_COLLECTOR_OVERHEAD_RATIO={statistics.mean(full) / statistics.mean(minimal):.4f}")
print(f"FAISAL_HARDWARE_MINIMAL_RESULT={minimal_result}")
print(f"FAISAL_HARDWARE_FULL_RESULT={full_result}")
print("FAISAL_HARDWARE_BENCHMARK_SCOPE=local_procfs_sysfs_devfs_observation_without_provider_commands_or_physical_workload")
