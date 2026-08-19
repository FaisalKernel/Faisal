# FAISAL Hardware Qualification Evidence

## Purpose

Major Linux-based AI infrastructure depends on real device topology, driver health, IOMMU/DMA behavior, accelerator memory paths, NUMA placement, RDMA, storage, firmware, power, and thermal behavior. FAISAL must observe and qualify those properties rather than infer them from a model, provider metadata, or a virtual fixture.

This subsystem collects host observations from procfs, sysfs, PCI topology, IOMMU groups, device classes, NUMA nodes, and optional vendor tools. It emits canonical JSON evidence with a record digest. It is provider-neutral and does not require a specific accelerator vendor.

## Observed state versus qualification claim

The collector distinguishes:

| State | Meaning |
|---|---|
| `present` | The corresponding host observation exists in the inspected procfs/sysfs path or tool output. |
| `absent` | The inspected path exists and no matching device was observed. |
| `unknown` | The path or observation could not be inspected. |

`present` is not equivalent to production qualification. A GPU entry does not prove safe VRAM isolation, DMA correctness, reset behavior, thermal stability, driver compatibility, or performance. Physical qualification requires a signed test report for the exact hardware, firmware, kernel, driver, topology, and workload.

The evidence permanently sets `fake_hardware_evidence`, `physical_qualification`, `provider_metadata_is_authority`, and `production_approval` to false. The release gate therefore remains fail-closed when physical evidence is unavailable.

## Hardware observations

The collector records CPU and host facts, canonicalized procfs digests, PCI BDF/vendor/device/class/NUMA/driver/IOMMU-group information, GPU and NPU candidates, IOMMU groups, DMA class devices, RDMA/InfiniBand devices, CXL devices, NVMe devices, NUMA nodes, TPM devices, and optional `nvidia-smi`, `rocminfo`, `xpu-smi`, and `rdma` command availability.

Vendor commands are observations only. Their output is represented by a digest and never becomes authority. The tool does not execute firmware updates, reset devices, change IOMMU mode, load drivers, or claim support for an absent device.

## Production qualification workflow

1. Collect immutable host observation evidence.
2. Bind it to exact kernel, initramfs, firmware, driver, device IDs, PCI topology, IOMMU mode, and workload artifacts.
3. Run vendor-neutral functional, isolation, DMA, reset, thermal, power, performance, fault-injection, and recovery tests on physical hardware.
4. Obtain independent review and signed operator evidence.
5. Add the evidence digest to the candidate manifest.
6. Keep the production gate blocked if any required evidence is absent, stale, unsigned, or not independently produced.

The current sandbox can validate the collector and report its own environment, but it cannot substitute for physical accelerator qualification.
