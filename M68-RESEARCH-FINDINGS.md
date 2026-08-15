# FAISAL M68 Research Findings

**Research date:** 2026-08-15
**Kernel base:** Linux `v7.2-rc7` in this repository.

## Findings

| Area | Verified Linux mechanism | M68 implication |
|---|---|---|
| Shared virtual addressing | HMM provides CPU page-table mirroring, `mmu_interval_notifier`, device-private memory, and migration helpers; device-specific policy remains in drivers [1]. | FAISAL should describe SVA/HMM capability and negotiated support, not implement a fake universal page-migration engine. |
| Device memory | HMM represents device-private memory with `struct page`/`ZONE_DEVICE` and uses driver DMA or device-specific instructions for migration [1]. | A generic FAISAL object can account placement intent and observed bytes, but actual placement/migration must remain provider-owned. |
| DMA addressing | Linux DMA addresses are device/bus addresses, may be translated by IOMMUs, and drivers must establish a valid DMA mask before use [2]. | Never expose CPU physical addresses or fabricate a globally valid device address in the FAISAL ABI. |
| DMA sharing | dma-buf provides cross-driver buffer sharing, attachments, mappings, fences, reservation locking, and coherency boundaries [3]. | The existing FAISAL tensor transport metadata should compose with dma-buf/fences rather than replace them. |
| Accelerator queues | UACCE exposes accelerator queues and can negotiate SVA/PASID support; control uses file operations and data paths use mapped queue memory [4]. | A vendor-neutral FAISAL context should be a capability/accounting layer over provider queue FDs, not a new universal queue submission ABI. |
| SVA/PASID | SVA requires IOMMU support; ATS/PRI synchronize device translations and page requests; PASID is process/address-space scoped and hardware/provider managed [5]. | A context may report negotiated address-space mode, but it must not promise SVA or PASID on unsupported hardware. |
| Device memory managers | DRM TTM manages accelerator memory placement, movement, CPU mappings, eviction, fences, and resource accounting; GEM is common infrastructure with different scope [6]. | FAISAL should avoid duplicating TTM/GEM/driver allocators and instead bind metadata to existing provider resources. |
| CPU scheduling | Linux utilization clamping is a scheduler hint constrained by cgroups/system limits and influences placement/frequency; it is not a device scheduler or latency guarantee [7]. | M68 can expose CPU orchestration hints and accounting, but must not claim CPU/GPU/NPU unified scheduling. |
| DMA engines | DMA Engine uses provider-specific channels and descriptors, mapped scatterlists, callbacks, and termination semantics [8]. | No generic FAISAL “CPU-to-accelerator transfer” operation should bypass provider DMA APIs. |

## Design conclusion

The user’s architectural direction is valid as a **heterogeneous-first control plane**, but the kernel cannot safely make every accelerator a peer through one universal hardware ABI. Linux already has the correct lower-level composition points: device model and driver ownership, DMA/IOMMU, dma-buf and dma-fence, HMM/SVA where hardware supports them, DRM memory managers, UACCE for user-facing accelerator queues, and scheduler hints.

The smallest justified M68 primitive is therefore a **capability-scoped heterogeneous compute context**. It records the FAISAL agent/context identity, selected provider class, address-space mode, memory-fabric capabilities, CPU orchestration hints, and accounting counters. It may bind existing FAISAL tensor regions and transport metadata, but it must not allocate VRAM, program an IOMMU, submit vendor commands, expose DMA addresses, or claim CPU/GPU/NPU global scheduling. Those operations remain in trusted device providers and userspace runtimes under Linux authorization.

## Sources

[1]: https://docs.kernel.org/mm/hmm.html "Linux kernel documentation: Heterogeneous Memory Management (HMM)"
[2]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[4]: https://docs.kernel.org/misc-devices/uacce.html "Linux kernel documentation: Uacce (Unified/User-space-access-intended Accelerator Framework)"
[5]: https://docs.kernel.org/arch/x86/sva.html "Linux kernel documentation: Shared Virtual Addressing (SVA) with ENQCMD"
[6]: https://docs.kernel.org/gpu/drm-mm.html "Linux kernel documentation: DRM Memory Management"
[7]: https://docs.kernel.org/scheduler/sched-util-clamp.html "Linux kernel documentation: Utilization Clamping"
[8]: https://docs.kernel.org/driver-api/dmaengine/client.html "Linux kernel documentation: DMA Engine API Guide"
