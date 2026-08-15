# FAISAL M68 — Heterogeneous Compute-Context Fabric

**Status:** Implemented and validated in two-vCPU QEMU.
**Base:** Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7`.
**FAISAL ABI:** 35.
**Validation date:** 2026-08-15.

## Objective

M68 addresses the architectural requirement that AGI compute should be heterogeneous-first without replacing Linux’s device model or fabricating a universal GPU/NPU command ABI. The new ABI-35 fields extend `AGI_LC_COMPUTE_CONTEXT` with negotiated device and memory-fabric capabilities, address-space mode, provider identity, and bounded accounting counters.

The context is a **control-plane and attribution object**. It does not become a GPU driver, accelerator scheduler, IOMMU programmer, HMM migration engine, or model executor. Actual hardware ownership remains with Linux device drivers and trusted userspace runtimes.

## Negotiated model

| Field | M68 behavior |
|---|---|
| Requested device mask | CPU, GPU, NPU, and I/O classes may be requested as metadata |
| Active device mask | CPU is the only universally available provider in this generic lifecycle driver |
| Unsupported device mask | Requested GPU/NPU/I/O classes are reported rather than falsely activated |
| Requested fabric | DMA-buf, DMA Engine, IOMMU SVA, HMM, and UACCE capabilities may be requested |
| Active fabric | Derived from the compiled kernel framework configuration plus the always-available CPU control plane |
| Address-space mode | Process address-space semantics are reported for CPU-backed contexts; no SVA claim is made for an unbound accelerator |
| Provider kind | CPU for CPU-backed contexts; none when only an unsupported accelerator class is requested |
| Accounting | Bound FAISAL memory-region bytes are reflected in `bytes_accounted`; provider transfer/compute counters remain zero until a real provider reports them |

In the recovered `x86_64` configuration, the QEMU validation reported active fabric bits `0xf`, corresponding to CPU control, DMA-buf, DMA Engine, and IOMMU-SVA framework support. HMM mirror and UACCE were not enabled in that build and were reported unsupported. This is **framework availability**, not proof that a QEMU guest has an SVA-capable accelerator or an active GPU/NPU provider.

## Linux composition

The implementation deliberately composes with existing Linux mechanisms. DMA-buf remains responsible for sharing buffers, attachments, mappings, fences, and coherency. DMA/IOMMU APIs remain responsible for device-visible addresses and protection. HMM remains responsible for device-private memory, page-table mirroring, invalidation, and migration when a device driver implements those operations. UACCE and driver-specific queue interfaces remain responsible for provider queues. The CPU scheduler and cgroup policy remain responsible for CPU task placement and resource enforcement.

The FAISAL context can bind an existing capability-scoped memory region. The driver records the region’s byte size and updates bounded context accounting on bind and unbind. It does not expose physical addresses, DMA addresses, VRAM addresses, PASIDs, or vendor command descriptors.

## Verification

The full kernel and module build passed. The static selftest passed, and the two-vCPU QEMU boot harness emitted:

```text
FAISAL_M68_BOOT_OK
M68_MEMORY_REGION_OK id=1 bytes=4096
M68_CONTEXT_NEGOTIATION_OK active_fabric=0xf
M68_CONTEXT_QUERY_OK
M68_STALE_CONTEXT_CAPABILITY_REJECT_OK
M68_CONTEXT_BIND_OK accounted=4096
M68_CONTEXT_UNBIND_OK
M68_GPU_PROVIDER_BOUNDARY_OK
M68_CONTEXT_CLOSE_OK
M68_SELFTEST_EXIT=0
FAISAL_M68_TEST_RC=0
```

The machine-readable evidence is in `tools/faisal-build/evidence/m68-heterogeneous-context-validation.json`; the raw serial log is in `tools/faisal-build/evidence/m68-qemu.log`.

## Explicit non-claims

M68 does not claim that the CPU has been replaced as the hardware host, that GPU/NPU execution is available on QEMU, that DMA-buf or IOMMU-SVA framework support implies an attached accelerator, that CPU/GPU/NPU scheduling is unified, that memory migration is implemented, that zero-copy transfers are guaranteed, or that inference latency or throughput improved. A production heterogeneous deployment still requires hardware-specific drivers, provider queues, IOMMU policy, HMM/SVA negotiation, fences, device reset/recovery, and measured workload benchmarks.

## References

[1]: https://docs.kernel.org/mm/hmm.html "Linux kernel documentation: Heterogeneous Memory Management (HMM)"
[2]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[4]: https://docs.kernel.org/misc-devices/uacce.html "Linux kernel documentation: Uacce"
[5]: https://docs.kernel.org/arch/x86/sva.html "Linux kernel documentation: Shared Virtual Addressing (SVA) with ENQCMD"
[6]: https://docs.kernel.org/gpu/drm-mm.html "Linux kernel documentation: DRM Memory Management"
