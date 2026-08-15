# FAISAL Distributed Tensor Networking — Research Findings

**Access date:** 2026-08-15
**Foundation:** Linux v7.2-rc7 source snapshot, upstream tag `v7.2-rc7`
**Status:** Research checkpoint; no direct-GPU transport or collective operation is claimed.

## Verified Linux boundaries

The Linux RDMA userspace-verbs documentation states that `ib_uverbs` exposes direct userspace access to InfiniBand hardware through verbs, while kernel interaction is primarily the slow path for resource management. Fast-path operations may be performed through hardware registers mapped into userspace. The kernel maintains opaque resource handles and performs cleanup and isolation for userspace contexts. Direct userspace I/O requires pinned resident memory, and the verbs layer accounts pinned memory and applies `RLIMIT_MEMLOCK` controls. These facts argue against adding a second FAISAL RDMA data path in the kernel. FAISAL should bind its resource identity, capability, provenance, and accounting metadata to existing RDMA resources rather than duplicate verbs.

The Linux DMA-BUF documentation defines `dma_buf` as a shared DMA buffer object, `dma_fence` for asynchronous completion, and `dma_resv` for synchronization of access. DMA-BUF exporters control allocation and migration of backing storage; importers attach to devices and map scatter-gather tables into the device address space. DMA-BUF synchronization does not itself prevent concurrent process or device access, and clients remain responsible for GPU/device ordering. Therefore a FAISAL transport object must not claim that a tensor capability alone performs a safe device transfer; it must compose with DMA-BUF attachment, DMA mapping, and fence semantics.

The DMA API documentation distinguishes CPU virtual, physical, and device bus addresses. IOMMUs and host bridges can translate device addresses, so a physical address is not a valid generic transport handle. Drivers must use the DMA API and set a device DMA mask before performing DMA. Streaming mappings are intended for transfers and must be mapped for the actual transfer lifetime, while coherent mappings still require memory barriers. Consequently, FAISAL must never expose physical addresses or assume direct GPU memory access. The safe kernel primitive is a capability-scoped transport descriptor that references an existing DMA-BUF or registered RDMA resource and records the required direction, length, device scope, and fence/provenance state.

AF_XDP demonstrates that high-performance networking can use registered userspace UMEM and single-producer/single-consumer rings, with zero-copy only when the device driver supports it. Its documentation also describes fallback copy mode and explicit wakeup semantics. This is evidence that low-overhead networking is achieved through device-specific existing paths and userspace rings, not through a generic new kernel collective syscall. FAISAL can provide control-plane identity and resource accounting for such rings, but tensor collectives remain userspace/runtime operations until a specific accelerator and transport driver exposes a verifiable kernel API.

## Design consequences

| Requested capability | Kernel-supported FAISAL scope | Not claimed |
|---|---|---|
| GPU-memory-to-GPU-memory transfer | Capability-scoped registration and accounting for an existing DMA-BUF/RDMA resource | Generic direct GPU-to-GPU copy across vendors |
| AllReduce/Broadcast/ReduceScatter | Bounded collective descriptor and participant/capability validation, if justified after source review | Kernel execution of NCCL or interpretation of tensor graphs |
| Low latency | Resource ownership, fence references, completion accounting, and optional ring metadata | Unmeasured latency improvement |
| Isolation | Agent/context capability checks plus existing Linux RDMA, DMA-BUF, IOMMU, LSM, cgroup, and device-driver enforcement | Replacement of Linux security or IOMMU policy |
| Memory safety | Length, direction, generation, device-scope, and lifetime validation | Exposing physical addresses or bypassing DMA API rules |

## Primary sources

[1]: https://docs.kernel.org/infiniband/user_verbs.html "Linux kernel documentation: Userspace verbs access"
[2]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[3]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
[4]: https://docs.kernel.org/networking/af_xdp.html "Linux kernel documentation: AF_XDP"
