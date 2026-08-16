# FAISAL Future-Technology Research

**Accessed:** 2026-08-16

## Candidate findings

### sched_ext

Linux’s official sched_ext documentation describes a scheduler class whose behavior can be defined by BPF programs. It exports a full scheduling interface, allows dynamic activation/deactivation, and explicitly restores default scheduling when an error is detected, a runnable task stalls, or SysRq-S is invoked. The documentation also states that sched_ext BPF APIs have no stability guarantees between kernel versions. Required configuration includes `CONFIG_SCHED_CLASS_EXT`, BPF syscall/JIT/BTF support, and related options. Source: https://docs.kernel.org/scheduler/sched-ext.html

**FAISAL impact:** sched_ext is an advanced path for experimenting with cognitive scheduling without replacing Linux’s default scheduler, but its unstable BPF ABI and missing support in the Linux v7.2-rc7 FAISAL base make direct backporting a high-risk project. It is a future integration target, not the smallest safe ABI-38 patch.

### DAMON/DAMOS

Linux’s official DAMON design documents a monitoring context executed by a kernel `kdamond` thread, with configurable sampling, aggregation, update intervals, region bounds, adaptive region merging/splitting, and overhead/accuracy controls. DAMOS allows high-level operation schemes such as statistics, migration, pageout, hugepage advice, and cold/hot memory actions. The documentation emphasizes best-effort sampling and tunable overhead. Source: https://docs.kernel.org/mm/damon/design.html

**FAISAL impact:** DAMON is a strong future foundation for access-aware AGI memory placement and cold/hot tensor-region policy, but a clean production feature should reuse the upstream subsystem rather than duplicate it in `agi_lifecycle.c`. A FAISAL memory-policy bridge can later bind capability-scoped tensor regions to DAMON/DAMOS targets.

### CXL memory tiering

Linux’s official CXL documentation describes platform/firmware/OS handoff, memory-tier creation, NUMA and HMAT/SLIT locality information, CDAT latency/bandwidth data, memory hotplug, DAX, demotion, reclaim, and memory allocation. Source: https://docs.kernel.org/driver-api/cxl/index.html

**FAISAL impact:** CXL is the most relevant future hardware path for AGI model-memory capacity and tier-aware placement, but it is hardware and firmware gated. FAISAL should add provider-neutral policy and honest capability reporting rather than claim CXL support in QEMU.

### HMM

Linux HMM provides helpers for integrating device memory into normal kernel memory-management paths, mirroring CPU page tables, representing device memory with `struct page`, and migrating ranges using device DMA. Policy decisions remain with device drivers. Source: https://www.kernel.org/doc/html/v5.0/vm/hmm.html

**FAISAL impact:** HMM is the correct upstream foundation for future GPU/NPU shared virtual memory and device-memory migration. FAISAL should not invent a parallel tensor allocator or pretend to provide GPU coherence without a real provider.

## Selection

The safest immediate future-facing extension is **capability-scoped adaptive memory policy intent**: a minimal ABI-preserving FAISAL contract that records a bounded policy request for access-aware memory observation and future DAMON/DAMOS/CXL/HMM integration, while refusing to migrate or reclaim memory in the kernel until a provider and policy backend are explicitly available. This creates an executable, auditable bridge without duplicating upstream memory-management code or fabricating hardware support.

The alternative of directly backporting sched_ext is deferred because the official documentation identifies an unstable BPF API and the FAISAL base lacks the full upstream subsystem. Direct CXL/HMM implementation is deferred because validation requires real hardware and provider drivers.
