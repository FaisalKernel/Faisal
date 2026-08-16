# M103 Future Adaptive Memory Policy Intent

## Purpose

M103 adds an ABI-38 additive ioctl, `AGI_LC_ADAPTIVE_MEMORY_POLICY`, that lets a capability-authorized AGI service describe a bounded access-aware memory policy for a FAISAL memory region. The contract is deliberately an **intent and admission primitive**, not a duplicate memory manager. It records sampling, aggregation, application intervals, overhead, byte budget, desired action, and future provider classes for DAMON, CXL, and HMM integration.

The current Linux v7.2-rc7 FAISAL build has no proven DAMON, CXL, or HMM provider connected to this contract. Therefore a non-required provider request is stored with `OBSERVE_ONLY` status and an explicit unsupported-provider mask. A request marked `PROVIDER_REQUIRED` fails with `-EOPNOTSUPP`. The kernel never fabricates accelerator, CXL, DAMON, or HMM availability.

## Why this belongs at the kernel boundary

Linux already provides the correct long-term subsystems for access monitoring, device memory, and tiered memory. The AGI service needs an auditable, capability-scoped, generation-bound policy handle that can be persisted alongside the memory region and later consumed by a trusted provider adapter. Storing the bounded intent in the kernel prevents an untrusted model or service from silently changing memory policy outside the region capability and makes policy changes observable through the existing lifecycle event stream.

The semantic memory planner, DAMON/DAMOS policy selection, CXL topology interpretation, HMM device migration, and performance decisions remain in trusted userspace/provider services. The new ioctl does not reclaim, migrate, pin, or expose memory by itself.

## ABI and validation

The additive command uses ioctl number `0x64` while preserving `AGI_LC_ABI_VERSION 38`. SET, GET, and CLEAR are supported. Every operation requires the current session lineage and a capability authorized for read access to the region. Input intervals and budgets are bounded: sampling is 1 ms–1 s, aggregation is no shorter than sampling and at most 60 s, application interval is at most 5 minutes, overhead is at most 100,000 ppm, and per-interval bytes are at most 1 GiB. Reserved fields and unsupported flags are rejected.

CLEAR increments the memory-region generation and returns that new generation. This prevents a downstream tensor or transport operation from using a stale generation after policy mutation. A provider-required request is rejected before storage when no provider is available.

## Verification

The M79 real-kernel QEMU validator now exercises adaptive SET, provider-required denial, GET, CLEAR, generation handoff, and the existing tensor transport path. The final run produced `M79_ADAPTIVE_MEMORY_POLICY_OK status=observe-only providers=damon,cxl,hmm`, `M79_STALE_CAPABILITY_REJECT_OK`, `M79_SELFTEST_EXIT=0`, and no kernel warning, Oops, panic, or call-trace markers. The full FAISAL aggregate remained 26/26 after the change.

## Explicit limitations

M103 does not claim DAMON execution, CXL hardware support, HMM device migration, tensor migration, page reclamation, GPU/NPU coherence, performance improvement, or production readiness. Real providers must be implemented and qualified separately. The current whole-file checkpatch debt and incomplete current-head sanitizer matrix remain project-level release blockers.

## References

[1]: https://docs.kernel.org/scheduler/sched-ext.html — Linux sched_ext documentation.
[2]: https://docs.kernel.org/mm/damon/design.html — Linux DAMON/DAMOS design documentation.
[3]: https://docs.kernel.org/driver-api/cxl/index.html — Linux CXL subsystem documentation.
[4]: https://www.kernel.org/doc/html/v5.0/vm/hmm.html — Linux HMM documentation.
