# FAISAL M94 Milestone: Intent-Bound Authority Leases

**Status:** Implemented and validated in the working tree
**Date:** 2026-08-16
**Foundation:** Linux 7.2-rc7-derived FAISAL kernel

## Executive result

M94 adds a kernel-enforced **intent-bound authority lease** for persistent autonomous workloads. It is a deliberately narrow primitive that combines an existing FAISAL capability grant with a fixed-size intent digest, operation class, resource mask, scope, agent identity, execution lineage, generation, expiry, revocation state, and bounded use counter.

The kernel does not interpret model output or natural language. A trusted userspace policy service may request a lease, but issuance requires an already-active capability grant with rights sufficient for the operation class. Consumption rechecks the entire binding and atomically decrements the remaining-use counter. This establishes a temporal and causal action boundary without turning the kernel into an AI application.

No claim is made that this is globally unprecedented. The narrower engineering claim is that FAISAL now has a tested integration of these constraints in one auditable lifecycle contract while composing with Landlock, seccomp, LSM, Linux capabilities, namespaces, cgroups, and pidfd-based supervision patterns.

## Implemented changes

The UAPI ABI is now 38 with the additive `AGI_LC_INTENT_LEASE` ioctl at `0x63`, intent operation and status constants, operation-to-right mappings, a fixed-size digest field, and bounded TTL/use definitions. Existing ABI 37 operations remain present.

The lifecycle driver owns a 64-record per-session intent table. It validates acquisition authority, performs operation-to-capability mapping, binds subject and lineage, enforces expiry and generation, rejects digest and scope mismatches, supports query and explicit revocation, atomically consumes uses, emits lifecycle events, and invalidates all records on session revoke and descriptor close.

The dedicated selftest and harness exercise the complete contract in normal QEMU. The final one-vCPU KASAN and KCSAN runs are clean; earlier two-vCPU sanitizer attempts completed the selftest but emitted QEMU virtual-clock RCU starvation warnings, which are preserved as diagnostic history and are not counted as clean sanitizer evidence. The verified-research selftest also received a fixture correction: a one-second freshness window was replaced by the existing supported maximum TTL because QEMU virtual-clock latency caused a deterministic false expiry during full-audit execution.

## Acceptance evidence

| Gate | Result |
| --- | --- |
| Strict lifecycle driver build | Passed |
| Static selftest build with warnings as errors | Passed |
| Normal M94 QEMU selftest | Passed |
| Three clean M94 QEMU smokes | Passed 3/3; 4089–4265 ms wall time |
| Generic KASAN + lockdep QEMU | Passed clean with one vCPU |
| Strict KCSAN + lockdep QEMU | Passed clean with one vCPU |
| M90 regression | Passed |
| M91 regression | Passed with explicit unsupported hardware result preserved |
| Full FAISAL regression | Passed 23/23 harnesses |
| Security and diff scan | Passed |

The final marker set includes successful acquisition, single-use atomic consume, replay denial, bounded multi-use, query, intent mismatch denial, expiry fail-closed, grant gating denial, explicit revocation denial, session invalidation, and clean selftest exit.

## Security and limitations

M94 does not authorize actions based on model text. It does not hook every Linux operation, replace existing security controls, provide hardware-backed attestation, provide universal accelerator enforcement, guarantee arbitrary userspace service crash recovery, or provide cross-agent supervisor revocation. M94’s explicit revoke path is owner/session-bound; supervisor-mediated ownership recovery is selected for M95.

M94 also does not claim a 1000× productivity increase, production readiness, or performance superiority. The benchmark report records validation wall time only. Lookup scalability, multi-agent contention, NUMA behavior, accelerator interaction, and end-to-end productivity remain unmeasured.

## Evidence paths

The machine-readable validation record belongs under `tools/faisal-build/evidence/m94-intent-lease-validation.json`. Raw build, QEMU, sanitizer, smoke, regression, and full-audit logs are collected from `/home/ubuntu/agi-kernel/build/` into the evidence directory before commit.

## Next dependency

The next selected dependency is **M95: supervisor-mediated lease ownership and crash recovery**, using stable task-lifetime supervision principles without duplicating pidfd semantics or allowing an AI model to revoke or broaden authority by itself.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Kernel documentation, “Landlock: unprivileged access control.”
[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux Kernel documentation, “Seccomp BPF (SECure COMPuting with filters).”
[3]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
