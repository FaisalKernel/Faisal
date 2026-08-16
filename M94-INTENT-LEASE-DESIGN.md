# FAISAL M94: Intent-Bound Authority Lease Design

**Status:** Implemented and under final validation
**Access date:** 2026-08-16
**ABI:** 38, with the prior ABI 37 structures and operations retained

## Purpose

FAISAL already provides agent identity, capability grants, provenance, ordinary resource leases, cancellation, checkpointing, and session revocation. M94 adds a narrower primitive for autonomous actions that must be authorized for a particular **operation class, resource mask, subject, execution lineage, intent digest, time window, and bounded number of uses**.

The engineering claim is deliberately limited. M94 does not claim that no other system has ever used an intent token, temporal capability, or one-time authority. Its new FAISAL integration is the combination of a kernel-owned subject and lineage check, an already-issued capability grant, fixed-size action digest, expiry, generation, revocation, bounded consumption, and lifecycle events in one auditable contract.

## Boundary and authority model

The kernel never parses natural language, evaluates model output, or decides whether an intent is semantically wise. A trusted userspace policy service may compute an intent digest and request a lease, but the request succeeds only when the caller already holds a valid FAISAL capability grant with rights sufficient for the declared operation class.

> **Model output is data, not authority.** A model’s proposed action can be hashed and presented to a trusted policy service, but it cannot directly issue, broaden, or consume a lease without the kernel’s identity, capability, lineage, scope, expiry, generation, and use-count checks.

M94 composes with existing Linux controls rather than replacing them. Landlock remains a process-and-child filesystem/network containment layer [1]. Seccomp user notification remains a broker mechanism with its documented time-of-check/time-of-use limitations [2]. Linux capabilities, namespaces, LSM policy, cgroups, pidfds, and application policy remain independent controls.

## Object and lifecycle

Each session owns a bounded table of 64 intent-lease records. Each record contains the returned UAPI structure plus validity and revocation state. The record stores the issuing grant identity and capability, agent identity and capability, session lineage, operation class, resource mask, scope ID, generation, fixed-size intent digest, monotonic expiry, maximum uses, remaining uses, and use sequence.

| Operation | Kernel behavior | Failure examples |
| --- | --- | --- |
| `ACQUIRE` | Validates the current FAISAL lineage and agent, finds an active grant, checks operation-to-rights mapping, validates scope and bounded limits, allocates one table slot, and emits an intent-lease event. | `-EACCES`, `-EINVAL`, `-ERANGE`, `-ENOSPC` |
| `CONSUME` | Revalidates all subject, grant, lineage, flags, operation, resource, scope, generation, digest, expiry, and status fields, then decrements the remaining-use counter and increments the use sequence. | `-EACCES`, `-EKEYREVOKED`, `-ETIME`, `-ENOSPC`, `-EKEYREJECTED` |
| `QUERY` | Returns the kernel-owned state after refreshing expiry. | `-EACCES`, `-ENOENT`, `-ETIME` is represented through status for a found record |
| `REVOKE` | Marks the record revoked and emits a cancellation event. Current M94 ownership is session/agent-bound; supervisor-mediated cross-agent revocation is selected for M95. | `-EACCES`, `-EKEYREVOKED` |
| Session revoke/close | Invalidates every intent lease before the session is released. | All later use fails closed |

The `SINGLE_USE` flag requires `max_uses == 1`; otherwise M94 permits a bounded maximum of 4096 uses. The TTL is bounded to seven days. The generation is currently initialized to one and matched on consume, leaving a future generation-invalidation path for supervisor recovery without pretending that M94 provides transparent crash recovery.

## Operation classes and rights

The kernel maps declared operation classes to existing FAISAL rights. Filesystem actions require `AGI_LC_CAP_FS_WRITE`; network actions require `AGI_LC_CAP_NET_CONNECT`; browser actions require `AGI_LC_CAP_BROWSER_CONTROL`; device actions require `AGI_LC_CAP_DEVICE_USE`; privileged/tool actions require `AGI_LC_CAP_PRIVILEGED_API`; and model deployment requires `AGI_LC_CAP_COMPUTE_EXECUTE`.

This mapping is intentionally conservative. A lease is an additional temporal and intent constraint, not a replacement for the underlying capability. A caller must satisfy both the capability boundary and the lease boundary.

## Compatibility and ABI

The new `AGI_LC_INTENT_LEASE` ioctl occupies `0x63`, after the existing FAISAL ioctl namespace. The ABI version is 38 because the public UAPI gains a new structure and operation. Existing ABI 37 structures and ioctl behavior remain source-compatible when rebuilt against the new header; userspace that requires the old version can continue to use the existing operations and should negotiate the version through the existing information interfaces.

No Linux process, scheduler, filesystem, network, or accelerator subsystem was rewritten. The implementation is isolated to the FAISAL lifecycle driver, its UAPI header, a dedicated selftest, and a QEMU harness.

## Failure and recovery semantics

The primitive fails closed on invalid size, unknown operation, unsupported flag, invalid operation class, empty digest, malformed authority fields, absent lineage, revoked session, wrong agent, wrong grant, wrong scope, wrong generation, wrong digest, expiry, revocation, exhausted uses, or unavailable table capacity. A session revoke invalidates all records. A descriptor close invalidates all records before releasing the session object.

The implementation does not dereference userspace pointers after copying the fixed-size request. The bounded table is session-owned and is not shared across sessions. M94 does not make arbitrary concurrent destruction of userspace service objects safe; that remains the responsibility of the owning supervisor and is a selected future dependency.

## Verification scope

The dedicated QEMU test validates successful acquisition, single-use atomic consumption, replay denial, bounded multi-use consumption, query, intent mismatch denial, one-nanosecond expiry fail-closed behavior, capability-grant gating, explicit revocation, and session invalidation. The final kernel was also exercised under Generic KASAN+lockdep and strict KCSAN+lockdep configurations, and the complete 23-harness FAISAL regression passed.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Kernel documentation, “Landlock: unprivileged access control.”
[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux Kernel documentation, “Seccomp BPF (SECure COMPuting with filters).”
[3]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
