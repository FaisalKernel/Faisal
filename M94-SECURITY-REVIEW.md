# FAISAL M94 Security Review: Intent-Bound Authority Leases

**Review date:** 2026-08-16
**Scope:** `drivers/misc/agi_lifecycle.c`, `include/uapi/linux/agi_lifecycle.h`, M94 selftest and QEMU harness

## Security objective

M94 reduces the time-of-check/time-of-use gap between a trusted userspace action policy and an autonomous operation. It does not attempt to make an AI model trusted. The kernel stores a fixed-size digest and verifies it against a kernel-owned lease record; it does not interpret the digest or the model text that may have produced it.

## Threat analysis

| Threat | Required invariant | M94 result |
| --- | --- | --- |
| Model or prompt injection requests a privileged action | Model output must not create authority | The kernel requires an already-active FAISAL capability grant; a digest alone cannot acquire a lease. |
| Caller changes the intended action after issuance | Operation, resource mask, scope, flags, generation, subject, lineage, and digest must match | All are copied into the record and compared on consume. |
| Replay of a one-time action | Remaining uses must be decremented in kernel-owned state | The consume path decrements before returning and rejects exhausted records. |
| Expired authority remains usable | Expiry must be checked at query and consume time | Monotonic time refreshes status; expired records fail with `-ETIME` or an expired status. |
| Revoked authority remains usable | Revocation must dominate consumption | Revoked records fail with `-EKEYREVOKED`; session revoke and close invalidate all records. |
| Cross-agent use | Subject and execution lineage must be bound | Current task lineage and agent identity are required and compared to the issued record. |
| Capability confusion | Intent lease must not broaden base rights | Operation classes map to existing FAISAL rights, and issuance checks the active grant. |
| Table exhaustion becomes an unbounded allocation | Resource use must be bounded | Each session has 64 slots and each lease has bounded TTL and use count. |
| Userspace pointer lifetime or malformed UAPI | Fixed-size copy and strict validation | Requests are copied once, sizes/reserved fields/flags/ranges are checked, and responses are copied only after kernel validation. |
| Session object is used after descriptor close | Close must invalidate before freeing | Close marks the session revoked and every intent record revoked before freeing session-owned memory. |
| Supervisor falsely assumes M94 provides process-crash recovery | Avoid unsupported recovery claims | M94 does not claim transparent crash recovery or pidfd integration; supervised cross-agent recovery is selected for M95. |

## Authorization review

The acquire path requires a session, current FAISAL lineage, current agent identity, nonzero grant identity/capability, a matching active grant record, and sufficient rights for the declared operation class. The current agent must match the grant subject. Scope is checked when the grant is scoped. The lease cannot grant a right absent from the underlying capability record.

The consume path requires the same subject and lineage, the original grant identity and capability, original policy flags, operation class, resource mask, scope, generation, and digest. It also rejects revoked, expired, exhausted, and provenance-required-but-unverified records. This is an additional gate, not a replacement for Linux capabilities, LSM, Landlock, seccomp, namespaces, cgroups, or application authorization.

## Concurrency and lifetime

M94’s table is session-owned, and the current lifecycle ioctl path serializes session control under the existing FAISAL ioctl lock. Session revoke and descriptor release invalidate the bounded table before memory release. No userspace service pointer is stored by this kernel primitive. The implementation therefore avoids the stale-pointer class addressed in M93, but does not claim safety for an independently destroyed userspace object that has not first revoked its lease.

## Validation

The final source passed a strict driver build, static selftest build, normal QEMU validation, three clean QEMU smokes, clean one-vCPU Generic KASAN+lockdep QEMU validation, clean one-vCPU strict KCSAN+lockdep QEMU validation, M90 and M91 regressions, and the complete 23-harness FAISAL audit. Earlier two-vCPU sanitizer attempts completed the selftest but produced QEMU virtual-clock RCU starvation warnings; those logs remain preserved as diagnostic history and are not counted as clean sanitizer evidence. The M77 verified-research harness initially failed because its one-second freshness window expired under QEMU virtual-clock latency; the selftest was corrected to use the existing supported maximum TTL, and the final full audit passed all 23 harnesses.

## Residual risks and future work

M94 does not attach automatically to every filesystem, network, browser, device, or deployment operation. A trusted userspace broker must explicitly require and consume the lease before performing the protected action. It does not provide hardware-backed keys, remote attestation, universal accelerator enforcement, arbitrary service crash recovery, supervisor-mediated cross-agent revocation, or a proof of race freedom beyond the exercised KCSAN scope.

No performance improvement is claimed. The current implementation uses a bounded linear table of 64 records per session. A future scalability milestone must measure lookup and contention costs before considering indexed storage or per-agent partitioning.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Kernel documentation, “Landlock: unprivileged access control.”
[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux Kernel documentation, “Seccomp BPF (SECure COMPuting with filters).”
[3]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
