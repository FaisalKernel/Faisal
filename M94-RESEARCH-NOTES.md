# FAISAL M94 Research Notes: Intent-Bound Authority and Supervised Lifetime

**Access date:** 2026-08-16

## Current FAISAL gap

The FAISAL lifecycle driver already has agent identity, capabilities, provenance, leases, cancellation, checkpoints, resource budgets, and session revocation. Its M93 userspace provider adds bounded multi-service registration and controlled restart, but M93 explicitly does not claim transparent process-crash recovery or arbitrary unsynchronized service-destruction safety. The next useful gap is therefore not another generic capability token. It is a kernel-enforced **intent-bound authority lease** whose authority is limited by subject, operation class, resource scope, expiry, and a single-use or bounded-use counter, and whose owner can be supervised through stable process lifetime references.

## Authoritative findings

| Source | Verified fact | Design implication |
| --- | --- | --- |
| [1] | Linux Landlock restricts ambient rights for a process and its future children through stackable LSM rulesets. Its rules describe actions on kernel objects such as file hierarchies and network ports. | Landlock is a strong sandbox boundary, but it is not an AGI action-intent ledger: it does not bind a specific capability to a particular provenance action, model-independent approval, one-time use, or an autonomous task’s resource budget. FAISAL should compose with it rather than replace it. |
| [2] | `pidfd_open()` returns a file descriptor referring to a task. pidfds are stable against PID reuse, can be monitored with poll/epoll, and report task termination through readiness/hangup behavior. | A supervisor can safely detect task disappearance without polling `/proc` or trusting recycled PIDs. FAISAL can use the same lifetime principle for supervised agent authority, but must avoid duplicating pidfd functionality or claiming that a pidfd alone provides capability authorization. |

## Candidate innovation

**Intent-bound capability leases**: a kernel object records an agent/session subject, an operation class, a resource or object scope, a cryptographic intent digest supplied by a trusted userspace policy service, an expiry timestamp, a maximum-use counter, a generation, and a revocation state. A consuming operation must present the lease and matching action digest; the kernel atomically checks subject, lineage, capability, expiry, generation, and remaining uses before consuming one use. The model’s text is never interpreted by the kernel and never authorizes itself.

This is deliberately narrower than a universal “AGI syscall.” The kernel enforces a temporal and causal boundary; a trusted userspace broker decides what intent digest and operation class should be issued. Landlock, seccomp, Linux capabilities, namespaces, and LSM policy remain independent defense layers. A pidfd or equivalent supervisor reference can revoke or quarantine leases when the issuing agent terminates.

## Claims not yet established

No novelty claim is made that the world has never used any similar concept. The engineering claim to test is narrower: FAISAL can integrate intent digest, provenance sequence, bounded use, expiry, and supervisor lifetime into one auditable kernel contract for autonomous-agent actions. Performance, scalability, and security benefit must be measured after implementation.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Kernel documentation, “Landlock: unprivileged access control.”
[2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.

## Additional security precedent

The official seccomp documentation confirms that `SECCOMP_RET_USER_NOTIF` lets a userspace supervisor receive syscall notifications and send a response, but it also emphasizes that seccomp is not a complete sandbox and that policy decisions involving tracee memory must avoid time-of-check/time-of-use errors. This reinforces the M94 boundary: an intent lease may carry a trusted digest and kernel-checked constraints, but the kernel must not treat arbitrary model output or an unchecked userspace response as authorization. The lease must be consumed atomically against kernel-owned subject, expiry, generation, and use-count state, while Landlock/seccomp/LSM remain independent containment layers.

[3]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux Kernel documentation, “Seccomp BPF (SECure COMPuting with filters).”

## Selected implementation

M94 will implement the smallest reversible kernel increment: an additive **intent-bound lease** ioctl and event path. It will not hook every Linux syscall or claim universal policy enforcement. The new object will provide an atomic kernel decision primitive that a trusted userspace broker can require before executing a high-impact action.

The lease will be issued only when the caller presents an already-active FAISAL capability grant with sufficient rights. The kernel will copy and retain a fixed-size intent digest, operation class, resource mask, scope ID, expiry, maximum-use counter, grant identity, agent identity, lineage, and generation. A consume operation will verify all bindings and atomically decrement remaining uses. Expired, revoked, stale-generation, wrong-agent, wrong-lineage, wrong-intent, and exhausted leases will fail closed and emit an auditable event. Existing Landlock, seccomp, LSM, Linux capabilities, and application-specific policy remain separate layers.

The first implementation will use a new ioctl number after the current namespace and ABI version 38, while preserving all ABI 37 structures and ioctl behavior. Existing selftests will be rebuilt against the new header and a dedicated QEMU selftest will verify compatibility, grant gating, one-time use, bounded multi-use, intent mismatch denial, expiry, revocation, generation invalidation, wrong-agent denial, and session-close cleanup.
