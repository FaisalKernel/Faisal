# FAISAL M80 — Cross-Subsystem Stress, Fuzz, and Failure-Injection Validation

## Scope

M80 is a bounded validation milestone for the already-implemented FAISAL services. It does not add a new kernel ABI. It exercises repeated service composition, malformed-input rejection, capability denial, cancellation, resource-budget observation, audit retention, and deterministic rollback. The suite uses a finite iteration budget and fails closed on any unexpected success, state mismatch, or missing recovery marker.

The sandbox does not provide `stress`, `stress-ng`, syzkaller, or a KASAN/KCSAN-enabled build in the recovered configuration. M80 therefore uses deterministic in-process malformed-UAPI loops and repeated QEMU service runs rather than claiming coverage from unavailable external fuzzers or sanitizers.

## Scenarios

| Scenario | Bounded action | Required invariant |
|---|---|---|
| Long-running composition | Repeat M76 end-to-end coordinator 3 times in one harness sequence | Each run reaches completion or explicit recovered state; no stale report is reused |
| Malformed UAPI | 256 deterministic mutations over M73–M79 request classes | Mutated reserved fields, sizes, capabilities, masks, and approval fields are rejected before action |
| Cancellation | Reuse M76 IPC/cancellation path and repeat 8 cancellation requests | Cancelled work cannot be reported as completed work |
| Resource pressure | Repeated M78/M79 snapshots and bounded memory-budget observations | Measured, unavailable, and unsupported fields remain distinct; no fabricated accelerator state |
| Audit retention | Record a bounded audit marker for every scenario | Audit count is monotonic and remains within fixed capacity |
| Rollback fault injection | Force deterministic canary failure twice | Recovery reaches explicit rolled-back state or fails closed; no false activation |
| Capability denial | Mutate context, transport, telemetry, browser, and policy handles | Stale or cross-scope capabilities are denied |

## Failure model

M80 injects failures at the userspace orchestration boundary, not by corrupting kernel memory. A failure means an intentionally false health result, malformed request, stale capability, cancelled IPC message, or bounded resource request. Kernel panics, memory corruption, races, or unexpected acceptance are critical failures. No test suppresses a kernel failure.

## Evidence limits

M80 QEMU success demonstrates repeated bounded contract execution. It does not prove multi-day reliability, production scheduler fairness, complete fuzz coverage, absence of races, model quality, provider hardware behavior, semantic correctness, consciousness, or production readiness. Formal KASAN/KCSAN, syzkaller, lockdep, hardware stress, and long-duration soak testing remain required work when the corresponding build and environment are available.
