# FAISAL M95: Durable Task Security Review

**Scope:** `tools/faisal-task/`, M95 selftest, QEMU harness, and the kernel ABI handshake
**Status:** Final review after host, QEMU, sanitizer, and regression validation
**Date:** 2026-08-16

## Security position

M95 adds a bounded userspace execution state machine. It does not grant authority to a planner, model, task description, or journal record. A task can reference an agent, capability, and required M94 intent lease, but the service itself does not replace kernel capability checks. The QEMU path verifies ABI 38 and creates a real FAISAL lifecycle session and planner light agent before executing the durable-task test.

> **Non-negotiable boundary:** model output and natural-language task text are untrusted data. They never become kernel authorization.

## Threat analysis

| Threat | Control | Validation | Residual risk |
|---|---|---|---|
| Journal truncation or tampering | Fixed header, magic/version/size checks, monotonic sequence, task-ID match, canonical SHA-256 digest, fail-closed replay | Corrupted-tail selftest and ASan/UBSan | A local privileged attacker can replace the whole journal; authenticated storage and filesystem policy remain deployment responsibilities. |
| Duplicate task submission | Bounded idempotency key and objective comparison | Same-key identical request returns the original task; conflicting objective returns conflict | Cross-host idempotency requires a replicated authoritative store, not this single-journal implementation. |
| Stale worker completes a task | Lease generation and expiry checked on heartbeat and completion | Lease recovery and generation checks in selftest | External side effects may already have occurred; exactly-once effects require tool-level idempotency. |
| Infinite retry loop | Maximum retries, exponential backoff, dead-letter state | Retry-exhaustion test | Retry policy is static per task; future policy service must be independently authorized. |
| Dependency bypass | Claim requires every dependency to be successful; failed/cancelled/dead-letter dependencies stop dependents | Dependency gate test | Cyclic graphs are prevented only by bounded dependency IDs and no self/de duplicate IDs; general cycle detection is a future extension. |
| Deadline/budget abuse | Claim checks deadline and consumed budgets; completion rejects over-budget usage | Deadline and budget tests | The service cannot measure arbitrary external GPU, network, or money consumption without provider telemetry. |
| Unauthorized kernel operation | Optional kernel session opens `/dev/agi_lifecycle`, verifies ABI 38, creates session, attaches task, registers/selects planner agent | QEMU kernel-binding marker; M94 intent leases remain separate | The service does not intercept every external syscall or prove hardware-backed identity. |
| Concurrent state corruption | Mutex serializes index and journal mutations; queries use the same lock | Four-worker query stress and TSan | Distributed workers need a supervisor/ownership protocol, selected for M96. |
| Resource exhaustion | Fixed task and dependency bounds; bounded strings; bounded retry/lease/backoff values | Strict build, malformed/corruption checks, QEMU | Journal disk growth is not compacted in M95 and requires operational quotas/rotation. |
| Unsafe subprocess execution | No `system`, `popen`, `execve`, shell interpolation, or model execution in the M95 code | Source security scan | The task service does not execute tools; future tool registry must require independent policy and intent leases. |
| Crash during append | Candidate state is only published after complete record write and `fdatasync` | Restart/replay test | A storage device or filesystem can still lose data outside the service’s control; replication is future work. |

## Invariants reviewed

The journal sequence is strictly increasing during replay. Every stored task has a bounded state, dependency count, retry count, and fixed-size text fields. Public transitions require a valid service, task ID, lease generation where applicable, and bounded time/lease parameters. Terminal tasks cannot be cancelled or claimed again. Expired leases are reclaimed before a new claim. A failed append does not publish the candidate state in memory.

The digest is computed over a canonical task representation with the stored digest field zeroed. This avoids a self-referential digest and makes replay deterministic. The corruption test appends an incomplete tail and verifies that reopening returns `FTS_ERR_CORRUPT` rather than silently dropping or inventing the record.

## External Linux precedent and boundary

Linux workqueues provide bounded asynchronous execution contexts, worker-pool concurrency management, forward-progress mechanisms, and cancellation/flush facilities [1]. M95 does not add an autonomous planner to a kernel workqueue. Linux pidfds provide stable process-lifetime references and avoid PID-reuse races for supervision [2] [3]. M95 uses a userspace journal and leaves provider/process ownership recovery to M96.

## Validation

The final M95 evidence includes strict static build, normal host selftest, ASan/UBSan with leak detection, TSan, one-vCPU QEMU kernel binding, three QEMU smoke runs, full 23-harness FAISAL regression, M90 provider regression, M91 provider-gated hardware-attestation regression, source security scan, and diff hygiene.

## Non-claims

M95 does not claim distributed consensus, encrypted or remotely authenticated journals, exactly-once external side effects, automatic rollback of arbitrary tools, transparent process-crash recovery, hardware-backed attestation, universal kernel syscall enforcement, enterprise tenancy, general AGI, model training, consciousness, or performance improvement.

## References

[1]: https://docs.kernel.org/core-api/workqueue.html — Linux Kernel documentation, “Workqueue.”
[2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
[3]: https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html — Linux man-pages, `pidfd_send_signal(2)`.
