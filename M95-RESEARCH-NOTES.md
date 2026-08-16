

## Authoritative execution precedents

**Access date:** 2026-08-16

The official Linux workqueue documentation describes workqueues as asynchronous execution contexts in which work items are queued and workers execute them, with concurrency-managed worker pools, bounded `max_active`, forward-progress guarantees, cancellation/flush support, CPU locality, unbound execution, memory-reclaim rescue workers, and affinity scopes. This supports reusing Linux worker scheduling primitives rather than placing a general-purpose autonomous planner or database inside kernel workqueues. Source: [1].

The Linux `pidfd_open(2)` documentation states that a pidfd is a stable file descriptor referring to a task, is pollable through `poll`/`select`/`epoll`, and reports process termination through readiness/hangup behavior without PID-reuse ambiguity. `pidfd_send_signal(2)` documents stable signaling through a pidfd and explains why it avoids traditional PID race conditions. M95 should compose with these existing primitives in the supervisor, not duplicate them or treat process disappearance alone as proof that semantic task state was recovered. Sources: [2] [3].

M95 design implication: the durable task engine belongs in a trusted userspace service with a persistent journal and explicit leases, heartbeats, retry policy, idempotency, dead-letter, stop conditions, and replay-safe records. The FAISAL kernel should supply identity, capability/intent authorization, resource accounting, cancellation, event correlation, and checkpoint references. Linux workqueues remain an implementation precedent for bounded asynchronous execution; pidfds remain the process-lifetime supervision primitive.

[1]: https://docs.kernel.org/core-api/workqueue.html — Linux Kernel documentation, “Workqueue.”
[2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
[3]: https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html — Linux man-pages, `pidfd_send_signal(2)`.
