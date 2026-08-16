# FAISAL M95: Durable Objective and Task Execution Design

**Status:** Validated and committed as `FAISAL-M95`
**Access date:** 2026-08-16
**Specification source:** `PASTED-CONTENT-STRUCTURED.md`, sections 2–4, 18, 21–22, 28, 35, 50–51, 55, 57, 65–67

## Purpose

The pasted specification identifies durable objective execution as the highest-value gap after FAISAL’s existing lifecycle, memory, provenance, policy, and intent-authority foundations. M95 adds a real userspace durable-task service rather than pretending that graph metadata or a kernel session alone is a task engine.

The service persists bounded task snapshots in an append-only journal. Each mutation is written as a fixed-size record, flushed with `fdatasync()`, and replayed after restart only when its magic, version, size, monotonic journal sequence, task identity, state bounds, dependency bounds, and SHA-256 digest validate. A partial or corrupted tail fails closed instead of silently reconstructing an invented state.

## State machine

```text
READY ──claim──> LEASED ──heartbeat──> RUNNING ──complete──> SUCCEEDED
  │                 │                      │
  │                 └──expiry/recovery─────┘
  │
  └──dependency/budget/deadline checks──> DEAD_LETTER

LEASED/RUNNING ──retryable failure──> RETRY_WAIT ──backoff──> READY
LEASED/RUNNING ──nonretryable failure──> FAILED
READY/RETRY_WAIT/LEASED/RUNNING ──policy/stop──> CANCELLED
```

The state machine is bounded by `FTS_MAX_TASKS == 128`, `FTS_MAX_DEPENDENCIES == 8`, `FTS_MAX_RETRIES == 16`, a seven-day maximum lease, and a 24-hour retry backoff cap. The service does not create an unbounded autonomous loop. A task stops on success, impossible or failed execution, policy cancellation, deadline, budget exhaustion, retry exhaustion, or dependency failure.

## Task contract

A task contains a goal ID, parent task ID, owner agent and capability references, optional required intent lease, timestamps, deadline, lease generation, resource budgets, consumed CPU and money counters, state, retries, failure class, stop reason, dependency IDs, objective digest, idempotency key, objective text, result, and failure description.

The idempotency key is hashed and retained as a bounded string. Re-submitting the same key and identical objective returns the existing task. Reusing the key with a different objective returns a conflict. This prevents a retrying producer from creating duplicate work while preserving an explicit conflict signal for accidental key reuse.

## Durable mutation protocol

The service uses a copy–append–publish pattern. A public mutation copies the current task into a candidate, validates the transition and limits, appends the candidate with a new journal sequence, flushes the record, and only then publishes the candidate into the in-memory index. A failed append therefore does not silently claim that an operation became durable.

Replay applies the latest valid snapshot for each task ID. The journal sequence is strictly increasing. The digest is computed over a canonical task copy with the stored digest field cleared, avoiding self-referential hashing. Any malformed or truncated record returns `FTS_ERR_CORRUPT`.

## Dependency, retry, and recovery behavior

A task cannot be claimed until every dependency is successful. A failed, cancelled, or dead-letter dependency stops the dependent task rather than allowing a planner to execute it on stale assumptions. A retryable failure enters `RETRY_WAIT` with exponential backoff. When the retry budget is exhausted, the task enters `DEAD_LETTER`; it is never retried indefinitely.

A task lease has a generation and expiry. A heartbeat requires the current generation and extends the lease within the maximum bound. On service restart, `fts_recover_expired()` returns expired `LEASED` or `RUNNING` tasks to `READY`, or moves them to `DEAD_LETTER` when retry policy is exhausted. This is semantic task recovery; it does not claim that arbitrary external side effects can be rolled back.

## Kernel integration boundary

When requested by the QEMU test, the service opens `/dev/agi_lifecycle`, verifies ABI 38 through `AGI_LC_GET_INFO`, creates a FAISAL lifecycle session, attaches the current task, registers a planner light agent, and selects it. The service therefore executes through a real FAISAL kernel session, identity, and capability context.

The journal and planner remain in userspace because semantic objective text, dependency policy, idempotency, and recovery manifests are service concerns. The kernel remains responsible for lifecycle identity, capability and intent authorization, cancellation, resource accounting, event delivery, checkpoints, isolation, and provenance. M95 does not add a database, planner, model, browser, or tool parser to kernel space.

Linux workqueues remain the appropriate kernel precedent for bounded asynchronous execution contexts and concurrency-managed workers [1]. Linux pidfds remain the stable process-lifetime supervision primitive for the next provider-recovery milestone, rather than something M95 duplicates [2] [3].

## Limitations

M95 is a single-service, single-journal bounded implementation. It does not yet provide multi-node replication, distributed consensus, exactly-once external side effects, a general goal hierarchy object, a full policy-as-code language, economic value measurement, tenant isolation beyond the service boundary, automatic tool/model routing, or supervisor-mediated provider crash recovery. These are explicit subsequent dependencies, not hidden claims.

## References

[1]: https://docs.kernel.org/core-api/workqueue.html — Linux Kernel documentation, “Workqueue.”
[2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.
[3]: https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html — Linux man-pages, `pidfd_send_signal(2)`.
