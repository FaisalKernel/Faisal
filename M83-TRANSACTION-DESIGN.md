# M83 Transaction Design

## Boundary and Motivation

M82 supplies persistent-memory classes, provenance, replay, freshness, contradiction handling, and restart recovery. Its individual journal writes are durable, but a composite update spanning multiple journals can be partially applied. M83 adds the smallest service-level mechanism needed for the demonstrated gap: a bounded coordinator for at most two journals. The kernel continues to enforce lifecycle identity, selected-agent lineage, and memory-record capability checks.

## State Machine

| State | Meaning | Recovery action |
|---|---|---|
| `EMPTY` | No valid coordinator manifest | Reject as incomplete |
| `PREPARED` | Backups and transaction intent are durable; one or more operations may have applied | Restore every backup and mark `ABORTED` |
| `COMMITTED` | All operations completed and commit manifest was durably written | Retain journal contents; backups are removed |
| `ABORTED` | Recovery completed and the partial transaction was rolled back | No transaction operations are replayed |

The commit order is intentionally conservative. First, each target journal is copied to a backup. Second, the prepared manifest is written and synchronized. Third, each operation is applied through the existing memory service. Finally, the manifest is rewritten as committed and synchronized. The test injects failure after the second operation to force the recovery path to process a genuinely partial cross-journal update.

## Session Reactivation

`fms_open` creates a lifecycle session and selects a memory light-agent. Opening a second service in the same process changes the current task’s selected session. M83 adds `fms_reactivate` to attach the current task to a service’s session and select its memory agent before a kernel-backed operation. This preserves the kernel’s authorization model instead of weakening it to accommodate multiple service objects.

## Concurrent Access

The M83 test uses a pthread read/write lock around shared `fms_service` objects. A writer performs 16 updates to each journal while a reader performs 2,000 reads of a stable baseline record. The lock is explicit because the legacy service structure is not advertised as internally thread-safe. This is a measured service-level concurrency contract, not a claim that callers may access `fms_service` without synchronization.

## Crash Model

Crash injection returns immediately after the selected operation count, leaving a durable prepared manifest and backups. Recovery is then invoked as a separate logical phase, representing process restart. This is deterministic and executable, but it is not a power-cut test. The implementation does not claim that an unexpected failure during the `fdatasync` call itself, a filesystem metadata loss, or a device write-cache failure is fully covered.
