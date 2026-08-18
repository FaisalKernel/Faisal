# FAISAL Execution-Memory Snapshot Index

## Purpose

The snapshot index provides a compact, durable memory layer for **short-term resumable execution state**. It is intentionally separate from long-term experience, semantic memory, and model-generated knowledge. A snapshot binds an objective, task, agent, objective generation, and task generation to a bounded payload and an append-only digest chain.

## Contract

A snapshot request must provide nonzero objective, task, and agent identities, nonzero generations, a current timestamp, a bounded retention class, and a future expiry time. The service records a bounded payload, parent digest, importance, provenance flags, payload digest, and snapshot digest. The snapshot is appended with a monotonic journal sequence and durable `fsync`.

Restore selects the newest active snapshot matching all identities and generations, respecting expiry, maximum age, retention class, and minimum importance. A generation mismatch fails closed instead of returning state from a prior objective or task incarnation.

## Retention and compaction

`EPHEMERAL` records are short-lived, `STANDARD` records are ordinary resumable checkpoints, and `PINNED` records are preserved from automatic expiry and can be retained through compaction policy. Compaction only retires an older snapshot when a newer active snapshot exists for the same objective/task/agent and generation tuple. This prevents the index from deleting the only recoverable state for a workload.

The service maintains an active-snapshot index so restore does not scan historical compacted or expired records. Every state transition is itself journaled and chained. Replay validates record structure, snapshot digests, previous-chain digests, and record digests before rebuilding the active index.

## Security and authority boundaries

Payloads, model proposals, provider metadata, and action plans are data. The snapshot index does not authorize tools, actuators, browser actions, privileged kernel changes, or world-state promotion. `FSI_FLAG_MODEL_PROPOSAL` is provenance metadata only. A production integration must bind snapshots to the existing capability broker, safety control plane, task lease, and audit services.

## Rollback and qualification

The implementation is isolated under `tools/faisal-snapshot-index/` and does not modify the Linux or platform ABI. The prior frontier tag is the rollback checkpoint. Validation includes strict compilation, functional replay/corruption tests, malformed-input fuzzing, ASan/UBSan, ThreadSanitizer, restore benchmarks before and after compaction, and current M82/M83 memory regressions. No physical accelerator, robotics device, live model, or production cluster qualification is implied.
