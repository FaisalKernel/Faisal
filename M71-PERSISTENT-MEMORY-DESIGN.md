# FAISAL M71 Persistent-Memory Service Design

## Scope

M71 implements the first userspace persistent-memory service. The service stores semantic content and metadata in a durable append-only journal, while the FAISAL kernel stores bounded lifecycle metadata, ownership, capability, generation, provenance sequence, freshness, conflict, and checkpoint state. The kernel is not turned into a semantic database.

## Service contract

The service accepts a memory record containing content, source digest, scope, tier, confidence, importance, freshness, relationships, and optional provenance sequence. It computes a SHA-256 content digest, writes a length-checked journal entry, calls `AGI_LC_MEMORY_RECORD` to create or update the kernel metadata record, and calls the checkpoint/recovery interface for service-state manifests. A record is acknowledged only after both the journal data and kernel metadata operation succeed.

The service exposes four internal operations for the first implementation: `PUT`, `GET`, `CORRECT`, and `RECOVER`. It also supports `CHECKPOINT` and `RESTORE` test paths. It does not call a language model and does not claim that persistence retrains a model.

## Durable journal format

The journal is a sequence of fixed-header, length-bounded binary entries. Each entry contains a magic value, format version, header size, sequence, kernel record ID, kernel generation, tier, confidence, importance, provenance sequence, SHA-256 digest, content length, and content bytes. The header and content are written with `write()` and made durable using `fdatasync()` before the service acknowledges the operation.

On restart the service reads entries sequentially. It rejects a truncated header, invalid magic/version/header size, content length above the configured limit, short payload, or digest mismatch. It replays the last valid entry for each record ID and stops at the first incomplete tail, preserving earlier committed records. The service never silently converts corrupt data into a memory record.

## Capability and provenance policy

The service must hold an explicit FAISAL agent identity and kernel session. Every kernel record mutation carries the returned authority capability and exact record ID. A capability is not persisted as semantic content and is never accepted from a model. On restart, the service creates a fresh session and rebinds only through a trusted supervisor or explicit recovery policy; stale capabilities are rejected by the kernel.

Provenance is a reference to a kernel-held action/result sequence. The journal stores the sequence and content digest, not the action text, model weights, secrets, browser content, or physical addresses. A missing or stale provenance sequence is represented as unverified and cannot be silently upgraded to verified.

## State machine

```text
ABSENT
  │ PUT: durable journal + kernel CREATE
  ▼
ACTIVE
  ├─ CORRECT: new durable entry + kernel CORRECT → ACTIVE, generation increases
  ├─ CHECKPOINT: durable journal fsync + kernel manifest → CHECKPOINTED
  ├─ DELETE: tombstone entry + kernel DELETE → DELETED
  └─ crash/restart → REPLAYING → ACTIVE or CORRUPT_TAIL

CHECKPOINTED
  │ verified manifest and service journal digest
  ▼
RESTORE_PENDING
  │ kernel recovery restore + journal digest verification
  ▼
RESTORED
  │ userspace record replay and capability rebinding
  ▼
ACTIVE
```

A crash after the journal fsync but before the kernel ioctl is recovered by replay and an idempotent `UPSERT`/dedup request. A crash after the kernel mutation but before the journal fsync is not acknowledged as durable; recovery queries the kernel record and requires a matching journal digest before treating it as committed. This distinction prevents “kernel metadata exists” from being confused with durable semantic memory.

## Acceptance gates

| Gate | Evidence |
|---|---|
| Build | Service and selftest compile with warnings enabled; kernel ABI header remains compatible. |
| Persistence | A record survives service close and restart with matching digest and metadata. |
| Capability denial | A mutation using a stale or wrong authority capability is rejected. |
| Recovery | A checkpoint manifest and journal digest restore after a simulated crash/tail. |
| Corruption | Truncated and digest-corrupt entries are detected and never returned as valid memory. |
| Concurrency | Concurrent readers and serialized writers preserve sequence and digest invariants. |
| Security | Journal permissions, path policy, provenance handling, and model-authority separation are reviewed. |
| Performance | Journal fsync and kernel metadata overhead are measured; no improvement is claimed without baseline. |

## Explicit non-claims

M71 does not implement semantic understanding, vector search, world modeling, skill learning, model retraining, consciousness, or a guarantee that durable storage implies correct knowledge. Those are future userspace services with separate acceptance gates.
