# FAISAL M71 — Persistent Memory Service

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** First userspace durable-memory service integrated with FAISAL kernel metadata, capability checks, provenance references, checkpoint manifests, execution gates, and recovery.

## Implementation

M71 adds `tools/faisal-memory/faisal_memory_service.c` and its header. The service keeps semantic content in a `0600` append-only journal with fixed-size headers, bounded content, sequence numbers, tier/confidence/importance metadata, optional provenance sequence, and SHA-256 content digests. It synchronizes each acknowledged record with `AGI_LC_MEMORY_RECORD`, using the kernel-generated authority capability and generation returned by the kernel.

The service does not persist kernel capabilities as semantic content. A restarted service replays the durable journal, creates a fresh FAISAL session, and rehydrates fresh kernel metadata rather than trusting old session-local record IDs or authority capabilities.

M71 integrates the kernel checkpoint path. It closes the execution gate, creates a checkpoint, attaches a user-state manifest, verifies the state digest, exports the validated handoff, persists the checkpoint sidecar, marks a simulated crash, and on restart performs digest verification, recovery restore, checkpoint verification/import, continuation, and gate reopening.

## Validation

The full kernel and module build passed. The static service/selftest build passed with warnings enabled. Three repeated QEMU runs passed all persistence, capability, checkpoint, recovery, replay, and corruption markers. M64 and M66–M70 regression harnesses also passed against the completed security kernel.

```text
FAISAL_M71_BOOT_OK
M71_PUT_OK record=1 generation=1
M71_GET_DIGEST_OK
M71_STALE_CAPABILITY_REJECT_OK
M71_CHECKPOINT_OK id=8142508126285856770 sequence=4
M71_CRASH_MARK_OK
M71_RESTART_REPLAY_OK record=1
M71_VERIFIED_RESTORE_OK
M71_INCOMPLETE_TAIL_RECOVERED_OK
M71_CORRUPT_DIGEST_REJECT_OK
M71_SELFTEST_EXIT=0
FAISAL_M71_TEST_RC=0
```

## Explicit non-claims

M71 does not implement semantic understanding, vector search, world modeling, procedural skill learning, model orchestration, foundation-model retraining, distributed consensus, encryption at rest, production database throughput, or consciousness. The service proves durable experience retention and recovery; it does not claim that remembered content is correct or that a neural model learned from it.

## Evidence

The contract is in `M71-PERSISTENT-MEMORY-DESIGN.md`; the security review is in `M71-SECURITY-REVIEW.md`; benchmark limits are in `M71-BENCHMARKS.md`; machine-readable evidence is in `tools/faisal-build/evidence/m71-persistent-memory-validation.json`; and the raw QEMU serial log is `tools/faisal-build/evidence/m71-qemu.log`.
