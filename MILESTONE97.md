# FAISAL M97 — Continuity Capsules and Causal Residency Contracts

**Status:** Validated for integration

**Date:** 2026-08-16

**Parent milestone:** FAISAL-M96

**Author:** Manus AI

## Summary

FAISAL M97 implements a new cross-layer continuity primitive: the **Continuity Capsule**, or **Causal Residency Contract**. It binds an M96 committed causal branch to the exact working-state, world-state, and resource-state identities used by that branch. A resume check succeeds only when the current state vector is identical, the task objective generation has not advanced, the committed branch remains valid, and the canonical branch digest matches.

This is not a claim that no other system stores multiple hashes. The novel FAISAL contract is that **durable existence is not sufficient for resumability**: continuation becomes an explicit state-vector consistency decision. The check never grants authority. New side effects still require a fresh M96/M94 authority path.

## Implementation

The service now maintains a bounded `<journal_path>.continuity` append-only journal with fixed-size records, versioned headers, monotonic journal sequence numbers, canonical SHA-256 capsule digests, bounded replay, and fail-closed corruption handling. Capsules have sealed and invalidated states. A capsule can be sealed only for a committed M96 branch and can be invalidated without rewriting history.

The implementation intentionally remains a userspace service primitive. Linux HMM, cgroups, device memory, checkpoint/restore, and the M94 kernel intent lease remain the lower-level mechanisms. No new kernel syscall or ioctl was added because the current evidence does not demonstrate that capsule serialization or state-vector checks are the bottleneck.

## Validation result

| Gate | Result |
|---|---:|
| Strict static build | Pass |
| Host continuity selftest | Pass |
| ASan/UBSan | Pass; exit 0 |
| TSan | Pass; exit 0 |
| Kernel-integrated QEMU with real M94 lease | Pass; exit 0 |
| Three QEMU smokes | 3/3 pass |
| M96 host/QEMU regressions | Pass |
| M95 host/QEMU regressions | Pass |
| M90/M91 regressions | Pass |
| Full FAISAL audit | 23/23 harnesses pass |
| Security scan | All specified patterns clear |

The final QEMU run passed these markers:

```text
FAISAL_M97_BOOT_OK
M97_CONTINUITY_SERVICE_OPEN_OK kernel=1
M97_CONTINUITY_AUTHORITY_REFERENCE_OK lease=1
M97_COMMITTED_BRANCH_PRECONDITION_OK branch=1
M97_CONTINUITY_CAPSULE_SEALED_OK id=1
M97_CONTINUITY_RESUME_EXACT_OK
M97_WORKING_STATE_DRIFT_REJECTED_OK
M97_WORLD_STATE_DRIFT_REJECTED_OK
M97_RESOURCE_STATE_DRIFT_REJECTED_OK
M97_CONTINUITY_REPLAY_OK id=1
M97_CONTINUITY_INVALIDATION_REVOKED_OK
M97_CONTINUITY_CORRUPTION_FAIL_CLOSED_OK
M97_SELFTEST_EXIT=0
FAISAL_M97_TEST_RC=0
FAISAL_M97_CONTINUITY_CAPSULE_QEMU_PASS
```

## Security result

The design rejects working-memory drift, world-state drift, resource-state drift, task-generation drift, branch-digest drift, invalidated branches, malformed records, and corrupted journal tails. The M97 capsule check is observational and cannot authorize a new external action. The full security analysis is in [`M97-SECURITY-REVIEW.md`](M97-SECURITY-REVIEW.md).

## Performance result

Three complete QEMU validation runs took 6,534 ms, 6,413 ms, and 6,460 ms, with a mean of 6,469.00 ms. These are validation-envelope timings, not service latency or energy benchmarks. M97 makes no speedup claim. The required future comparison is against a task-journal-only and checkpoint-only baseline under independently injected state drift.

## Limitations

M97 does not create checkpoints, migrate memory, establish the truthfulness of digest producers, provide distributed consensus, roll back irreversible remote effects, or replace HMM, cgroups, CRIU, or durable-execution systems. A compromised producer can provide a false but consistent digest. Future work must add malformed-journal fuzzing, provenance binding for each state producer, resource/thermal fault injection, and useful-work-per-joule experiments.

M97 also does not create AGI, consciousness, model retraining, or unrestricted autonomous authority. It is a verified systems primitive for continuity and safe resume decisions.

## Evidence

The machine-readable validation record is `tools/faisal-build/evidence/m97-continuity-capsule-validation.json`. Raw logs are stored below `tools/faisal-build/evidence/`. The first-principles design and research record are [`M97-FIRST-PRINCIPLES-DESIGN.md`](M97-FIRST-PRINCIPLES-DESIGN.md) and [`M97-WORLD-TECH-RESEARCH.md`](M97-WORLD-TECH-RESEARCH.md).

## References

[1]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.

[2]: https://docs.kernel.org/mm/hmm.html — Linux kernel documentation, “Heterogeneous Memory Management.”

[3]: https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong — Zhong et al., “Managing Memory Tiers with CXL in Virtualized Environments,” OSDI 2024.

[4]: https://www.iea.org/reports/key-questions-on-energy-and-ai/executive-summary — International Energy Agency, “Key Questions on Energy and AI,” executive summary.
