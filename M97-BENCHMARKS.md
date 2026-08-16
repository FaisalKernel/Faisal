# FAISAL M97 — Continuity Capsule Benchmarks

**Status:** Validation report

**Date:** 2026-08-16

**Author:** Manus AI

## Measurement policy

M97 is a correctness and state-continuity milestone. The recorded QEMU timings measure an end-to-end validation envelope including initramfs creation, kernel boot, userspace journal creation, state-vector checks, log verification, and poweroff. They do not isolate capsule seal latency, resume-check latency, memory movement, energy use, or useful work. No performance improvement claim is made.

## Validation matrix

| Test | Result |
|---|---:|
| Strict static build | Pass |
| Host selftest | Pass; exact, working, world, and resource drift markers present |
| ASan/UBSan | Pass; exit 0 |
| TSan | Pass; exit 0 |
| Kernel-integrated QEMU with `--require-kernel` | Pass; exit 0 |
| Three clean QEMU smokes | 3/3 pass |
| M96 host and QEMU regressions | Pass |
| M95 host and QEMU regressions | Pass |
| M90 key-provider regression | Pass |
| M91 provider-gate regression | Pass |
| Full FAISAL regression | 23/23 harnesses pass |
| Security-pattern scan | All specified patterns clear |

## QEMU smoke timing

| Run | Wall-clock validation time |
|---:|---:|
| 1 | 6,534 ms |
| 2 | 6,413 ms |
| 3 | 6,460 ms |
| **Minimum** | **6,413 ms** |
| **Mean** | **6,469.00 ms** |
| **Maximum** | **6,534 ms** |

The observed spread is 121 ms, approximately 1.87% of the mean. These measurements come from the sandboxed QEMU/TCG environment and should not be interpreted as hardware performance results.

## Functional measurement markers

The final kernel-integrated run produced:

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

## Required superiority experiment

The central hypothesis is not that capsule code is faster than a journal. It is that a state-vector contract prevents unsafe resume decisions that a task-journal-only or checkpoint-digest-only baseline would accept. A future controlled benchmark must create identical committed branches and inject independent working, world, resource, objective-generation, and branch-lineage drift. It should report unsafe-resume acceptance rate, correct-stale rejection rate, recovery decision latency, bytes written per state transition, seal cost, resume-check cost, and useful work preserved after failure.

A second experiment should measure whether state-aware admission reduces wasted compute and energy under thermal or memory-tier pressure. The IEA reports rapidly increasing AI data-centre power demand and large workload power swings [1], while CXL studies show that memory tiering can suffer from contention and application-oblivious placement [2]. FAISAL should not claim improvement until those measurements exist.

## Explicit non-claims

M97 does not claim lower latency, higher throughput, lower energy, better model quality, a new hardware memory tier, exactly-once external effects, or a universal checkpoint replacement. It claims only the validated state-vector equality and fail-closed behavior exercised by the tests.

## References

[1]: https://www.iea.org/reports/key-questions-on-energy-and-ai/executive-summary — International Energy Agency, “Key Questions on Energy and AI,” executive summary.

[2]: https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong — Zhong et al., “Managing Memory Tiers with CXL in Virtualized Environments,” OSDI 2024.
