# FAISAL M96 — Benchmarks and Validation Measurements

**Status:** Validation report

**Date:** 2026-08-16

**Author:** Manus AI

## Measurement policy

M96 is primarily a correctness, authorization, replay, and auditability milestone. The available runs measure validation and boot-to-poweroff behavior; they do not constitute a full workload-performance comparison against upstream Linux or M95. Accordingly, this report does not claim that M96 is faster, more efficient, or superior on throughput without a controlled benchmark.

## Validation matrix

| Test | Configuration | Result |
|---|---|---|
| Strict host build | GCC, C11, `-Wall -Wextra -Werror`, static link | Pass |
| Host causal selftest | Host mode, all nine causal markers | Pass; `M96_SELFTEST_EXIT=0` |
| ASan/UBSan | `-fsanitize=address,undefined`, leak detection and halt-on-error | Pass; exit 0 |
| TSan | `-fsanitize=thread`, halt-on-error | Pass; exit 0 |
| Kernel-integrated QEMU | FAISAL recovered kernel, ABI 38, `--require-kernel` | Pass; exit 0 |
| Three clean QEMU smokes | Fresh rootfs/image/log per run | 3/3 pass |
| M95 host regression | Extended service linked with M95 selftest | Pass |
| M95 QEMU regression | Extended service, recovered kernel, durable-task harness | Pass |
| Security pattern scan | M96 source, selftest, harness, and notes | All patterns clear |

## QEMU smoke timing

The timing below is wall-clock time for each complete harness invocation, including initramfs creation, QEMU boot, selftest execution, log checks, and poweroff. It is a validation-envelope measurement, not an isolated service latency benchmark.

| Run | Wall-clock time |
|---:|---:|
| 1 | 6,195 ms |
| 2 | 6,341 ms |
| 3 | 6,188 ms |
| **Minimum** | **6,188 ms** |
| **Mean** | **6,241.33 ms** |
| **Maximum** | **6,341 ms** |

The three-run spread is 153 ms, or approximately 2.45% of the mean. The environment is a sandboxed QEMU/TCG setup, so these values should not be used as hardware performance estimates.

## Functional markers measured

The kernel-integrated run produced the following acceptance sequence:

```text
FAISAL_M96_BOOT_OK
M96_CAUSAL_SERVICE_OPEN_OK kernel=1
M96_AUTHORITY_REFERENCE_OK lease=1
M96_CAUSAL_BRANCH_PROPOSE_OK id=1 generation=2
M96_CAUSAL_PREPARE_AUTHORIZED_OK
M96_INCOMPLETE_COMMIT_REJECTED_OK
M96_EVIDENCE_COMPLETE_COMMIT_OK id=2
M96_BRANCH_INVALIDATION_OK
M96_CAUSAL_REPLAY_OK committed=1
M96_CAUSAL_CORRUPTION_FAIL_CLOSED_OK
M96_SELFTEST_EXIT=0
FAISAL_M96_TEST_RC=0
FAISAL_M96_CAUSAL_AUTHORITY_QEMU_PASS
```

This sequence demonstrates that the selftest opened the service through the kernel path, obtained an intent lease, rejected an incomplete commit, accepted an evidence-complete commit, invalidated a branch, replayed a committed branch, and failed closed after causal-journal corruption.

## Performance work intentionally deferred

A defensible superiority claim requires controlled measurements against the M95 journal and a suitable baseline. The next benchmark should use identical task graphs, injected failures, and resource policies while measuring recovery ambiguity, commit latency, journal bytes per transition, fsync cost, branch fan-out, concurrent query throughput, and time to reconstruct agent/objective/authority/evidence lineage. It should also separate kernel ioctl cost from userspace journal cost.

M96 therefore records a **correctness and validation result**, not a speedup claim. The causal layer’s architectural advantage is a testable hypothesis: richer durable authority and evidence state may reduce unsafe or ambiguous recovery decisions, but that must be demonstrated by a future controlled experiment.

## References

[1]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.

[2]: https://www.usenix.org/conference/osdi23/presentation/zhuang — Zhuang et al., “ExoFlow: A Universal Workflow System for Exactly-Once DAGs,” OSDI 2023.
