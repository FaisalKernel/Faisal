# FAISAL M96 — Causal Authority Fabric

**Status:** Validated for integration

**Date:** 2026-08-16

**Parent:** FAISAL-M95

**Author:** Manus AI

## Executive summary

FAISAL M96 adds a bounded, append-only Causal Authority Fabric to the durable-task service. A causal branch records its task and objective generation, authority reference, observation frontier, dependency frontier, resource admission, evidence, and terminal outcome. The service prepares only authorized current branches and commits only branches with verified observation, result, and verification evidence.

The implementation reuses the existing ABI-38 M94 kernel intent-lease ioctl. It adds no new syscall or ioctl, does not place model inference or planning in the kernel, and does not equate model output with authority. The kernel-integrated QEMU test acquired a real intent lease and passed all M96 acceptance gates.

## Delivered implementation

| Area | Delivered result |
|---|---|
| Causal persistence | Separate `<journal_path>.causal` append-only journal with FCA1/versioned records and canonical SHA-256 digest |
| Branch lifecycle | Proposed, prepared, committed, rejected, and invalidated states with bounded transitions |
| Authority binding | Agent/task/lease/operation/capability/objective-generation reference bound to M94 kernel intent lease |
| Admission gates | Task lifecycle, lease expiry, objective generation, resource admission, and kernel authorization checks |
| Evidence gate | Exactly three required verified evidence kinds for commit: observation, result, verification |
| Recovery | Replay reconstructs causal state and fails closed on malformed or corrupted records |
| Testing | Host selftest, QEMU kernel selftest, ASan/UBSan, TSan, three smoke runs, M95/M90/M91 regressions, and 23-harness audit |
| Documentation | Research, design, security, benchmark, milestone, and machine-readable evidence records |

## Verification result

All planned M96 validation gates passed.

| Gate | Result |
|---|---:|
| Strict userspace build | Pass |
| Host causal selftest | Pass |
| ASan/UBSan | Pass, exit 0 |
| TSan | Pass, exit 0 |
| Kernel-integrated QEMU with `--require-kernel` | Pass, exit 0 |
| QEMU smoke validations | 3/3 pass |
| M95 host and QEMU regressions | Pass |
| M90 key-provider regression | Pass |
| M91 provider-gate regression | Pass |
| Full FAISAL audit | 23/23 harnesses pass |
| Security-pattern scan | All specified patterns clear |
| Git whitespace check | Pass |

The kernel-integrated log contains the following markers:

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

## Security conclusion

M96 preserves the authority boundary between high-level autonomous software and the kernel. A branch proposal is not authorization. A durable record is not permission. The service must revalidate current task state, lease validity, objective generation, resource admission, and kernel intent authority before preparation and again before commit. Incomplete evidence is rejected, invalidated branches cannot be reused, and causal journal corruption is fail-closed.

The implementation deliberately does not execute arbitrary commands, grant root, invoke models, or perform live kernel replacement. Production deployment still requires independent trusted-supervisor and operator approval. The full review is in [`M96-SECURITY-REVIEW.md`](M96-SECURITY-REVIEW.md).

## Performance statement

The three QEMU validation runs completed in 6,195 ms, 6,341 ms, and 6,188 ms, with a mean of 6,241.33 ms. These are end-to-end sandbox/QEMU validation-envelope measurements, not isolated service or kernel latency measurements. M96 makes no speedup claim. A controlled comparison against M95 and an upstream baseline remains future benchmark work.

## Limitations and future work

M96 does not provide transactional rollback for arbitrary irreversible external effects, prove the truthfulness of external evidence, or implement a universal exactly-once distributed workflow. It does not retrain a model, create consciousness, or make an AGI. The bounded 64-branch and 8-evidence limits are conservative admission controls, not a final scalability result. Future work should add malformed-journal fuzzing, fault-injected lease revocation tests, external side-effect executor integration under an independent supervisor, and a controlled recovery-ambiguity benchmark.

## Repository evidence

The machine-readable validation record is [`tools/faisal-build/evidence/m96-causal-authority-validation.json`](tools/faisal-build/evidence/m96-causal-authority-validation.json). Raw logs are stored under [`tools/faisal-build/evidence/`](tools/faisal-build/evidence/). The two inherited M63 files remain untracked and are explicitly excluded from the M96 changeset.

## References

[1]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.

[2]: https://www.usenix.org/conference/osdi23/presentation/zhuang — Zhuang et al., “ExoFlow: A Universal Workflow System for Exactly-Once DAGs,” OSDI 2023.

[3]: https://docs.kernel.org/admin-guide/cgroup-v2.html — Linux kernel documentation, “Control Group v2.”

[4]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.

[5]: https://criu.org/Main_Page — CRIU project documentation.
