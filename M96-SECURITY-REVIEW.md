# FAISAL M96 — Security Review

**Status:** Reviewed against the implemented M96 source and validation artifacts

**Date:** 2026-08-16

**Author:** Manus AI

## Security objective

M96 is intended to make durable autonomous execution more attributable and less permissive under restart, retry, stale state, and journal corruption. Its security objective is not to make a model trustworthy. It is to ensure that model-produced data cannot bypass a kernel-enforced intent lease or the service’s explicit admission and evidence gates.

The review follows FAISAL’s central rule:

> **Model output must never equal kernel authorization.**

A causal branch may describe a proposed action, but the service can prepare or commit it only when the task lifecycle, lease, objective generation, resource admission, authority reference, and evidence conditions are valid.

## Threat model

| Threat | M96 control | Validation |
|---|---|---|
| Prompt-injected or compromised model requests a privileged action | Model text is never consumed as kernel authority; authority is obtained through the M94 intent-lease ioctl | QEMU `--require-kernel` run and security-pattern scan |
| Stale branch is replayed after objective change | Branch stores objective generation; prepare and commit require a current matching generation | Causal state-machine tests; kernel-backed authority reference marker |
| Lease expires or is revoked during execution | Prepare and commit re-query the kernel lease; commit consumes the lease | QEMU real-device path; authorization gate implementation review |
| Incomplete or unverifiable result is committed | Commit requires verified observation, result, and verification evidence | `M96_INCOMPLETE_COMMIT_REJECTED_OK`; `M96_EVIDENCE_COMPLETE_COMMIT_OK` |
| Invalidated branch is reused | Terminal invalidated state rejects future preparation or commit | `M96_BRANCH_INVALIDATION_OK` |
| Journal tail is truncated or modified | Fixed headers, bounded lengths, canonical SHA-256 digest, sequence/state validation, and fail-closed replay | `M96_CAUSAL_CORRUPTION_FAIL_CLOSED_OK`; ASan/UBSan; QEMU |
| Resource exhaustion through unbounded branch/evidence input | Maximum 64 branches, 8 evidence items per branch, bounded payloads and provenance | Source review and selftest coverage |
| Concurrent mutation causes inconsistent authorization | Service lock serializes branch/evidence/journal mutation; queries copy stable state | TSan pass and concurrent inherited M95 regression |
| Unauthorized external side effect is inferred from a durable record | M96 records authorization context but does not execute arbitrary external side effects or claim rollback | Design boundary; no `system`, `popen`, `execve`, `setuid`, `ptrace`, or model-authority integration found |

## Trusted computing base and trust boundaries

The kernel lifecycle driver and its ABI-38 intent-lease implementation are the trusted authority boundary for kernel authorization. The M96 userspace service is trusted to enforce its own state-machine policy but is not treated as equivalent to the kernel. The model, planner, browser, research engine, and other high-level components are untrusted input producers from the perspective of authorization.

The service’s causal journal is an evidence and audit mechanism. It is not a substitute for Linux capabilities, LSM policy, cgroups, namespaces, seccomp, pidfds, or device-driver authorization. A deployment must still place the service and its workers inside an independently configured security domain and must require an independent trusted supervisor and operator approval for production changes.

## Fail-closed properties

M96 fails closed in the following cases:

1. The causal journal cannot be opened, has an invalid header, contains an oversized record, or has a digest mismatch.
2. A branch transition is invalid, a branch is missing, or the branch is already terminal.
3. The task is not `LEASED` or `RUNNING`, its lease is expired, its objective generation differs, or resource admission is zero.
4. Kernel authority cannot be queried or consumed in required-kernel mode.
5. The evidence set lacks a verified observation, result, or verification record.
6. A branch has been invalidated or the service has marked the causal journal unusable after corruption.

The corruption injector test intentionally damages the causal tail and confirms that replay reports failure rather than reconstructing a potentially unsafe state.

## Memory and parser safety

All persistent records use fixed-width integer fields and explicit lengths. The replay path validates record length before allocation and checks branch and evidence bounds before indexing. The implementation is compiled with strict warnings as errors. The host selftest passes with AddressSanitizer and UndefinedBehaviorSanitizer, and the ThreadSanitizer run reports no race. The QEMU run confirms that the same selftest reaches the real ABI-38 kernel authority path.

These results are evidence for the tested paths, not a proof of absence of all kernel or userspace vulnerabilities. Additional fuzzing of malformed journal records and adversarial interleavings remains a future hardening task.

## Security scan result

The M96 files were scanned with fixed-string matching for the following high-risk patterns: `system(`, `popen(`, `execve(`, `setuid(`, `ptrace(`, `invokeLLM`, `model_output`, `livepatch`, and `CAP_SYS_ADMIN`. All patterns were clear in the implementation, selftest, QEMU harness, and M96 notes. The scan is a screening control, not a substitute for code review, static analysis, LSM testing, or fuzzing.

## Residual risks

M96 does not prevent a trusted service from misusing an authority lease within the policy it has been granted. It does not provide transactional rollback for irreversible remote actions. It does not prove provenance of external observations; provenance strings and digests are only as trustworthy as the producer and verification service. It does not establish confidentiality of journal contents, so deployments handling sensitive evidence must protect the journal with filesystem permissions, encryption, and appropriate key management.

The service currently uses a host-mode bypass when `kernel_fd < 0`; this is intentional for deterministic userspace tests and must not be accepted as sufficient production validation. Production harnesses must use `--require-kernel`, as the M96 QEMU gate does.

## Security conclusion

Within its bounded scope, M96 preserves the kernel/service authority separation, rejects incomplete and stale causal branches, invalidates unsafe branches, and fails closed on causal-journal corruption. The evidence supports integration of the implementation as FAISAL-M96, with the residual risks and future fuzzing requirements recorded above.

## References

[1]: https://docs.kernel.org/admin-guide/cgroup-v2.html — Linux kernel documentation, “Control Group v2.”

[2]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.

[3]: https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html — Linux man-pages, `pidfd_send_signal(2)`.
