# FAISAL M100 — Verified Effect Capsule and Deterministic Tool-Adapter Sandbox

**Status:** Validated and ready for commit

**Date:** 2026-08-16

## Purpose

M99 establishes that a tool invocation is admitted only when tool identity, operation scope, mission binding, authority lease, risk, provenance, revocation generation, and verification policy are valid. M100 adds the missing effect boundary: a deterministic adapter must prove what local state it observed, what it changed, what output it produced, and whether the effect can be safely resumed after a crash.

The implementation is a userspace service above the existing FAISAL M98/M99 services. It does not add a kernel ABI change. Its deterministic fixture writes the caller-approved payload only to a fixed `effect.bin` path inside a caller-provided scratch directory. The child process applies `PR_SET_NO_NEW_PRIVS`, a Landlock filesystem restriction when the running kernel supports it, and a deny-by-default seccomp syscall allowlist. When Landlock is unavailable with `ENOSYS`, M100 records a seccomp-only execution path rather than pretending that Landlock is active.

## Verified Effect Capsule

Each durable receipt binds the M99 invocation, mission, tool, agent, authority lease, registry and revocation generations, idempotency key digest, invocation input digest, sandbox-policy digest, scope, pre-state digest, post-state digest, output digest, read-back verification, result code, and lifecycle state. The append-only `.effects` journal uses per-record digests and monotonic sequence numbers; malformed, truncated, reordered, or tampered records fail closed during replay.

The state machine distinguishes `PENDING`, `EFFECTED`, `COMMITTED`, and `FAILED`. M100 writes `PENDING` before the child effect, writes `EFFECTED` only after read-back and digest verification, and writes `COMMITTED` only after successful M99 completion. If execution reaches `EFFECTED` but the authority commit is interrupted, the receipt is returned as **ambiguous** and the same idempotency key is refused for automatic retry. A committed duplicate returns `M100_ERR_DUPLICATE`; a divergent input returns `M100_ERR_CONFLICT`.

## Validation matrix

| Validation | Result | Evidence |
|---|---:|---|
| Strict host build, `-Wall -Wextra -Werror` | Pass | `build/m100/selftest-build5.log` |
| Host deterministic selftest | Pass | `build/m100/host-selftest4.log` |
| Real-kernel QEMU with `--require-kernel` | Pass | `build/m100/qemu-harness.log` |
| UBSan selftest | Pass | `build/m100/ubsan-run.log` |
| TSan selftest | Pass | `build/m100/tsan-run.log` |
| GCC `-fanalyzer` adapter scan | Pass | `build/m100/gcc-analyzer.log` |
| Full FAISAL aggregate regression | 23/23 pass | `build/m100/full-audit.log`, `build/recovered/full-audit-summary.txt` |
| Host timing smoke, five runs | 5/5 pass; 20–21 ms | `build/m100/benchmark-host.csv` |

The ASan+UBSan binary built successfully, but its child process was rejected by the production seccomp policy because the sanitizer runtime requires additional post-filter behavior. This is recorded as a test-harness incompatibility, not a security bypass or a passing sanitizer result. UBSan and TSan completed successfully; the normal host selftest and real-kernel QEMU path exercised the production sandbox policy.

## Security and compatibility boundary

M100 does not claim complete sandbox isolation, kernel exploit resistance, hardware-backed identity, remote exactly-once semantics, rollback of arbitrary external effects, prompt-injection immunity, or production readiness. The model remains unable to mint M99 authority, alter the adapter policy, or forge a receipt. Existing Linux filesystems, networking, drivers, and the ABI 38 kernel interface remain unchanged.

## Next dependency

The next unblocked dependency is M101. The preferred direction is a non-deterministic browser/research adapter that remains network-isolated and uses M100 receipts, M75/M77 trusted services, M99 capability admission, M98 mission binding, and independent supervisor/operator approval. No irreversible external effect should be exposed without adapter-specific containment and verification evidence.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Landlock userspace API documentation.

[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux seccomp filter documentation.

[3]: https://arxiv.org/html/2512.01295v1 — Christodorescu et al., “Systems Security Foundations for Agentic Computing.”
