# FAISAL M100 Security Review

**Scope:** `tools/faisal-adapter/faisal_adapter_service.c`, `faisal_adapter_service.h`, the M100 selftest, and the QEMU harness.

**Review date:** 2026-08-16

## Security objective

M100 is designed to prevent a model-selected tool result from becoming an unverified real-world effect. M99 remains the authority boundary. M100 adds deterministic local effect containment and an independently replayable receipt. The model does not receive kernel authority merely by emitting a tool request.

> Landlock and seccomp are defense-in-depth mechanisms. Neither is treated as a complete sandbox or as the source of authorization.[1] [2]

## Threat model

The design assumes a compromised or mistaken model, malicious tool payloads, hostile path strings, stale or revoked authority, duplicate retries after uncertain completion, journal corruption, child-process failure, and a malicious or malformed effect file. It does not assume that a Linux kernel exploit, a malicious privileged supervisor, or arbitrary external systems can be rolled back.

| Threat | Control | Test evidence | Residual risk |
|---|---|---|---|
| Model invents authority | M99 admission and M94 authority lease remain mandatory | M100 QEMU uses `--require-kernel`; M99 regressions pass | A compromised trusted supervisor remains outside M100’s model |
| Path traversal or scope confusion | Absolute directory validation, `..` rejection, fixed `effect.bin`, `O_NOFOLLOW` | `M100_SCOPE_TRAVERSAL_REJECTED_OK` | The caller must provision a dedicated scratch directory |
| Ambient filesystem access | Landlock ruleset restricted to the opened scratch hierarchy | QEMU runs on recovered kernel without Landlock; fallback is explicit | Landlock availability and filesystem semantics vary by kernel/filesystem |
| Excess syscall surface | `PR_SET_NO_NEW_PRIVS` and explicit seccomp allowlist | Production host and QEMU effect path pass | The allowlist is specific to this fixture, not arbitrary commands |
| Duplicate effect | Durable key lookup and committed duplicate refusal | `M100_IDEMPOTENT_DUPLICATE_OK` | Remote side effects are not covered |
| Divergent retry | Input digest comparison returns conflict | `M100_IDEMPOTENCY_CONFLICT_OK` | Digest correctness depends on the trusted invocation producer |
| Crash after local effect | `EFFECTED` receipt precedes M99 completion; retry returns ambiguous | `M100_CRASH_AMBIGUITY_NO_RETRY_OK` | No automatic rollback of arbitrary side effects |
| Revocation race | Tool generation is checked immediately before effect admission | `M100_REVOCATION_BEFORE_EFFECT_DENIED_OK` | A revocation after the check but before a future external effect needs adapter-specific atomicity |
| Output tampering | Read-back, exact payload comparison, pre/post/output digests | `M100_VERIFIED_EFFECT_COMMITTED_OK` | The local filesystem and kernel remain trusted assumptions |
| Journal corruption | Header, sequence, record-size, record digest, and field validation; replay fails closed | `M100_CORRUPTION_FAIL_CLOSED_OK` | Availability is sacrificed after corruption until operator recovery |
| Concurrency | Service mutex protects effect table and journal transitions | TSan pass; full audit pass | The current bounded table is intentionally small |

## Review findings

The adapter keeps the M100 policy and ABI declarations explicit and does not include the FAISAL kernel’s internal `linux/filter.h`, `linux/seccomp.h`, or `linux/landlock.h` headers in userspace. This avoids accidentally compiling kernel-internal types into a userspace service. The local declarations match the documented Linux UAPI layouts and constants used by this fixture; they are limited to the fields M100 consumes.

Landlock failure handling is deliberately narrow. `ENOSYS` means the running kernel does not provide the syscall, so M100 continues with seccomp-only containment and does not claim Landlock coverage. Other Landlock failures remain sandbox errors. This avoids silently converting permission or policy failures into success.

The child writes only after the parent has durably recorded `PENDING`. The parent never trusts the child’s exit status alone: it performs a stat/read-back, exact payload comparison, digest computation, and M99 completion before appending `COMMITTED`. The child is not allowed to select a path or command; it receives a fixed path constructed by the parent.

## Validation and limitations

Strict compilation, host execution, QEMU execution against the real ABI 38 device, UBSan, TSan, GCC `-fanalyzer`, and the aggregate 23-harness regression passed. The ASan+UBSan binary compiled, but execution failed closed because the sanitizer runtime performs behavior not included in the production seccomp allowlist. No sanitizer report was emitted. This is not recorded as an ASan pass. The sanitizer limitation should be addressed in a future test-only mode or with a separately justified sanitizer-compatible policy; production policy must not be widened merely to make a sanitizer runtime succeed.

M100 is not a general command sandbox, browser sandbox, network adapter, payment adapter, deployment adapter, or hardware-device adapter. It does not provide kernel exploit resistance, hardware-backed identity, remote exactly-once effects, semantic prompt-injection detection, or arbitrary rollback. Those claims require separate designs and evidence.

## Security decision

**Decision: acceptable for the bounded deterministic fixture and M100 milestone, not approved for irreversible external effects.** M101 must add a distinct network-isolated adapter contract and retain M100’s receipt, revocation, provenance, independent approval, and ambiguity rules.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Landlock userspace API documentation.

[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux seccomp filter documentation.

[3]: https://arxiv.org/html/2512.01295v1 — Christodorescu et al., “Systems Security Foundations for Agentic Computing.”
