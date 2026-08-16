# FAISAL M100 — Verified Effect Capsule and Deterministic Tool-Adapter Sandbox

**Status:** Design complete; implementation next

**Date:** 2026-08-16

## First-principles observation

M99 can admit a tool invocation, but admission is not the same as a safe effect. Linux Landlock restricts ambient filesystem and network rights, while seccomp reduces the exposed syscall surface. The Linux documentation explicitly describes seccomp filtering as **not a complete sandbox**, and agent-security research identifies semantic gaps, dynamic task policies, fuzzy boundaries, and probabilistic trusted-computing bases as unresolved problems [1] [2] [3].

A premium FAISAL adapter therefore needs a second invariant above access control:

> **An effect is resumable and reportable only when its identity, scope, input, sandbox policy, pre-state, post-state, output, verification, and idempotency key are all durably bound in one receipt.**

## Proposed technology: Verified Effect Capsule

A Verified Effect Capsule is a fixed-format durable record for one deterministic adapter effect. It binds:

| Field | Purpose |
|---|---|
| M99 invocation identity | Prevents an adapter result from being attributed to another action |
| Tool and mission identity | Preserves the M98/M99 causal chain |
| Idempotency key | Prevents retrying the same effect with divergent input |
| Input digest | Separates model-selected content from the effect actually applied |
| Sandbox-policy digest | Makes the Landlock/no-new-privileges/seccomp policy auditable |
| Effect scope | Restricts the adapter to one dedicated scratch directory and fixed file name |
| Pre-state digest | Records the state observed before mutation |
| Post-state digest | Records the state after mutation |
| Sanitized output digest | Proves the output passed deterministic content checks |
| Verification receipt | Shows that the local effect was read back and matched the expected bytes |
| Commit state | Distinguishes pending, effected-but-ambiguous, failed, and committed states |

The first implementation is intentionally non-network and deterministic. It writes an approved payload to a fixed `effect.bin` file inside a caller-provided dedicated scratch directory. A forked child applies `PR_SET_NO_NEW_PRIVS`, a Landlock filesystem policy, and a seccomp syscall allowlist before opening or writing the file. The parent computes pre/post digests, validates output encoding, and commits the M99 invocation only after read-back verification.

## Crash and retry semantics

The adapter persists a `PENDING` receipt before applying the effect. It persists `EFFECTED` before attempting the M99 completion commit. If a crash or injected failure occurs after the local effect but before the authority commit, replay preserves the receipt as **ambiguous** and refuses automatic retry. A duplicate with the same idempotency key returns the ambiguous receipt; a divergent input is rejected. This is stronger than blindly retrying a tool call, but it does not roll back arbitrary external systems.

## Security boundary

The model can propose the M99 action, but it cannot create the registry entry, mint authority, change the sandbox policy, or forge a verification receipt. Landlock and seccomp are defense-in-depth controls; M99 remains the authority admission layer; M100 is the effect and receipt layer; M98/M96 remain the mission and causal commit layers.

## Explicit non-claims

M100 will not claim arbitrary command execution safety, complete process isolation, kernel exploit resistance, hardware-backed identity, remote exactly-once semantics, rollback of irreversible effects, prompt-injection immunity, or production readiness. The deterministic fixture is a proof of the contract, not a browser, network, payment, deployment, or device adapter.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux kernel Landlock userspace API documentation.

[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux kernel seccomp filter documentation.

[3]: https://arxiv.org/html/2512.01295v1 — Christodorescu et al., “Systems Security Foundations for Agentic Computing.”
