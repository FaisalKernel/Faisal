# FAISAL M100 sandbox research checkpoint — 2026-08-16

## Research objective

Identify the smallest premium, first-principles technology that can turn M99’s admitted tool invocation into a bounded effect with stronger containment and verifiable outcome semantics than a generic process launcher.

## Authoritative Linux findings

1. Linux Landlock documentation: https://docs.kernel.org/userspace-api/landlock.html. Landlock is an unprivileged, stackable LSM for restricting ambient filesystem and network rights. Rules describe actions on file hierarchies or network ports, and restrictions are inherited by descendant threads/processes. Its scope is access control; it does not by itself define tool identity, mission intent, idempotency, effect receipts, output sanitization, or rollback. The documentation also records unsupported filesystem actions and overlay-filesystem considerations. M100 should compose Landlock when available, but must not claim Landlock alone is a complete tool sandbox.

2. Linux seccomp documentation: https://docs.kernel.org/userspace-api/seccomp_filter.html. Seccomp filters inspect syscall numbers and arguments and can reduce exposed kernel surface. The official documentation explicitly says syscall filtering is not a sandbox; logical behavior and information-flow policy require other hardening and potentially an LSM. Filters require `no_new_privs` or appropriate privilege, are inherited by descendants, and can use user notifications for selected syscall mediation. M100 should use seccomp as a syscall-surface reduction layer, not as the authority or effect-verification layer.

## M100 first-principles gap

Landlock and seccomp constrain what a process can attempt, but neither answers whether an admitted tool effect was the exact intended effect, whether a retry duplicated it, whether output contains tainted instructions, whether revocation arrived before the effect, or whether a result can be independently verified. The premium FAISAL primitive is therefore a **Verified Effect Capsule**: a deterministic adapter transaction that binds M99 invocation identity, effect scope, canonical input, sandbox policy digest, idempotency key, pre-state digest, post-state digest, output-sanitization digest, and verification receipt into a durable append-only receipt. The adapter must fail closed on scope mismatch, duplicate key with different input, policy drift, revocation, malformed output, missing pre/post evidence, or crash ambiguity.

The initial adapter must be non-network and deterministic. A safe fixture can mutate only a dedicated scratch directory under a Landlock-restricted process and emit a cryptographic receipt; arbitrary shell/network/device/browser effects remain future adapters requiring separate approval and isolation evidence.

## Non-claims

This research does not establish complete sandbox isolation, kernel exploit resistance, hardware-backed identity, rollback of arbitrary side effects, exact-once semantics for remote systems, or prompt-injection immunity. It establishes why M100 must add effect semantics and evidence above existing Linux access-control primitives.


3. Christodorescu et al., “Systems Security Foundations for Agentic Computing,” arXiv:2512.01295v1, https://arxiv.org/html/2512.01295v1. The report argues for deterministic guardrails across hardware, OS, userspace, and application layers because a probabilistic model must not be the trusted computing base. It identifies dynamic task-specific policies, fuzzy security boundaries, semantic gaps, and prompt injection as analogous to difficult dynamic-code-loading problems. M100’s adapter boundary is intended to reduce this semantic gap: M99’s structured invocation becomes a typed effect request, the adapter applies a deterministic sandbox policy, and a receipt records the exact pre/post state and verification outcome. The paper does not establish a complete solution; M100 remains a bounded implementation hypothesis.
