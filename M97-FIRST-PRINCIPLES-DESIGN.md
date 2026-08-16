# FAISAL M97 — Continuity Capsules and Causal Residency Contracts

**Status:** Implemented and validation-backed

**Date:** 2026-08-16

**Author:** Manus AI

## First-principles problem

A long-horizon autonomous task is not only a sequence of process states. It is a coupled state vector:

```text
intent authority
+ objective generation
+ working-state identity
+ world-observation identity
+ resource/thermal admission
+ verification evidence
+ execution lineage
```

Existing systems provide strong pieces of this vector. Linux HMM and device-memory APIs address shared address spaces and migration; CXL systems address capacity and tier placement; checkpoint systems preserve process state; durable-execution systems replay workflow state; and FAISAL M96 binds causal branches to kernel intent authority. The missing invariant is a **single verifiable continuity decision** that says whether a previously committed execution state may be resumed under the same world, resource, objective, and lineage assumptions.

The failure mode is subtle: a task can be durably replayable while its world observation is stale, its resource admission is gone, its working memory has changed, or its branch has been invalidated. Resuming it merely because a checkpoint exists can turn a valid historical result into a new unauthorized action.

## Proposed new technology

M97 introduces a **Continuity Capsule**, also called a **Causal Residency Contract**. A capsule is a bounded, append-only, digest-sealed record attached to an M96 committed branch. It binds four state dimensions:

| Dimension | Meaning |
|---|---|
| Working state digest | Identity of the user-space working memory or checkpoint manifest used by the committed branch |
| World state digest | Identity of the observation/world-model frontier used by the branch |
| Resource state digest | Identity of the CPU/memory/accelerator/thermal admission snapshot used by the branch |
| Causal branch digest | Identity of the committed M96 branch and its evidence-complete authority context |

A resume check succeeds only if all dimensions match the current supplied state vector and the branch remains committed. Any mismatch returns an explicit stale result. Invalidated branches and corrupted capsule journals fail closed. The capsule does **not** authorize a new side effect; a caller must obtain fresh M96/M94 authority for any new action.

This is not a claim that no other system has ever stored multiple digests. The innovation hypothesis is the cross-layer enforcement contract: **resume is a state-vector consistency decision, not a process-restart decision**. Its superiority must be measured against a baseline that checks only a durable task record or checkpoint digest.

## Why this belongs above the kernel in the first implementation

The first implementation is a bounded FAISAL service primitive because semantic working-memory, world-model, and resource-manifest digests are produced by trusted system services, not by the Linux kernel. The kernel remains the authority for process identity, capabilities, leases, cgroups, memory, devices, and security. M97 consumes those trusted facts and refuses to interpret model output as any of them.

A later kernel ABI could expose an efficient capsule handle or event stream after a workload proves that userspace serialization is the bottleneck. Adding a new ioctl before that measurement would violate the project’s minimal-ABI rule.

## State machine

```text
COMMITTED M96 BRANCH
        |
        | seal working/world/resource digests
        v
SEALED CONTINUITY CAPSULE
        |
        +--> resume check: exact state vector --> RESUMABLE
        |
        +--> any digest mismatch -----------> STALE / reacquire state
        |
        +--> branch invalidated ------------> REVOKED
        |
        +--> malformed/corrupt journal ------> FAIL CLOSED
```

A capsule may be sealed only for a committed branch. It is immutable except for an append-only invalidation record. The resume check is observational: it returns whether the old state remains valid and never issues a capability, lease, or external action.

## Acceptance hypotheses

| Hypothesis | Baseline | Measurement |
|---|---|---|
| Cross-domain stale-state detection prevents unsafe resume | Task journal or checkpoint digest alone | Inject working/world/resource drift independently and measure rejection rate |
| Continuity replay is deterministic | Reconstruct from task and causal journals only | Restart, replay, and compare capsule digest/state |
| Capsule sealing is bounded | Unbounded checkpoint metadata or service logs | Bytes and time per seal/resume check |
| No authority confusion | Resume check treated as action authorization | Attempt post-check action without fresh lease and verify denial in integrated service tests |

## Explicit non-claims

M97 does not claim a new memory-management algorithm, a new hardware interconnect, exactly-once remote side effects, automatic checkpoint creation, truthfulness of supplied digests, model retraining, consciousness, or a universal replacement for Linux HMM, cgroups, CRIU, or existing durable-execution systems. It is a testable cross-layer contract whose value depends on independent trusted producers for the state digests.

## References

[1]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.

[2]: https://docs.kernel.org/mm/hmm.html — Linux kernel documentation, “Heterogeneous Memory Management.”

[3]: https://www.usenix.org/conference/osdi24/presentation/zhong-yuhong — Zhong et al., “Managing Memory Tiers with CXL in Virtualized Environments,” OSDI 2024.

[4]: https://www.iea.org/reports/key-questions-on-energy-and-ai/executive-summary — International Energy Agency, “Key Questions on Energy and AI,” executive summary.
