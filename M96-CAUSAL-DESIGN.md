# FAISAL M96 — Causal Authority Fabric Design

**Status:** Implemented and validation-gated

**Date:** 2026-08-16

**Author:** Manus AI

## Purpose and boundary

FAISAL M96 adds a bounded, append-only causal ledger to the M95 durable-task service. The ledger records branch proposals, evidence, preparation, commit, and invalidation as durable state transitions. Its purpose is to reduce recovery ambiguity for long-running autonomous work while ensuring that a durable record is not confused with authority to perform an external action.

The implementation is deliberately smaller than a general workflow engine. It does **not** execute model output, does not embed a planner or inference engine in the kernel, does not provide exactly-once semantics for arbitrary external systems, and does not claim consciousness or model retraining. The trusted boundary remains the FAISAL kernel intent-lease interface introduced in M94 and the service-side policy gates around it.

> **Authority rule:** Model output is data. Kernel authorization requires a valid process identity, capability and intent lease, objective generation, lease validity, resource admission, and the service’s evidence gate. A model cannot authorize itself by emitting a command.

## Why the M95 journal needed a causal layer

M95 durably records task lifecycle state, retries, leases, deadlines, budgets, dependencies, and dead-letter outcomes. That is sufficient to reconstruct a task state, but it does not by itself express why a candidate action was selected, which observation frontier it depended on, whether a supervisor-approved intent was still current, or whether completion evidence was sufficient.

Research on long-horizon agent evaluation emphasizes trajectory-grounded failure diagnosis rather than terminal success alone [1]. Durable-execution systems and exactly-once workflow research establish important precedents, but also show that execution durability and side-effect semantics are separate concerns [2] [3]. M96 therefore adds a causal authorization record without replacing Linux process, cgroup, pidfd, VFS, networking, or security infrastructure.

## Object model

| Object | Durable fields | Security meaning |
|---|---|---|
| Branch | Branch ID, task ID, objective generation, parent branch, state, authority reference, observation digest, dependency frontier, resource admission, timestamps, canonical digest | Names one candidate execution lineage and the policy context under which it may be evaluated |
| Authority reference | Agent ID, task ID, lease ID, operation, capability, objective generation, expiry | Binds the branch to the M94 kernel intent lease and prevents stale-generation reuse |
| Evidence | Kind, verified bit, sequence, digest, provenance text, timestamp | Supplies explicit facts required before a branch can commit |
| Causal record | Append-only header, transition, branch payload, SHA-256 digest | Makes replay fail closed on truncation, malformed records, or digest mismatch |

The branch state machine is bounded to five states: `PROPOSED`, `PREPARED`, `COMMITTED`, `REJECTED`, and `INVALIDATED`. A branch can be proposed once, prepared only after authorization checks, committed only after the required verified evidence is present, and invalidated as a terminal non-authorizing outcome.

## Admission and commit protocol

The service follows this protocol:

```text
PROPOSE
  -> bind task/objective generation, authority reference, observation frontier,
     dependency frontier, and resource admission

PREPARE
  -> require LEASED or RUNNING task
  -> require unexpired task lease and matching objective generation
  -> require non-zero resource admission
  -> query the real M94 kernel intent lease
  -> transition to PREPARED and append a digest-checked record

EVIDENCE
  -> append bounded evidence records
  -> accept only known evidence kinds and bounded payloads
  -> preserve verification status and provenance

COMMIT
  -> re-run all authorization and admission checks
  -> require exactly one verified OBSERVATION, RESULT, and VERIFICATION item
  -> consume the M94 kernel intent lease
  -> append COMMITTED record only after all gates pass

INVALIDATE
  -> append INVALIDATED record
  -> prevent future preparation or commit of the branch

REPLAY
  -> verify record shape, sequence, and canonical SHA-256 digest
  -> rebuild branch state and evidence
  -> fail closed on any causal-journal corruption
```

The implementation requires **three verified evidence items of the required kinds**—observation, result, and verification—for commit. Additional bounded evidence kinds are supported for provenance and resource context, but they do not silently substitute for the required three.

## Persistence and replay

The causal ledger is stored beside the M95 task journal at `<journal_path>.causal`. Each record contains a fixed magic value (`FCA1`), version, record type, branch identifier, payload length, and canonical digest. Digest calculation zeroes the digest field before hashing the complete canonical branch representation. Replay stops and marks the service unusable if the journal has a short header, invalid record type, oversized payload, invalid branch transition, sequence discontinuity, or digest mismatch.

This is an append-only service journal, not a filesystem replacement and not a claim that arbitrary remote side effects are transactionally committed. An external action still needs an independently trusted supervisor or policy-controlled executor. The ledger makes the authorization context and evidence durable; it cannot roll back an email, payment, deployment, or other irreversible side effect by itself.

## Kernel binding

M96 reuses the M94 ABI-38 `AGI_LC_INTENT_LEASE` ioctl. In kernel mode, the service opens `/dev/agi_lifecycle`, establishes its lifecycle session, and queries or consumes the intent lease through the existing kernel interface. Host-mode selftests intentionally use `kernel_fd < 0` and skip the device check, which permits deterministic userspace testing of journal and state-machine behavior. The QEMU harness runs with `--require-kernel` and therefore validates the real kernel path.

The design preserves Linux’s existing boundaries. Resource accounting remains compatible with cgroup-style hierarchical controls [4], stable task references remain compatible with pidfds [5], and checkpoint/restore remains a userspace/system-service concern compatible with CRIU [6]. M96 does not add a new syscall or ioctl.

## Concurrency and bounds

The service serializes journal mutation under its service lock. Branch and evidence counts are bounded at 64 branches per service and 8 evidence items per branch. Payload lengths, provenance strings, and replay records are bounded before allocation. The append path uses `write` plus `fsync` and only advances in-memory state after the durable record is accepted. Query operations copy stable state while holding the lock and do not expose internal pointers.

These bounds are correctness and denial-of-service controls. They are not a claim that the design is optimal for all agent populations. Scaling beyond the bounded service requires a separately benchmarked sharding or kernel-backed event design.

## Frontier hypotheses and non-claims

| Hypothesis | Required future measurement | Current status |
|---|---|---|
| Causal records reduce recovery ambiguity | Compare unambiguous next-authorized-action rate against M95-only replay under fault injection | M96 interface and replay path implemented; comparative experiment remains future work |
| Authority-bound replay rejects stale side effects | Inject lease revocation and objective-generation changes before prepare/commit | Current gates are tested; external side-effect executor is future work |
| Evidence-carrying commits improve audit reconstruction | Measure reconstruction time and missing-field rate | Current selftest proves required evidence gating; performance study remains future work |
| Branch invalidation reduces safe-recovery redo | Compare branch resume with restart-from-last-task-state | Branch invalidation is implemented; workload benchmark remains future work |

M96 therefore claims a **validated causal authorization substrate**, not AGI, exactly-once distributed side effects, self-improving model weights, or a universal heterogeneous compute scheduler.

## References

[1]: https://arxiv.org/html/2604.11978v1 — Wang et al., “The Long-Horizon Task Mirage? Diagnosing Where and Why Agentic Systems Break,” arXiv, 2026.

[2]: https://restate.dev/what-is-durable-execution — Restate, “What is Durable Execution?”

[3]: https://www.usenix.org/conference/osdi23/presentation/zhuang — Zhuang et al., “ExoFlow: A Universal Workflow System for Exactly-Once DAGs,” OSDI 2023.

[4]: https://docs.kernel.org/admin-guide/cgroup-v2.html — Linux kernel documentation, “Control Group v2.”

[5]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html — Linux man-pages, `pidfd_open(2)`.

[6]: https://criu.org/Main_Page — CRIU project documentation.
