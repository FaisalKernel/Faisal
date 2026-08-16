# FAISAL Frontier Direction: Causal Authority Fabric

**Status:** Research/design candidate; not yet implemented or validated
**Milestone target:** M96 or a revised dependency selected after repository audit
**Date:** 2026-08-16

## Problem

Long-horizon autonomous systems fail in a way that ordinary task queues and model traces do not make operationally safe. A planner may lose an early constraint, repeat a failed action, continue from a stale observation, retry an external side effect after a crash, or resume with a capability that was valid for an older objective generation. A terminal success bit and a text transcript do not provide a sufficient authorization or recovery boundary.

Linux already provides strong process lifetime, cgroup resource control, checkpoint, event, and capability primitives. Existing workflow research demonstrates that execution and recovery can be separated and that exactly-once orchestration is a distinct layer. FAISAL’s opportunity is to connect those layers to **kernel-enforced intent authority and resource admission** while retaining semantic planning in userspace.

## Proposed abstraction

The Causal Authority Fabric is a bounded, append-only causal ledger for durable tasks. It records a sequence of objective generations and branch nodes. Each proposed action references:

| Field | Meaning |
|---|---|
| Objective generation | The precise durable goal state against which the action was planned |
| Observation frontier | Digest of the observations and verified facts available when the action was proposed |
| Dependency frontier | Completed predecessor tasks and required conditions |
| Authority lease | M94 capability- and intent-bound lease required for the operation |
| Resource admission | CPU, memory, storage, network, accelerator, and monetary budget reservation |
| Branch ID | Speculative path that may be abandoned without committing its side effects |
| Evidence set | Action result, verification result, provenance, and resource receipt |
| Commit state | Proposed, prepared, committed, rejected, invalidated, or compensated |

A branch is speculative until a trusted service verifies that the objective generation, observation frontier, dependency frontier, authority lease, and resource admission still match. Only then can it enter a prepared state. A separate commit gate requires evidence completeness and records the commit before a side-effecting tool is released. A model can propose a branch, but it cannot commit one.

## Novelty boundary

This is not claimed to be a world-first idea. Event sourcing, workflow recovery, exactly-once orchestration, capability systems, cgroups, pidfds, and transactional outboxes are established precedents. The proposed FAISAL contribution is their **single authority-bearing causal contract** across agent lineage, intent digest, resource admission, observation freshness, and recovery branch state. Whether this is better than current designs is an empirical question.

## Measurable superiority hypotheses

| Hypothesis | Metric | Baseline | Acceptance direction |
|---|---|---|---|
| Causal state reduces recovery ambiguity | Fraction of injected crashes where the supervisor selects one authorized next action without human reinterpretation | M95 journal replay | Higher, with zero stale-lease authorizations |
| Branch invalidation prevents stale actions | Stale objective/observation/lease attempts rejected after branch invalidation | M95 retry and lease checks | 100% rejection in exhaustive bounded tests |
| Evidence gate improves auditability | Time to reconstruct agent, objective, observation, authority, resource, and result lineage | M95 journal plus logs | Lower reconstruction time at equal event volume |
| Resource admission reduces wasted execution | Completed useful objectives per CPU-second under contention and injected failures | FIFO M95 worker queue | Higher or no worse, with no policy violations |
| Recovery avoids unnecessary redo | Valid work retained after a failed branch | Restart-from-last-task baseline | Higher retained-work ratio |
| Security cost remains bounded | Added per-record and per-action overhead | M95 journal path | Measured overhead reported; no unsupported target |

## Minimal implementation boundary

The first increment must not add a model runtime, browser, parser, distributed consensus, or kernel semantic planner. It should add a bounded userspace branch/evidence ledger integrated with M95 and M94:

1. Add fixed-size branch and evidence records with canonical digests.
2. Add objective-generation and observation-frontier checks.
3. Add explicit `prepare`, `commit`, `invalidate`, and `replay` transitions.
4. Require a valid M94 intent lease for prepared side-effect actions.
5. Reject stale, revoked, budget-exhausted, incomplete, or mismatched commits.
6. Inject crashes at each journal phase and verify deterministic replay.
7. Compare audit reconstruction and useful-work retention against M95.

The kernel remains the enforcement point for identity, capabilities, intent leases, resource controls, and lifecycle. The userspace service remains responsible for semantic objective interpretation, observation verification, tool selection, and compensation policy.

## Security properties

A branch digest is integrity evidence, not authority. A model-generated digest cannot grant itself permission. Commit requires an already-issued kernel capability and M94 intent lease, matching task and objective generations, current resource admission, complete evidence, and independent supervisor approval. Revocation invalidates all uncommitted branches that reference the revoked authority. Journal corruption fails closed.

## Explicit non-claims

The design does not claim a new foundation model, consciousness, guaranteed autonomy, exactly-once real-world side effects, rollback of irreversible external actions, universal accelerator support, hardware-backed attestation, zero overhead, 1000× productivity, or superiority over current systems before benchmark evidence exists.
