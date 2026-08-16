# FAISAL M98 — Mission Autonomy Control Loop

**Status:** Design target

**Date:** 2026-08-16

**Author:** Manus AI

## Purpose

FAISAL already has durable task records, causal authority branches, and continuity capsules, but those primitives do not yet form a persistent autonomous operating loop. M98 adds the smallest missing control contract: a mission supervisor that repeatedly turns a durable objective into bounded observe → propose → admit → prepare → await trusted execution → verify → commit → continue/replan/stop/escalate cycles.

This is not a language model in the kernel and not an unrestricted autonomous agent. It is a deterministic state machine that coordinates trusted services. A model may propose an observation interpretation, plan, or tool choice, but the supervisor accepts only structured inputs and delegates authority to M94/M96 gates.

## Current-world requirements

Current reliability research separates consistency, robustness, predictability, and safety rather than treating terminal success as sufficient [1]. Government guidance on agentic systems emphasizes least privilege, per-invocation authorization, identity, continuous monitoring, tool validation, segmentation, resource limits, and resilient recovery [2]. NIST identifies agent authentication/identity infrastructure, open protocols, and security evaluations as active priorities [3].

M98 therefore makes the following enforceable:

| Requirement | M98 contract |
|---|---|
| Persistence | Mission and stop/escalation decisions are journaled and replayable |
| Long-horizon operation | Bounded step cycles with explicit wakeups, replan, continue, stop, and escalate states |
| Authority separation | Model proposals never authorize; M94 lease + M96 branch gates remain mandatory |
| Per-invocation checks | Every action proposal is checked against current task, continuity, policy, deadline, budget, and authority |
| Recovery | Restart replays the mission journal and resumes only from a valid durable state; stale continuity forces observation/replan |
| Safety | Risk, deadline, CPU/money budget, retry, and max-step limits produce deterministic stops |
| Accountability | Mission, task, branch, capsule, action, evidence, and escalation identifiers remain correlated |
| Human/supervisor boundary | Policy failures become escalation, not silent retries or model overrides |

## State machine

```text
NEW → ACTIVE → OBSERVE_REQUIRED → PROPOSAL_REQUIRED
                         │              │
                         │              └─ policy/authority denial → ESCALATED
                         │
                         └─ stale capsule → OBSERVE_REQUIRED

PROPOSAL_REQUIRED → PREPARED → EXECUTION_PENDING → EVIDENCE_PENDING
                                      │                     │
                                      └─ timeout/budget ────┴→ STOPPED

EVIDENCE_PENDING → COMMITTED → CONTINUE / REPLAN / SUCCEEDED
                              └→ ESCALATED on failed verification or risk
```

The state machine never assumes that a committed record means an external side effect was exactly once. A trusted tool broker owns actual side-effect execution and must provide its own idempotency and authorization evidence.

## Minimal API boundary

M98 will expose a C userspace service with:

1. Mission creation from a durable M95 objective and bounded policy.
2. Event submission with monotonic event sequence and trigger class.
3. Observation admission carrying working/world/resource digests.
4. Plan proposal admission carrying action digest, resource mask, risk class, and opaque model provenance.
5. Preparation through M96 authority and M97 continuity checks.
6. Result and verification evidence submission through M96 commit gates.
7. Deterministic decision evaluation: continue, replan, stop, or escalate.
8. Restart replay with corruption fail-closed behavior.

The implementation uses a scripted callback/selftest harness rather than a model. This proves control semantics without fabricating model intelligence.

## First-principles novelty hypothesis

The innovation hypothesis is **autonomy as a journaled control loop with authority-preserving failure semantics**. Existing workflow engines, agent frameworks, and OS services may provide parts of this behavior, but M98 makes the loop’s continuation decision depend on the combined M95 task state, M96 evidence-complete causal branch, and M97 state-vector continuity contract. A task is not merely “running”; it must be in a specific durable control state with a valid reason to continue.

The hypothesis is measurable against a baseline that restarts a task from its last durable record without explicit stop/escalation or continuity revalidation. M98 must demonstrate stale-state rejection, budget/deadline stopping, deterministic recovery, no-authority proposal rejection, and escalation on verification failure.

## Explicit non-claims

M98 does not claim general intelligence, model reliability, consciousness, model retraining, autonomous kernel modification, exactly-once remote effects, truthfulness of external observations, distributed consensus, or a complete tool ecosystem. It does not replace Linux scheduling, cgroups, capabilities, LSM, HMM, or browser/tool services. It is a bounded autonomy-control primitive above those mechanisms.

## References

[1]: https://arxiv.org/html/2602.16666v1 — Rabanser et al., “Towards a Science of AI Agent Reliability,” 2026.

[2]: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF — ASD ACSC, CISA, NSA, Canadian Cyber Security Centre, NCSC-NZ, and NCSC-UK, “Careful adoption of agentic AI services,” 2026.

[3]: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative — NIST, “AI Agent Standards Initiative,” updated 2026.
