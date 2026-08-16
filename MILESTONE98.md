# FAISAL M98 — Mission Autonomy Control Loop

**Status:** Validated and committed as `FAISAL-M98` at `08947b8f1ccac5d24b523baf29d7976b2627e66a`

**Date:** 2026-08-16

## Objective

M98 closes the largest remaining autonomy gap after M97: FAISAL had durable tasks, causal authority, and continuity checks, but no single persistent control loop that could safely decide whether a mission should continue, replan, stop, or escalate.

M98 adds a deterministic userspace Mission Autonomy Control Loop. It is not a model and does not claim consciousness or general intelligence. Its purpose is to make autonomy an enforceable lifecycle rather than an unbounded process loop.

## Implemented behavior

The new `tools/faisal-mission/` service provides:

| Capability | Implementation |
|---|---|
| Durable mission creation | M95 task submission and lease claim plus a fixed-format `.mission` journal |
| Event-driven progress | Monotonic observation event sequences and manual/event/timer/recovery trigger classes |
| Authority separation | Model provenance is recorded, but M96 proposal/prepare requires an M94 authority reference and current task/resource state |
| Evidence-gated action | Results require observation, result, and independent verification evidence before M96 commit |
| Continuation | A committed branch seals an M97 Continuity Capsule; the next observation must match working/world/resource state |
| Replanning | State-vector drift returns a public stale result and enters `M98_MISSION_REPLAN_REQUIRED` |
| Recovery | In-flight execution or evidence-pending state replays as explicit escalation rather than automatic duplicate execution |
| Safety stops | Deadline, CPU budget, money budget, maximum steps, retry limit, and risk ceiling are persisted and enforced |
| Concurrency | Mutex-protected query path with four concurrent workers |
| Integrity | Monotonic journal sequence, fixed record sizes, canonical SHA-256 digest, and corruption fail-closed replay |

## Validation

The final candidate passed strict build, host execution, ASan/UBSan, TSan, real-kernel QEMU with `--require-kernel`, three clean QEMU smokes, M95/M96/M90/M91 regressions, full 23/23 FAISAL audit, and the targeted security-pattern scan.

The QEMU selftest proves the following markers: service open with `kernel=1`, real authority reference, mission creation, observation admission, unauthorized model-proposal rejection, authorized proposal preparation, evidence-complete commit and capsule seal, stable continuation observation, world-state drift replan, replay, in-flight recovery escalation, deadline stop, concurrent query locking, corruption fail-closed behavior, and exit 0.

## Architectural significance

M98 makes the autonomy decision itself durable and auditable. A mission is not considered healthy merely because a process is alive. It must have a current observation, a valid authority-bound proposal, evidence-complete execution, state continuity, and a policy-permitted reason to continue. Unknown or ambiguous states stop or escalate.

This is a first-principles systems innovation hypothesis: **autonomy is a journaled, authority-preserving control loop whose continuation decision depends on causal evidence and state continuity**. It is deliberately implemented above Linux’s existing scheduler, cgroups, capabilities, storage, networking, and security mechanisms rather than replacing them.

## Explicit limitations

M98 does not provide a language model, planning intelligence, browser implementation, tool registry, truthful world observations, autonomous kernel modification, exactly-once remote side effects, distributed consensus, hardware-backed identity, energy optimization, or complete AGI. Model-generated plans remain untrusted proposals. External side-effect execution remains the responsibility of a separately authorized tool broker.

The implementation is bounded to 16 mission records in memory and fixed-size journal records. The current benchmark measures only a QEMU validation envelope. A production deployment would require larger-capacity design, power-loss testing, multi-tenant isolation, formal review of digest producers, fault injection against tools, long-duration soak, and comparative baseline measurements.

## Rollback

Rollback is a Git revert of the M98 commit and removal of the standalone mission service and harness. M95–M97 journals and APIs remain independently usable because M98 composes them without changing ABI 38.

## Next dependency

The next high-value dependency is **M99 capability-scoped tool registry and execution broker**. It should bind each tool to identity, risk, cost, provenance, verification requirements, revocation, resource budgets, and independent approval, then become the only path through which M98 can execute real external actions.
