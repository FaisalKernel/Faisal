# FAISAL M85 — Controlled Self-Healing Design

## Objective

M85 adds controlled autonomous recovery for bounded FAISAL userspace services. “Self-healing” means the supervisor can detect a known failure, diagnose it against a fixed policy table, restore a verified checkpoint, or activate a pre-approved repair candidate through a canary and rollback path. It does not mean that an AI can rewrite and authorize arbitrary kernel code.

## State machine

```text
OBSERVED
   ↓
DETECTED
   ↓
DIAGNOSED
   ├── known rollback class ──> ROLLBACK_REQUIRED ──> RECOVERED
   ├── approved repair class ─> REPAIR_VALIDATED -> CANARY
   │                                                   ├── pass -> RECOVERED
   │                                                   └── fail -> rollback -> RECOVERED
   ├── security/unknown class -> QUARANTINED
   └── policy/retry failure ---> QUARANTINED or FAILED
```

Every transition is bounded and audit-recorded. A signal is an observation, not an authorization. Diagnosis is a deterministic policy mapping for the supported signal classes. The supervisor never treats model prose as a command to activate a repair.

## Signal classes

The initial implementation handles health, resource, corruption, security, timeout, and dependency signals. Health, resource, corruption, and timeout failures trigger automatic rollback when policy permits. Dependency failures may use a repair candidate, but only if the candidate has the required independent supervisor, operator, integrity, and canary approvals. Security signals quarantine rather than attempting autonomous repair.

Unknown or malformed signal inputs are rejected. The supervisor accepts at most 32 signals and audit records per service instance. Recovery attempts are capped at three. A retry limit forces quarantine rather than an infinite restart loop.

## Repair contract

A candidate must satisfy the existing M78 candidate contract: bounded build identifier, nonzero artifact and state digests, approved supervisor/operator/integrity/canary bits, distinct nonces, policy generation, CPU and memory limits, and a digest recomputed independently by the supervisor. The candidate is admitted, checkpointed, canaried, and activated only through M78’s existing state machine.

The self-healing service does not compile code, sign artifacts, modify kernel text, load modules, or grant capabilities. A higher-trust deployment pipeline may produce a candidate, but activation remains subject to the independent supervisor and operator approval contract.

## Rollback contract

Before recovery, the supervisor preserves the checkpoint digest. Post-checkpoint signals and audit transitions are retained in the bounded supervisor record but are not appended to the checkpointed M71 journal until recovery verification has completed. This prevents an observation from changing the state digest that the recovery operation is required to verify. The existing M78/M71 recovery path then marks the service crashed, restores the verified checkpoint, imports the validated handoff, and continues execution.

## Failure policy

| Failure | Automatic action | Reason |
|---|---|---|
| Health failure | Checkpoint rollback | Known reversible service failure |
| Resource pressure | Checkpoint rollback | Avoid continued degradation |
| State corruption | Rollback then escalate on failure | Preserve last verified state |
| Timeout | Rollback | Bound long-running failure |
| Dependency failure | Approved repair canary | Requires trusted candidate |
| Security signal | Quarantine | Do not auto-repair a possible compromise |
| Unknown signal | Reject/quarantine | No implicit authority |
| Repeated failure | Quarantine | Prevent restart loops |

## Recovery invariants

The supervisor must never activate a candidate without independent approvals and digest verification. It must never continue after a failed checkpoint verification. It must never mutate a checkpointed journal before recovery verification. It must never silently discard an audit transition. It must never infer successful repair from process restart alone; success requires a canary and explicit recovered state.
