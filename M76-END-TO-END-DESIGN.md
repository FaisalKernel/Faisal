# FAISAL M76 End-to-End Multi-Agent Integration Design

## Scope

M76 composes the validated M72 experience service, M73 world-state service, M74 model orchestration service, and M75 browser/tool broker into a bounded end-to-end control-plane fixture. It also exercises FAISAL light-agent registration, IPC channels/messages, queued-message cancellation, reflection, observability, and deterministic failure recovery. The model and browser engines remain userspace components; this milestone does not claim a complete AGI runtime or production deployment.

## Task graph and roles

The fixture represents a long-horizon goal as a staged graph:

```text
COORDINATOR
├── PLANNER → BROWSER/RESEARCH → VERIFIER
├── MEMORY/EXPERIENCE RETENTION
└── MONITOR → RECOVER → CANARY/ROLLBACK
```

The coordinator owns the control-plane session. Planner and verifier are kernel light-agent identities with separate capabilities and roles. A channel carries coordinator-to-planner work; a queued message is deliberately cancelled to verify cancellation; light-agent messages carry planner/verifier and verifier/coordinator acknowledgements. Each transition is bounded, attributable, and observable.

## Service composition

Because each existing service owns a kernel session and attaches the current task lineage, M76 executes the M72, M74, M73, and M75 stages sequentially in their own service sessions, persists their outputs, closes them, and then opens a final coordinator session for IPC and monitoring. This avoids pretending that separate kernel lineages are one session. The coordinator receives bounded summaries and provenance sequences from the completed service stages and uses them as inputs to the multi-agent task graph.

| Stage | Composed service | Verified result |
|---|---|---|
| Experience | M72 | Durable evaluated/reusable experience record |
| Model admission | M74 | Explicit approvals, budgets, checkpoint, output proposal, rollback |
| World observation | M73 | Bounded fact, temporal probe, resource snapshot, sequence evidence |
| Browser/tool observation | M75 | Scoped browser action, hostile-content boundary, cancellation |
| Coordination | M76 control plane | Light agents, IPC, cancellation, reflection, observability, recovery |

## IPC and cancellation contract

Inline IPC is bounded to the FAISAL UAPI limit. Every message includes channel identity, source/target agent and capabilities, type/schema, priority, correlation, and payload length. The kernel chooses the highest-priority queued message on receive and rejects malformed or unauthorized endpoints. M76 cancels a known queued message with `AGI_LC_IPC_CANCEL`; it does not fabricate delivery or completion after cancellation. Light-agent acknowledgements are sent only after the receiving agent has been selected in the control session.

## Monitoring and reflection

M76 enables sampled observability, begins a reflection action for the long-horizon coordinator step, and records an action end state. Reflection snapshots report measured kernel counters such as agent count, blocked/failed/cancelled counts, resource counters, and event sequence. Observability query counters are reported as operational telemetry only. These records are not semantic self-awareness or consciousness.

## Failure and recovery

A deterministic failure injection can interrupt a named stage. The coordinator marks the task as failed, records a recovery reflection state, preserves completed durable service outputs, and reports a recovery decision. The recovery fixture then performs a bounded retry/canary path and either marks the candidate recovered or selects rollback. No stage is reported complete when its failure injection was active. The recovery result is a control-plane outcome, not proof that arbitrary model or browser state was restored.

## Deployment gate

A candidate is eligible for the test canary only if all of the following are independently supplied: trusted-supervisor approval, operator approval, completed selftests, security-negative pass, and regression pass. A model or page string cannot satisfy either approval. If any gate is missing, the candidate is denied and the fixture selects rollback. M76 does not deploy a production kernel or service; production replacement remains subject to independent trusted-supervisor and operator approval.

## Explicit non-claims

M76 does not claim consciousness, semantic truth, unrestricted autonomy, model retraining, reliable browser use, safe real-world action, complete multi-agent scalability, complete failure recovery, or production deployment. Durable memory is not retraining. Reflection is measurable telemetry, not consciousness. A passing end-to-end fixture is not evidence that the system is generally intelligent.
