# FAISAL Pasted Specification — Requirement-to-Implementation Map

**Source:** `PASTED-CONTENT-STRUCTURED.md` and `PASTED-CONTENT-RAW.txt`
**Repository state inspected:** FAISAL-M94, Linux v7.2-rc7-derived tree, ABI 38
**Purpose:** Convert the 2,035-line user specification into executable implementation dependencies without treating existing names or documentation as proof of functionality.

## Current conclusion

The attachment describes a complete autonomous-execution platform, while the repository currently contains a validated kernel control plane and a collection of bounded userspace services. It is not yet a complete enterprise autonomous-intelligence system. The strongest existing foundations are lifecycle identity, capabilities, provenance, cancellation, resource accounting, event delivery, checkpoints, memory and experience services, world-state synchronization, browser and research boundaries, orchestration, deployment supervision, runtime verification, provider-gated attestation, and M94 intent-bound authority leases.

The most important gap exposed by the specification is **durable objective execution**. The current header has graph-node, lifecycle, checkpoint, event, resource, and agent operations, but inspection did not find a first-class persistent goal/mission object or a durable task queue with worker leases, idempotency keys, retry policy, heartbeats, dead-letter handling, restart recovery, and explicit stop conditions. A graph metadata object is not a durable execution engine. This is the next architectural focus.

## Capability status matrix

| Specification domain | Current FAISAL state | Evidence or source path | Decision |
|---|---|---|---|
| Kernel lifecycle and agent identity | Validated kernel primitive | `drivers/misc/agi_lifecycle.c`, `include/uapi/linux/agi_lifecycle.h`, M64–M94 evidence | Retain and extend only through additive contracts. |
| Capability security and provenance | Validated bounded controls | FAISAL capability grants, provenance records, M64/M90–M94 tests | Preserve model-output non-authority and add policy composition rather than bypassing Linux security. |
| Intent-bound action authority | Validated in M94 | `AGI_LC_INTENT_LEASE`, M94 selftest and QEMU evidence | Integrate with durable task execution; do not claim universal syscall interception. |
| Graph and heterogeneous execution metadata | Partial kernel control plane | Graph/context/tensor/accelerator UAPI and tests | Keep provider-neutral and hardware-gated. |
| Goals and mission hierarchy | Missing as a first-class durable kernel/service contract | No dedicated goal/mission object or goal ioctl found in current UAPI inventory | Highest-value next dependency: durable objective state. |
| Planner and executable DAG | Partial metadata and userspace orchestration | Graph operations, model orchestration, end-to-end tests | Add durable task contracts and recovery semantics before expanding planner intelligence. |
| Durable execution engine | Partial checkpoints and userspace services; no unified queue contract | Checkpoint/recovery driver paths; no durable queue/worker/heartbeat contract found | Implement bounded task records, leases, retry/backoff, idempotency, dead-letter, and stop conditions in userspace first, with kernel identity/resource/policy linkage. |
| Agent runtime and model routing | Partial userspace services | `tools/faisal-orchestrator`, model orchestration selftests | Define typed provider-neutral contracts; model execution remains userspace. |
| Secure tool abstraction | Partial browser/research/deployment boundaries | `tools/faisal-*`, browser and research UAPI | Generalize tool metadata and risk/policy contracts in userspace; kernel enforces capabilities and leases. |
| Memory classes and experience | Validated bounded services | `tools/faisal-memory`, `faisal-experience`, M71–M83 evidence | Add lifecycle links from task outcomes to durable objectives and evaluation. |
| World model and knowledge provenance | Partial/validated bounded services | `tools/faisal-world`, `tools/faisal-research`, M73/M77 evidence | Preserve fact/source/inference/conflict boundaries; add mission event synchronization. |
| Self-evaluation and continuous improvement | Partial deployment/self-healing/evaluation paths | M74/M78/M85/M87 evidence | Require independent evaluator records and explicit keep/reject gates; no unrestricted self-modification. |
| Economic intelligence and value metrics | Mostly missing as an integrated contract | Resource/cost fields exist in scattered structures; no unified value ledger found | Defer until durable task outcome records exist; then add measured value/cost records in userspace. |
| Resource budgets | Partial and validated | Resource demand/snapshot, budget, accelerator, power UAPI | Link budget exhaustion to durable task stop conditions and queue admission. |
| Scheduler and event bus | Partial kernel hints and event queue | scheduler hints, lifecycle event queue, world sync, QEMU tests | Add durable event-triggered task admission in userspace; do not replace Linux scheduler without benchmark evidence. |
| Observability and replay | Partial/validated telemetry and provenance | graph telemetry, observability, reflection, experience, audit evidence | Extend correlation to task/goal IDs and replay-safe redaction. |
| Failure intelligence and self-healing | Partial bounded recovery | M78/M85/M87 evidence; checkpoint/recovery | Add typed failure classification, retry budgets, circuit breakers, quarantine, and dead-letter state to durable execution. |
| Security, tenancy, policy | Security primitives validated; enterprise tenancy incomplete | capabilities, namespaces/LSM composition, M94; no complete tenant control plane found | Implement tenant-scoped durable records and policy references before enterprise claims. |
| Human escalation | Structured policy boundary incomplete | approval gates and deployment supervisor exist; no general escalation object found | Add escalation records as userspace policy-service work, not hidden kernel authority. |
| Continuous operation | Boot/QEMU services and recovery tests exist; no unified mission daemon | Multiple service harnesses; no one durable mission loop | Build a supervised mission/execution service with explicit stop conditions and restart recovery. |
| Dynamic capability discovery | Provider-gated components exist; general discovery incomplete | key provider, accelerator provider gate, deployment supervisor | Require schema/security/health/policy/evaluation admission before registration. |
| Simulation/digital twin/causal reasoning | Partial truth-boundary services; no general simulator | M82 simulation boundary, M73 world model | Add interfaces and evidence records only after durable objective/task state. |
| Adaptive context | Not a kernel responsibility; no unified service contract found | Existing memory/world/orchestrator components | Implement userspace context assembly linked to goal/task state. |
| Data/memory lifecycle | Partial validated memory lifecycle | memory service and transaction tests | Add tenant/policy links and task retention references. |
| Reliability mechanisms | Partial across services | retries/recovery/rollback appear in individual services | Consolidate contracts through durable task engine rather than duplicating ad hoc retries. |
| Performance and cost benchmarking | Validation timing exists; outcome baselines incomplete | M94 benchmark report and historic evidence | Define baseline and threshold per feature; do not claim productivity gains. |
| Artifacts and versioning | Partial signed bundles/deployment artifacts | M78/M87/M90 evidence | Link artifacts to durable tasks and verification results. |
| Kernel API/CLI/configuration | Kernel UAPI is broad and typed; CLI/configuration are fragmented | `agi_lifecycle.h`, harnesses | Avoid adding dozens of syscalls; extend one bounded ABI only when justified. |
| Testing/adversarial evaluation | Strong QEMU and sanitizer regression infrastructure | 23-harness audit, KASAN/KCSAN, fuzz/selftests | Add durable-task fault injection, duplicate execution, stale lease, crash, budget, and policy tests. |
| Enterprise scale | Not established | No multi-node production evidence | Preserve provider-neutral interfaces; do not claim enterprise readiness. |
| Replayability | Partial structured telemetry/checkpoints | M81–M94 evidence | Add secret-redacted durable task event journals. |

## Kernel versus userspace allocation

The attachment uses “kernel” broadly, but the safe implementation boundary is narrower. The kernel should own identity, lineage, capabilities, resource accounting, event delivery, cancellation, bounded authority, checkpoint references, isolation, and auditable state transitions. Userspace services should own semantic goal interpretation, planning, model routing, tool protocols, research, browser control, memory indexing, evaluation, economic reasoning, simulation, and enterprise integrations. A durable execution service can be a trusted userspace component linked to FAISAL kernel objects; putting a database, language model, browser, or unrestricted planner inside the kernel would violate the specification’s own security and maintainability constraints.

## Proposed implementation dependency sequence

| Milestone | Objective | Why now | Acceptance boundary |
|---|---|---|---|
| M95 | Durable objective and task execution contract | It is the largest gap in the attachment’s required implementation order and unlocks mission mode, recovery, value, and evaluation. | Typed durable goal/task records; DAG dependency state; task lease/heartbeat; retry/backoff; idempotency; stop conditions; budget/policy references; restart/replay test; no model authority. |
| M96 | Supervisor-mediated provider ownership and crash recovery | Existing M93/M94 provider and lease lifetimes need explicit supervisor ownership after durable task state exists. | Ownership generation, stale-service reclamation, restart/reacquisition, secret isolation, fault injection, sanitizer, and rollback. |
| M97 | General tool registry and risk/cost-aware selection contract | The attachment requires secure tool abstraction and minimal useful toolsets, while current browser/research tools are specialized. | Schema validation, capability/risk/cost/latency metadata, policy filtering, health, registration revocation, adversarial tool description tests. |
| M98 | Independent evaluation and outcome/value ledger | Completion, correctness, usefulness, and economic value must be separated from activity. | Evaluator records, success criteria, cost/time/risk, causal evidence fields, keep/reject gates, replay, and baseline benchmark. |
| M99 | Continuous mission scheduler and event-triggered execution | Durable tasks and goals provide the state required for autonomous operation after restart. | Periodic/event/dependency triggers, watchdogs, backpressure, load shedding, circuit breakers, safe stop, and recovery. |
| M100 | Tenant-scoped policy and structured escalation | Enterprise boundaries require explicit policy and escalation rather than implicit human dependence. | Tenant isolation, policy decision records, approval levels, structured escalation, deny-by-default tests, no cross-tenant leakage. |

The existing governance-selected M95 provider-recovery item should be moved after the durable objective/task contract rather than silently implemented out of sequence. This is a graph revision, not a claim that provider recovery is unimportant; it reflects the user specification’s explicit priority for core execution state and durable task execution.

## Completion definition for this specification

The specification is not satisfied by the number of UAPI constants, service names, or booting tests. A requirement becomes validated only when real code exercises the behavior, the failure path is tested, the security boundary is reviewed, resource and stop conditions are measured, restart/replay behavior is demonstrated where applicable, and the result is connected to an objective/task outcome. The complete system remains unfinished until goal creation, decomposition, strategy/tool/model selection, execution, persistence, recovery, verification, cost/outcome measurement, failure learning, policy enforcement, credential protection, tenant boundaries, telemetry, continuous operation, restart adaptation, self-evaluation, and measurable strategy improvement all have executable evidence.
