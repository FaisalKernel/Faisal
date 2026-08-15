# FAISAL AGI-Kernel Design Decisions

## D1 — FAISAL is an operating-system program, not a documentation project

The project is complete only when the kernel primitives, trusted system services, runtime contracts, tests, benchmarks, security controls, deployment path, and rollback path operate together. Documents describe evidence and decisions; they do not substitute for implementation.

## D2 — The 14 phases are revisitable capability domains

The phases define dependency domains rather than a terminal checklist. A later service may expose a missing kernel dependency, a benchmark may reopen a completed scheduler feature, and a security finding may move a capability foundation ahead of a planned userspace service. The live dependency graph is authoritative.

## D3 — Routine engineering decisions are autonomous

The engineering agent inspects, researches, designs, implements, builds, tests, diagnoses, fixes, benchmarks, audits, documents, commits, and continues without approval for routine work. It must stop or ask only for genuine external blockers, production authority, sensitive credentials, unavailable hardware/provider access, or an explicit user stop request.

## D4 — Compilation is never the completion gate

A change is not accepted from compilation alone. The minimum serious-kernel gate is build, boot, executable test, regression test, security review, benchmark or an explicit benchmark blocker, failure analysis, and rollback evidence. Fuzzing and stress testing are added according to the interface and risk.

## D5 — Model output is never kernel authority

Natural-language output, graph labels, plans, prompts, embeddings, or model confidence cannot create capabilities, approve privileged actions, change security policy, or authorize deployment. Authority comes from kernel checks, process identity, Linux security policy, trusted services, explicit capability grants, independent supervisors, and operator approval where required.

## D6 — Semantic intelligence stays in userspace

Model execution, reasoning, planning, semantic memory, world-model interpretation, browser logic, web parsing, source ranking, learning policy, and model training remain in userspace services. The kernel provides efficient references, isolation, accounting, events, ordering, and enforcement.

## D7 — Learning and self-awareness have operational definitions

“Learning from one query” means an experience can be recorded with provenance, evaluated, retrieved, corrected, and operationalized as a skill or strategy. It does not imply model retraining. “Self-awareness” means measurable introspection of task, agent, resource, failure, permission, provenance, and world state. It does not imply consciousness.

## D8 — Linux mechanisms are composed, not casually replaced

FAISAL extends or correlates Linux scheduler, VM, VFS, cgroups, namespaces, LSM, seccomp, DMA-buf, IOMMU, HMM, CPUFreq, Devfreq, PM QoS, thermal, Powercap, DTPM, Energy Model, tracepoints, perf, and provider APIs. New kernel interfaces require a demonstrated workload gap and a compatibility/rollback plan.

## D9 — Hardware/provider boundaries are explicit

Generic FAISAL code cannot claim GPU/NPU execution, HMM migration, SVA activation, queue completion, device wake control, thermal coordination, or power-budget enforcement without a real provider contract and hardware evidence. Provider metadata is not device truth unless the provider defines a verifiable completion and lifetime contract.

## D10 — Bounded state and explicit lifetime are mandatory

New session and global structures have fixed bounds, ownership, generation/revocation semantics, lock-order rules, cleanup behavior, and failure paths. No model-size or user-controlled allocation is placed directly in a kernel record without a justified bounded design.

## D11 — Evidence is immutable engineering input

Build logs, raw QEMU serial logs, selftest output, benchmark data, security findings, and failed reproductions are preserved. A failing test is never hidden by deleting its evidence or weakening its assertion without documenting why the assertion was wrong.

## D12 — Production autonomy requires independent control

The AGI may diagnose, propose, build, test, fuzz, benchmark, compare, canary, monitor, and prepare rollback artifacts. Production kernel replacement, privilege expansion, destructive migration, or policy deployment requires an independent trusted supervisor and operator approvals. Self-healing cannot directly rewrite the production kernel.

## D13 — Baselines are mandatory for performance claims

A smoke timing establishes only that a path ran. Claims such as faster, lower latency, lower energy, more scalable, or more deterministic require controlled comparisons with an upstream baseline on the same hardware, configuration, runtime, workload, and thermal state.

## D14 — The dependency graph selects the next work

The next work item is the highest-priority unfinished dependency that unlocks multiple downstream capabilities and has an executable validation path. At the current state, M64 scoped capability/provenance security is selected for stabilization before persistent memory, browser/tool, and multi-agent services.
