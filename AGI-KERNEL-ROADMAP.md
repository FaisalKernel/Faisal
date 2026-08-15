# FAISAL AGI-Native Kernel Roadmap

## Mission

FAISAL will become a Linux-derived operating system whose kernel and system services provide native primitives for persistent autonomous agents, long-horizon execution, memory, experience-based learning, world-state observation, verified information acquisition, multi-agent coordination, secure tool use, and adaptive resource allocation.

This roadmap is an active dependency graph. The 14 strategic phases are not a sequence of documents that can be checked off. Each phase contains implementation work, tests, benchmarks, security gates, downstream integrations, and possible rework.

## Current position

| Item | State |
|---|---|
| Linux foundation | Verified Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7` |
| Latest integrated FAISAL security completion | `FAISAL-M64-SECURITY-COMPLETION` on top of ABI 37 and M70 |
| Kernel ABI | 37 |
| Validated kernel primitives | Lifecycle, agent/task identity, memory/tensor metadata, scoped capabilities, provenance binding, graph/context control plane, tensor transport metadata, deterministic domains, heterogeneous-context negotiation, graph telemetry, CPU PM QoS policy intent |
| Next selected dependency | M71 persistent memory service integrated with kernel capabilities, provenance, checkpoints, and recovery |
| Complete-system status | Not operational; userspace services and end-to-end autonomous integration remain unfinished |

## Strategic domains and implementation gates

### Phase 1 — Linux foundation and verified baseline

Maintain the exact upstream revision, configuration, toolchain, reproducible build metadata, boot path, driver compatibility, security hardening, and rollback image. Re-run this gate when the upstream base or toolchain changes.

### Phase 2 — AGI task, agent, and lifecycle substrate

Provide bounded identity, lineage, task/agent metadata, goals, phases, budgets, cancellation, resource accounting, provenance, and lifecycle events. The acceptance gate requires executable lifecycle, authorization, revocation, failure, and attribution tests.

### Phase 3 — Cognitive-aware scheduling and execution domains

Compose with Linux scheduling, affinity, cgroups, deadlines, CPU isolation, PM QoS, and provider queues. Implement only enforceable kernel hints and control contracts. A cognitive label is never a scheduler authorization and no scheduler improvement is claimed without a baseline benchmark.

### Phase 4 — Selective events, world-state observation, and observability

Deliver filtered, bounded, backpressured event streams and graph-operation telemetry. Add service-facing state snapshots and provenance correlation. Semantic interpretation, model drift classification, and world modeling remain userspace responsibilities.

### Phase 5 — Memory, tensor objects, checkpoint, and recovery primitives

Build capability-scoped memory regions, tier metadata, tensor layout policy, snapshot/checkpoint coordination, recovery manifests, and failure-safe restore contracts without moving semantic databases or model training into kernel space.

### Phase 6 — Agent IPC and cancellation

Provide secure structured messaging, streaming, backpressure, large-message references, priority, cancellation, timeout, hierarchical cancellation, and resource revocation while reusing Linux IPC where it meets the workload.

### Phase 7 — Capability security and provenance

Complete scoped tensor/context grants, generation checks, provenance binding, denial auditing, Linux LSM/DAC/namespace/seccomp composition, and trusted-supervisor policy. This phase gates browser control, tool use, persistent memory mutation, and multi-agent deployment.

### Phase 8 — Heterogeneous accelerator and resource integration

Extend the vendor-neutral control plane only through real provider contracts. Integrate DMA-buf, IOMMU/SVA/PASID, HMM, Devfreq, runtime PM, dma-fence, Powercap/DTPM, Energy Model, and accelerator accounting where hardware and drivers support them. This phase remains hardware-gated; no generic GPU/NPU capability is fabricated.

### Phase 9 — AGI system services and model orchestration

Build the trusted service layer for model selection, inference/training lifecycle, workload admission, policy supervision, resource negotiation, provenance, checkpoint coordination, and rollback. Model execution remains in userspace.

### Phase 10 — Persistent memory and experience learning

Implement working, episodic, semantic, procedural, and long-term experience services with correction, expiration, provenance, confidence, conflict handling, retrieval, and skill operationalization. Retained experience is not called model retraining unless a verified training pipeline changed model weights and passed evaluation.

### Phase 11 — World model and temporal/causal state

Implement a persistent world-model service for entities, relationships, events, uncertainty, temporal state, observation time, event time, and causal hypotheses. Kernel support is limited to ordering, lineage, durable references, and event delivery.

### Phase 12 — Verified internet research and source provenance

Build source collection, primary-source preference, ranking, cross-checking, conflict detection, freshness, retrieval time, publication time, confidence, and provenance. Unverified external text remains evidence, not silently asserted fact.

### Phase 13 — Browser and computer-use service

Build a userspace browser service with semantic navigation, accessibility/DOM observation, screenshots, downloads/uploads, interaction verification, isolation, capability limits, and audit. The kernel provides boundaries; it does not contain a browser or web parser.

### Phase 14 — Multi-agent integration, deployment, rollback, and continuous improvement

Integrate planning, perception, reasoning, tools, memory, world model, verification, multi-agent coordination, self-evaluation, candidate kernel construction, fuzzing, benchmarking, canary deployment, monitoring, and rollback. Autonomous self-healing remains policy-gated and cannot directly replace a production kernel.

## Continuous loop

```text
RESEARCH → DESIGN → IMPLEMENT → BUILD → BOOT → TEST → FUZZ
→ SECURITY AUDIT → BENCHMARK → BASELINE COMPARISON
→ IDENTIFY WEAKNESSES → FIX → REBUILD → RETEST
→ INTEGRATE → MOVE TO NEXT DEPENDENCY → REPEAT
```

A work item is blocked when an acceptance gate cannot be executed or when a critical regression is unresolved. A work item is validated only when its evidence, explicit non-claims, security review, benchmark status, and rollback path are stored. The agent automatically selects the next highest-priority unblocked dependency from `FAISAL-PROGRAM-STATE.json`.

## Immediate dependency queue

1. **M64 security completion:** validated and committed as `FAISAL-M64-SECURITY-COMPLETION`; retain regression coverage while downstream work proceeds.
2. **M71 persistent memory service contract:** implement the first userspace service plus kernel-backed durable memory/checkpoint integration, with explicit provenance and capability gates.
3. **M72 verified experience pipeline:** record, evaluate, retrieve, and operationalize experiences without claiming foundation-model retraining.
4. **M73 world-state service:** build event-driven system/world self-state representation with temporal ordering and freshness.
5. **M74 trusted model/tool/browser orchestration:** integrate userspace model and browser services behind the supervisor and capability APIs.

The queue is provisional and must be recomputed after every failure, security finding, benchmark regression, or new provider dependency.
