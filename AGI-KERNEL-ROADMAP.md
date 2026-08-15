# FAISAL AGI-Native Kernel Roadmap

## Mission

FAISAL will become a Linux-derived operating system whose kernel and system services provide native primitives for persistent autonomous agents, long-horizon execution, memory, experience-based learning, world-state observation, verified information acquisition, multi-agent coordination, secure tool use, and adaptive resource allocation.

This roadmap is an active dependency graph. The 14 strategic phases are not a sequence of documents that can be checked off. Each phase contains implementation work, tests, benchmarks, security gates, downstream integrations, and possible rework.

## Current position

| Item | State |
|---|---|
| M73 evidence | Validated as `FAISAL-M73`; world-state design, security, benchmarks, QEMU, and regression evidence stored |
| M74 evidence | Validated as `FAISAL-M74`; model admission, policy denial, checkpoint/rollback, output non-authority, fuzz, QEMU, and regression evidence stored |
| M75 evidence | Validated as `FAISAL-M75`; browser grant, network policy, semantic actions, transfer scopes, hostile-content, cancellation, QEMU, and regression evidence stored |
| M76 evidence | Validated as `FAISAL-M76`; five-stage end-to-end composition, multi-agent IPC/cancellation, reflection/observability, deployment gates, deterministic recovery, QEMU, fuzz, and regression evidence stored |
| M77 evidence | Validated as `FAISAL-M77`; scoped source acquisition, primary-source preference, equal/conflicting cross-checks, explicit verification, world-state promotion, unverified denial, metadata fuzz, QEMU, and regression evidence stored |
| M78 evidence | Validated as `FAISAL-M78`; independent deployment approvals, candidate digest binding, checkpoint verification, health monitoring, canary failure rollback, audit provenance, activation, manifest fuzz, QEMU, and regression evidence stored |
| M79 evidence | Validated as `FAISAL-M79` for the provider-neutral control plane; provider discovery, honest unsupported state, context/fabric masks, tensor transport, graph telemetry, resource masks, power-policy intent, stale-capability denials, 64 metadata fuzz cases, authoritative research, QEMU, and regression evidence stored |
| Linux foundation | Verified Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7` |
| Latest tagged FAISAL milestone | `FAISAL-M79`, provider-gated heterogeneous accelerator validation |
| Kernel ABI | 37 |
| Validated kernel and service primitives | Lifecycle, agent/task identity, scoped capabilities, provenance binding, tensor/graph/context control plane, tensor transport metadata, deterministic domains, heterogeneous-context negotiation, graph telemetry, CPU PM QoS policy intent, durable userspace memory journal, checkpoint/recovery integration, verified experience retention, skill-artifact gating, correction/re-evaluation, selective world subscriptions, world-sync acknowledgement, freshness/conflict state, temporal checks, honest resource snapshots, trusted model admission, explicit approval gates, kernel budget enforcement, checkpoint verification, rollback sequencing, model-output non-authority boundary, capability-scoped browser sessions, network policy, semantic action records, transfer scopes, hostile-content denial, cancellation, bounded multi-agent IPC, queued-message cancellation, reflection, observability, deployment-gate separation, deterministic recovery, verified source records, retrieval/provenance metadata, primary-source preference, kernel cross-check/conflict state, evidence-backed verification, unverified world-promotion denial, deployment candidate digest binding, independent approval separation, canary monitoring, explicit rollback, audit records, provider-neutral accelerator evidence and explicit unsupported-state reporting |
| Next selected dependency | M80 cross-subsystem stress, fuzz, and failure-injection hardening |
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
2. **M71 persistent memory service contract:** validated and committed as `FAISAL-M71`; retain restart, corruption, checkpoint, and capability regression coverage.
3. **M72 verified experience pipeline:** validated and committed as `FAISAL-M72`; retain the no-retraining and stale-artifact regression gates.
4. **M73 world-state service:** validated as `FAISAL-M73`; retain event-loss, freshness, conflict, temporal-capability, and resource-mask regression coverage.
5. **M74 trusted model/runtime orchestration:** validated as `FAISAL-M74`; retain independent-approval, resource-admission, checkpoint/rollback, and model-output non-authority regression coverage.
6. **M75 capability-scoped browser and tool supervision:** validated as `FAISAL-M75`; retain browser-grant, network-scope, transfer-scope, hostile-content, provenance, and cancellation regression coverage.
7. **M76 end-to-end multi-agent integration:** validated as `FAISAL-M76`; retain five-stage composition, IPC/cancellation, monitoring, approval-denial, recovery, and M64–M75 regression coverage.
8. **M77 verified internet research and source provenance:** validated as `FAISAL-M77`; retain source provenance, primary-source preference, cross-check/conflict, explicit verification, freshness, unverified-denial, and M64–M76 regression coverage.
9. **M78 controlled deployment, canary, monitoring, and rollback supervisor:** validated as `FAISAL-M78`; retain candidate-digest, independent-approval, checkpoint-verification, canary-failure, explicit-rollback, audit, and M64–M77 regression gates.
10. **M79 provider-gated heterogeneous accelerator validation:** validated as `FAISAL-M79` for provider-neutral control-plane semantics and explicit unsupported hardware reporting. Real-provider execution remains gated on hardware/provider evidence; do not infer capability from metadata or QEMU.
11. **M80 cross-subsystem stress, fuzz, and failure-injection hardening:** validated as `FAISAL-M80` in a bounded QEMU environment with 256 malformed-UAPI rejections, repeated composition and cancellation, resource-pressure observation, rollback injection, audit retention, unsupported-provider propagation, five smoke runs, and 15/15 pre-M80 regressions. The evidence does not claim sanitizer, syzkaller, hardware, long-duration, or production coverage.
12. **M82 unified memory ecosystem and simulation truth boundary:** validated as a bounded userspace integration over M71–M73. It adds eight memory classes, provenance-aware consolidation, bounded hybrid retrieval, freshness, contradiction/supersession, restart replay, and explicit simulation truth separation. It does not claim transactional cross-journal rollback, model retraining, semantic memory quality, or production readiness.
13. **M84 CogOS bounded atom control-plane module:** validated as an experimental FAISAL loadable module with fixed-point atom scores, RCU lookup, slab allocation, modern shrinker lifecycle, controlled scheduler thread, private ioctl ABI, QEMU insertion, ioctl validation, attention-drift validation, and clean unload. It does not claim semantic reasoning, production AtomSpace scale, stable ABI status, or sanitizer/fuzzer coverage.
14. **M81 concurrent lifecycle and IPC stress with sanitizer-enabled kernel validation:** next selected dependency; add concurrent stress and randomized structured inputs, then use KASAN/KCSAN/lockdep or record explicit infrastructure blockers before further production claims.

The queue is provisional and must be recomputed after every failure, security finding, benchmark regression, or new provider dependency.
