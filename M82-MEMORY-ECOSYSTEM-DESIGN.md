# FAISAL M82 — Unified AGI Memory Ecosystem Design

## Decision summary

The three requested repositories were inspected from checked-out source at fixed commits on 2026-08-15. FAISAL will **reuse verified architectural ideas, not copy implementations**. The new capability remains a userspace memory orchestrator over the existing M71 persistent-memory, M72 experience-learning, and M73 world-state services. No kernel ABI expansion is justified by this integration.

| Candidate | Verified license | Concrete strengths | FAISAL adoption decision |
|---|---|---|---|
| Engram | MIT | Local-first SQLite/FTS5, agent-agnostic MCP boundary, project/scope isolation, progressive disclosure, topic-key upserts, soft delete, review lifecycle, conflict surfacing | Adopt the lifecycle and retrieval contracts conceptually; use FAISAL journals and capabilities instead of copying Go/SQLite/MCP code |
| MiroFish | AGPL-3.0 in backend manifest | Separate graph-building, entity/persona setup, bounded multi-agent simulation, temporal memory updates, post-simulation report interaction, explicit dependency on OASIS and Zep Cloud | Keep simulation as a separate, explicitly labeled service boundary; do not copy AGPL code or require Zep/OASIS for the kernel test path |
| Supermemory | MIT repository metadata and package declarations | Hybrid memory/RAG retrieval, static and dynamic profile distinction, graph-oriented memory presentation, automatic contradiction/forgetting concepts, framework integration, benchmark tooling | Adopt hybrid retrieval, bounded context assembly, and profile-like projections; do not claim hosted-engine internals are present in this checkout |

## Unified architecture

```text
FAISAL kernel ABI 37
  ├─ persistent-memory records, capabilities, checkpoints, resource/event telemetry
  ├─ identity, scope, provenance, and isolation enforcement
  └─ no semantic ranking, model reasoning, or simulation truth authority
          ↓
M71 persistent-memory service
          ↓
FAISAL memory orchestrator
  ├─ admission and retention policy
  ├─ eight memory classes
  ├─ deterministic consolidation of structured experiences
  ├─ lexical + temporal + type + confidence + importance retrieval
  ├─ contradiction/supersession and freshness state
  ├─ provenance chain and truth-class separation
  ├─ bounded progressive-disclosure context assembly
  └─ explicit simulation-memory boundary
          ↓
M72 experience learning + M73 world state + separate simulation service
          ↓
AGI runtime, reasoning, and planning
```

The eight classes are **working, episodic, semantic, procedural, world, simulation, self, and experience**. Every record carries a scope, source, provenance sequence, task/agent identifiers, event and observation times, confidence, importance, freshness deadline, truth class, and lifecycle state. Simulation outputs are never returned by the factual retrieval path unless the caller explicitly requests simulation evidence.

## Memory lifecycle

```text
RAW STRUCTURED EXPERIENCE
  → admission filter
  → deterministic consolidation
  → extract supplied facts, skills, and causal links
  → assign confidence/importance/freshness
  → persist with kernel-backed capability and provenance
  → index in bounded userspace metadata
  → retrieve minimum relevant context
  → review, supersede, expire, correct, or retain with conflict context
```

The implementation intentionally does not pretend to summarize arbitrary natural language or retrain a model. Consolidation accepts structured action, observation, result, lesson, skill, and causal fields from a trusted userspace service; a future model may propose these fields, but the orchestrator treats them as untrusted data subject to policy and verification.

## Retrieval contract

Retrieval is context-aware and bounded. A query may constrain memory class, scope, truth class, freshness, minimum confidence, minimum importance, task similarity, and whether simulation records are allowed. Ranking combines lexical token matches with confidence, importance, recency, provenance presence, and exact task/episode matches. The service returns only the configured top-k records and supports a second detail lookup, rather than dumping the database into a model context.

## Contradiction and freshness contract

A topic key identifies an evolving claim. A new record with the same topic and a different value creates a conflict relation. If event time is newer or equal, the old record becomes superseded; if event time is older, the new record remains conflicted and the prior record remains active. Both records retain provenance and timestamps. A freshness deadline marks records stale; stale records remain auditable but are excluded from default factual retrieval and require explicit revalidation.

## Simulation contract

The simulation service may construct a bounded digital world, create typed agent states, run deterministic interactions, compare outcomes, and emit simulation records. Its output truth class is one of `simulation`, `prediction`, `hypothesis`, or `uncertainty`. The orchestrator does not promote any of these to `real_world_fact` automatically. Promotion requires an explicit verified source record through the normal provenance and verification path.

## Kernel boundary and compatibility

The kernel remains responsible for persistent record primitives, capabilities, identity, scope isolation, checkpointing, event delivery, resource accounting, and failure enforcement. Semantic extraction, ranking, graph traversal, simulation, profile projection, and model interaction remain userspace responsibilities. The implementation reuses `fms_open`, `fms_put`, kernel memory capabilities, and existing ABI 37 controls. No new ioctl or syscall is introduced.

## References

[1]: https://github.com/Gentleman-Programming/engram/tree/1dafc0f63051b2214100f7bd801357e4aab61c26 — Engram source inspected at commit `1dafc0f`.
[2]: https://github.com/666ghj/MiroFish/tree/b5b53acc57189a4a42e44a23e149dc655c98fe82 — MiroFish source inspected at commit `b5b53ac`.
[3]: https://github.com/supermemoryai/supermemory/tree/e651045ac50470aa10df5cc8ff7ad2a9b72b00cf — Supermemory source inspected at commit `e651045`.
[4]: https://github.com/Gentleman-Programming/engram/blob/1dafc0f63051b2214100f7bd801357e4aab61c26/docs/ARCHITECTURE.md — Engram architecture and lifecycle documentation.
[5]: https://github.com/666ghj/MiroFish/blob/b5b53acc57189a4a42e44a23e149dc655c98fe82/backend/pyproject.toml — MiroFish backend license and dependencies.
[6]: https://github.com/supermemoryai/supermemory/blob/e651045ac50470aa10df5cc8ff7ad2a9b72b00cf/README.md — Supermemory retrieval, profiles, graph, forgetting, and benchmark claims as documented by the project.
