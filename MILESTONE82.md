# FAISAL M82 — Unified Memory Ecosystem and Simulation Boundary

## Status

M82 implements and validates a **userspace unified memory orchestrator** over the existing FAISAL ABI 37 persistent-memory, experience-learning, and world-state services. The implementation deliberately does not expand the kernel ABI. It adds memory classes, provenance-aware consolidation, bounded hybrid retrieval, progressive context assembly, freshness expiration, contradiction/supersession lifecycle, restart replay, and an explicit simulation truth boundary.

The milestone is based on direct source inspection of Engram, MiroFish, and Supermemory at fixed commits. Engram documents a local-first structured observation store with scope, topic-key upserts, soft deletion, review lifecycle, conflict management, and progressive disclosure [1] [4]. MiroFish documents graph construction, entity/persona setup, bounded multi-agent simulation, temporal memory updates, and report interaction; its backend declares AGPL-3.0 and depends on Zep Cloud and OASIS [2] [5]. Supermemory documents hybrid memory/RAG search, static and dynamic profiles, graph-oriented memory, contradiction/forgetting behavior, and benchmark tooling [3] [6].

FAISAL adopts these architectural patterns without copying repository code. The implementation remains independent of their language runtimes, hosted services, and licenses.

## Implemented behavior

The new orchestrator persists records through M71 and indexes bounded metadata in its own append-only journal. It exposes eight memory classes: working, episodic, semantic, procedural, world, simulation, self, and experience. Each record retains scope, topic, source, content, confidence, importance, event and observation time, freshness deadline, truth class, lifecycle state, memory capability, kernel record identity, and a provenance chain.

Experience consolidation creates an experience record and a procedural skill record, invokes the existing M72 evaluation path through a sequential kernel session, and invokes the existing M73 world-state path through another sequential kernel session. Sequential opening is intentional: the current FAISAL userspace memory services attach kernel lineage to their active session, so holding multiple child sessions concurrently is not assumed. The orchestrator reattaches its primary memory session after each child-service operation.

Retrieval is bounded and deterministic. It combines lexical token matches with scope, task, confidence, importance, freshness, provenance, and recency signals. Default factual retrieval excludes simulation results and superseded records. Explicit simulation retrieval is required to include simulation truth. Context assembly is capped at 4096 bytes and returns a bounded top-k result set.

Contradictory records with the same scope, class, and topic are retained. A newer observation supersedes an older record and preserves both directions of the relation. An older observation remains conflicted rather than silently overwriting newer information. Freshness deadlines can expire records; expired records remain auditable and require explicit inclusion for retrieval.

## Validation results

| Validation | Observed result |
|---|---:|
| Strict static build | Passed with `-O2 -Wall -Wextra -Werror -Wno-cpp -static` |
| QEMU boot | `FAISAL_M82_BOOT_OK` |
| Experience consolidation | `records=2` |
| Hybrid retrieval | `results=1`, bounded top score reported |
| Progressive context | `count=1`, 196 bytes |
| Memory classes | `classes=8` |
| Simulation boundary | Simulation excluded by default and returned only by explicit request |
| Contradiction lifecycle | New record 13 superseded old record 12 |
| Freshness expiry | `expired=1` |
| Malformed ingest | Rejected |
| Provenance statistics | 14 total records, 13 complete, 1 simulation |
| Restart replay | 14 records replayed |
| M71 regression | Passed |
| M72 regression | Passed |
| M73 regression | Passed |
| M76 regression | Passed |
| Five M82 smoke runs | 5/5 passed |

The final QEMU run emitted `M82_SELFTEST_EXIT=0` and `FAISAL_M82_TEST_RC=0`. The five smoke runs measured complete harness elapsed times of 5067, 5113, 5003, 5082, and 5206 ms. These are end-to-end QEMU harness timings, not kernel or retrieval performance benchmarks.

## Security and trust boundaries

No model output is used as kernel authorization. Kernel capabilities, identity, lineage, and existing M71–M73 service controls remain the authority boundary. A simulation record is explicitly labeled `FMO_TRUTH_SIMULATION_RESULT` and is excluded from default factual retrieval. The orchestrator does not promote predictions, hypotheses, or simulation outcomes into real-world facts. Provenance completeness can be required by a query.

The implementation contains no shell execution, process spawning, unbounded string-copy primitive, or unbounded record allocation. Record storage, context output, result count, and journal replay are bounded by compile-time limits or EOF. The QEMU harness uses a fixed initramfs and does not download or execute repository code.

## Evidence limits and non-claims

M82 is a bounded userspace integration milestone. It does **not** claim that FAISAL has human-like memory, consciousness, autonomous model improvement, foundation-model retraining, semantic understanding of arbitrary natural language, production readiness, distributed database consistency, multi-day reliability, KASAN/KCSAN/UBSAN/lockdep coverage, syzkaller coverage, physical accelerator support, or superior performance over Linux or any inspected repository. The simulation fixture validates truth separation and lifecycle behavior; it is not a forecasting engine.

## Files

- `tools/faisal-memory-orchestrator/faisal_memory_orchestrator_service.h`
- `tools/faisal-memory-orchestrator/faisal_memory_orchestrator_service.c`
- `tools/testing/selftests/agi_memory_orchestrator_test.c`
- `tools/faisal-build/run_memory_orchestrator_qemu.sh`
- `M82-MEMORY-ECOSYSTEM-DESIGN.md`
- `M82-MEMORY-SECURITY-REVIEW.md`
- `M82-MEMORY-BENCHMARKS.md`
- `tools/faisal-build/evidence/m82-memory-validation.json`

## References

[1]: https://github.com/Gentleman-Programming/engram/tree/1dafc0f63051b2214100f7bd801357e4aab61c26 — Engram source inspected at commit `1dafc0f`.
[2]: https://github.com/666ghj/MiroFish/tree/b5b53acc57189a4a42e44a23e149dc655c98fe82 — MiroFish source inspected at commit `b5b53ac`.
[3]: https://github.com/supermemoryai/supermemory/tree/e651045ac50470aa10df5cc8ff7ad2a9b72b00cf — Supermemory source inspected at commit `e651045`.
[4]: https://github.com/Gentleman-Programming/engram/blob/1dafc0f63051b2214100f7bd801357e4aab61c26/docs/ARCHITECTURE.md — Engram architecture, lifecycle, scope, conflict, and progressive-disclosure documentation.
[5]: https://github.com/666ghj/MiroFish/blob/b5b53acc57189a4a42e44a23e149dc655c98fe82/backend/pyproject.toml — MiroFish backend license and dependency declaration.
[6]: https://github.com/supermemoryai/supermemory/blob/e651045ac50470aa10df5cc8ff7ad2a9b72b00cf/README.md — Supermemory memory, profile, graph, forgetting, and benchmark claims as documented by the project.
