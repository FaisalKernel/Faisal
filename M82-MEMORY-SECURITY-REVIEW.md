# FAISAL M82 — Memory Ecosystem Security Review

## Scope

This review covers the new userspace memory orchestrator, its sequential integration with M71 persistent memory, M72 experience learning, M73 world state, the M82 selftest, and the QEMU harness. It does not certify the Linux kernel globally or replace subsystem-specific reviews.

## Trust model

The orchestrator treats model-proposed content, lessons, skills, sources, and simulation outcomes as untrusted data. Model output never becomes kernel authorization. The kernel remains authoritative through the existing device, capability, identity, lineage, and persistent-memory controls. The orchestrator stores the kernel record identity and authority capability returned by M71 but does not mint or broaden either authority.

A record’s truth class is explicit. `FMO_TRUTH_REAL_WORLD_FACT` is distinct from `FMO_TRUTH_SIMULATION_RESULT`, `FMO_TRUTH_PREDICTION`, `FMO_TRUTH_HYPOTHESIS`, and `FMO_TRUTH_UNCERTAINTY`. Default retrieval excludes simulation results, and explicit retrieval is required to request them. There is no automatic simulation-to-fact promotion path.

## Isolation and provenance

Every ingest record requires a non-empty scope, topic, and content, and carries class, truth, confidence, importance, timestamps, and provenance. Queries can require complete source, experience, agent, task, event, and verification sequences. Scope and task filters are applied before results are returned. The M71 capability and record identifiers remain attached to every accepted record.

FES and FWS are opened sequentially rather than concurrently. This is a deliberate compatibility and security choice because the existing FAISAL memory services attach the current task lineage to their active kernel session. After each child service closes, the orchestrator reattaches its primary memory session before issuing another memory ioctl.

## Bounds and denial behavior

| Boundary | Enforcement |
|---|---|
| Orchestrator records | `FMO_MAX_RECORDS=96` |
| Returned results | `FMO_MAX_RESULTS=16` and caller top-k validation |
| Context assembly | `FMO_MAX_CONTEXT=4096` bytes with truncation flag |
| Scope/topic/source/content/skill/causal fields | Fixed arrays with length validation and bounded copy helper |
| Journal replay | Fixed record header validation, EOF-bounded replay, incomplete-tail truncation |
| Freshness | Explicit deadline and expired state; default retrieval excludes stale data |
| Simulation visibility | Explicit include flag and truth-class check |
| Malformed ingest | Invalid class, truth, empty identity fields, oversize fields, and out-of-range scores rejected |
| QEMU workload | Fixed initramfs, bounded selftest, no external network dependency |

No `system`, `popen`, `execve`, `fork`, `strcpy`, `strcat`, `gets`, or `sprintf` use exists in the reviewed M82 implementation. The only unbounded-looking journal loop is EOF-terminated replay over fixed-size records and validates each header before applying it.

## Failure and recovery

Persistent state uses M71’s kernel-backed journal plus an append-only orchestrator index. On restart, the index replays valid records and truncates an incomplete final header. A corrupt complete header fails closed rather than being silently accepted. If a downstream FES or FWS operation fails after an orchestrator record is persisted, the operation returns an error; the current milestone does not claim distributed rollback across the three independent journals. This limitation is explicit and is a priority for future transactional integration.

Contradiction handling preserves both records. A newer observation marks the older one superseded and records the relation in both directions. An older observation becomes a conflict instead of overwriting newer state. Expired records remain in the journal for audit and are excluded from normal retrieval unless explicitly requested.

## Static and executable checks

The implementation passed strict compilation with `-O2 -Wall -Wextra -Werror -Wno-cpp -static`. QEMU executed the malformed-ingest rejection, provenance, simulation boundary, contradiction/supersession, expiry, replay, and context-bound checks. The reused M71, M72, M73, and M76 QEMU harnesses also passed.

The security scan found no shell/process execution or unbounded copy primitive in the M82 paths. This scan is a targeted source review, not a replacement for KASAN, KCSAN, UBSAN, lockdep, syzkaller, or a formal audit.

## Residual risks

The userspace journals are not a distributed transaction across M71, M72, and M73. Natural-language extraction is outside this component, so semantic correctness of model-proposed fields is not established. The deterministic simulation fixture validates label separation, not predictive accuracy. No physical accelerator, hostile multi-tenant deployment, cryptographic source verification protocol, or long-duration crash campaign is claimed by M82.
