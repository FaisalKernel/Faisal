# FAISAL M73 World-State Service Design

## Scope

M73 implements a userspace world-state service that consumes structured FAISAL kernel events, maintains bounded entity state, records temporal constraints and observations, links facts to provenance and persistent memory, and exposes measurable system/self-state snapshots. The service is an operational state representation, not consciousness or a semantic world model with guaranteed truth.

## Record model

Each bounded world fact contains an entity key, property key, value digest, event sequence, observation time, optional source/provenance sequence, freshness deadline, confidence, conflict state, generation, and source kind. The service stores content in M71 persistent memory and keeps an index for current state. Kernel event sequence is the ordering authority for observed changes; userspace wall time is retained as observation time, not substituted for event order.

## Event ordering and loss

The service queries `AGI_LC_WORLD_SYNC` before consuming a batch. It accepts monotonically increasing kernel sequences, acknowledges only the newest sequence it has processed, and records a resynchronization requirement when the kernel reports dropped events or a non-contiguous observation. It never invents missing events. A resync invalidates derived state that depends on unknown transitions until a fresh snapshot or explicit source update rebuilds it.

## Freshness and conflict

A fact is `FRESH` while its freshness deadline has not elapsed. It becomes `STALE` after the deadline and is not used for authoritative decisions without revalidation. Two different digests for the same entity/property create `CONFLICT`; the service retains both provenance references and chooses no winner automatically. Resolution requires an explicit higher-level policy and records a new generation.

## Kernel synchronization

M73 subscribes to selected world events, queries world-sync counters, retrieves resource snapshots, creates and checks a kernel temporal record, and acknowledges processed sequences. The temporal record provides kernel observation and constraint state; it does not make a semantic fact true. Resource snapshots report measured, unavailable, and unsupported fields separately.

## Recovery

The world-state journal is rebuilt from M71 durable records and an explicit last-acknowledged event sequence. If the saved sequence is older than the kernel’s loss sequence or a journal digest fails, the service enters `RESYNC_REQUIRED`, discards untrusted derived state, obtains a fresh resource/world snapshot, and resumes only after a new temporal synchronization point is recorded.

## Acceptance gates

| Gate | Required result |
|---|---|
| Event ordering | Kernel sequence order is accepted and acknowledged monotonically. |
| Loss handling | Dropped/non-contiguous events produce `RESYNC_REQUIRED`; no fabricated transition is emitted. |
| Freshness | Expired facts become stale and are excluded from authoritative lookup. |
| Conflict | Conflicting digests are retained with conflict state and no silent winner. |
| Self-state | A resource snapshot reports measured and unavailable/unsupported masks separately. |
| Temporal | A kernel temporal record is created, queried, and checked against a current sequence. |
| Recovery | Journal/state replay and resync path preserve explicit uncertainty. |
| Security | World updates require service authority and provenance; state does not grant action capabilities. |

## Explicit non-claims

M73 does not claim human-like awareness, consciousness, semantic truth, causal inference, complete world coverage, automatic conflict resolution, or permission to act. It provides measurable state representation and introspection for higher-level services.
