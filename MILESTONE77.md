# FAISAL M77 — Verified Internet Research and Source Provenance

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Bounded userspace source collection through the M75 browser/tool broker, FAISAL verified-knowledge publication/cross-check/verification, durable M71 content retention, M73 world-state promotion, source preference, conflict retention, and metadata rejection.

## Research basis

M77 uses the W3C PROV distinction between entities, activities, and agents to structure source provenance.[1] HTTP response metadata is treated as representation evidence, not a truth decision, consistent with the separation of HTTP semantics, resources, representations, and metadata in RFC 9110.[2] Content digests provide an integrity identity for retained bytes, while NIST’s integrity-verification definition does not turn that identity into semantic correctness.[3]

The research record and URLs are preserved in `M77-RESEARCH-NOTES.md`.

## Implementation

M77 adds `tools/faisal-research/faisal_research_service.c` and its header. The service opens the existing M75 scoped browser/network session and M73 world-state service. Each collected source is bounded by claim, URI, content, source kind, rank, confidence, publication time, and freshness TTL. It records separate source and content SHA-256 digests, browser action/event sequence, durable memory record, kernel knowledge record, retrieval metadata, and verification fields.

The service publishes source records through `AGI_LC_KNOWLEDGE`. Equal independent source content transitions through a kernel cross-check and becomes eligible for an explicit evidence-backed verification. Differing content returns a retained conflict state for both source records; M77 refuses verification and promotion. The preferred source policy ranks primary above official, curated, and secondary sources, with confidence as a tie-breaker. Preference does not silently delete or override other records.

Only an explicitly `VERIFIED`, fresh, non-conflicting record can be promoted into M73 world state. The promotion is a bounded durable state update, not a semantic truth oracle. Browser/page/model text never supplies kernel authority or verification status.

## Validation

The static M77 build passed `-O2 -Wall -Wextra -Werror -Wno-cpp` with static OpenSSL EVP linkage. QEMU passed these markers.

```text
FAISAL_M77_BOOT_OK
FAISAL_M77_BROWSER_WORLD_OPEN_OK
M77_UNVERIFIED_FACT_DENIAL_OK source=1
M77_PRIMARY_SOURCE_PREFERENCE_OK source=1
M77_EQUAL_CROSSCHECK_OK count=1
M77_VERIFIED_WORLD_PROMOTION_OK knowledge=1 memory=1
M77_CONFLICT_RETENTION_OK sources=3,4
M77_METADATA_FUZZ_REJECT_OK iterations=64
M77_SELFTEST_EXIT=0
FAISAL_M77_TEST_RC=0
```

Five repeated M77 QEMU smoke runs passed with wall times from 5.0146 to 5.2380 seconds. The M64 and M66–M76 regression suite plus M77 passed, for thirteen of thirteen harnesses. The captured regression log contained no M77 failure marker, kernel panic, `BUG`, `Oops`, or general-protection failure.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Scoped browser/network acquisition | Pass | M75 broker opened and allowed bounded semantic fixture |
| Retrieval/content integrity records | Pass | Source and content digests plus browser provenance retained |
| Primary-source preference | Pass | Primary source selected over secondary source |
| Equal independent cross-check | Pass | Kernel cross-check count incremented and explicit verification succeeded |
| Verified world promotion | Pass | Fresh verified source promoted into M73 world-state memory |
| Conflict retention | Pass | Differing source digests retained with conflict state; verification denied |
| Unverified-fact boundary | Pass | Promotion denied before explicit verification |
| Metadata fuzzing | Pass | 64 malformed source records rejected before publication |
| Build and boot | Pass | Strict static build and QEMU boot markers |
| Regression | Pass | M64 and M66–M76 plus M77 |

## Explicit non-claims

M77 does **not** claim a universal truth oracle, complete source-quality ranking, semantic correctness, complete prompt-injection immunity, current internet access in every deployment, automatic conflict resolution, consciousness, model retraining, or safe real-world action. A verified kernel record means the bounded metadata, cross-check, evidence digest, freshness, and policy transitions passed; it does not prove that the proposition is true in the external world.

## References

[1]: https://www.w3.org/TR/prov-dm/ "W3C PROV-DM: The PROV Data Model"
[2]: https://httpwg.org/specs/rfc9110.html "RFC 9110: HTTP Semantics"
[3]: https://csrc.nist.gov/glossary/term/integrity_verification "NIST CSRC Glossary: Integrity verification"
