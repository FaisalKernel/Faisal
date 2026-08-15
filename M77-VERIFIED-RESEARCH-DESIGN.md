# FAISAL M77 — Verified Internet Research and Source Provenance

## Scope

M77 is a bounded userspace research/provenance service. It records source representations obtained through the M75 scoped browser/tool broker, publishes bounded metadata through the FAISAL verified-knowledge interface, cross-checks independent source IDs, retains conflicting digests, and promotes content to the M73 world-state service only after explicit verification. It does not place a web crawler, parser, source-ranking oracle, or semantic truth engine in the kernel.

## Source record

Each source record contains a claim key, source URI, source kind, source rank, source ID, source/content/evidence digests, browser action and event sequence, retrieval realtime and boottime timestamps, source-reported publication time when available, freshness TTL, confidence, verification state, conflict state, cross-check count, provenance sequence, and generation. Missing publication metadata remains unknown; it is never synthesized from retrieval time.

The record model follows the W3C PROV distinction between entities, activities, and agents: the retained source representation is an entity, retrieval/cross-check/verification are activities, and the M77/browser services are responsible agents. HTTP status and representation metadata are evidence fields, not semantic truth. Digest equality establishes identity of retained bytes, not authorship or correctness.

## Source preference

The service uses a bounded policy score. Primary and official sources outrank curated and secondary sources; confidence breaks ties. Preference is an explicit selection for cross-check planning, not an automatic truth decision. The service retains all accepted source records and never deletes a lower-ranked or conflicting source.

## Verification state machine

```text
UNVERIFIED ── cross-check equal content ──> eligible for explicit VERIFY
UNVERIFIED ── cross-check differing content ──> CONFLICT
CONFLICT ──> retained; promotion denied unless an explicit future conflict policy resolves it
eligible ──> VERIFY with evidence digest ──> VERIFIED
any source with invalid metadata/content ──> REJECTED
VERIFIED ── freshness expiry ──> kernel-reported STALE; promotion requires revalidation
```

M77 requires at least one independent source cross-check before verification. The kernel performs the cross-check state transition and returns `-EUCLEAN` for differing content while retaining both records. Verification is requested separately with a nonzero evidence digest. A detected conflict or expired source cannot be promoted as verified knowledge.

## World-state boundary

M77 calls M73 `fws_add_fact` only for a source whose kernel knowledge record is explicitly `VERIFIED`, has no detected conflict, and has a successful independent cross-check. World-state promotion is a durable operational update, not proof of semantic truth. A model output, browser/page instruction, HTTP success code, source rank, or digest alone cannot authorize promotion.

## Security and recovery

Network and browser access remain behind M75 capability and policy scopes. Source content is bounded and treated as hostile data; prompt-injection-like content is rejected by M75 before knowledge publication. Malformed metadata, future publication timestamps, empty content, overlong fields, zero confidence, invalid TTL, and reserved-field mutations are rejected before kernel publication. If a later source conflicts, prior records remain queryable and the new source is not silently discarded.

## Explicit non-claims

M77 does not claim a universal truth oracle, complete source-quality ranking, semantic fact verification, prompt-injection immunity, fresh internet access in every deployment, consciousness, or autonomous authorization. Verified means that the bounded policy and kernel cross-check/verification transitions passed for the retained records; it does not mean the proposition is true in the world.
