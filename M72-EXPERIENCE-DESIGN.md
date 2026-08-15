# FAISAL M72 Verified Experience Learning Design

## Operational definition

M72 implements the smallest truthful form of experience-based improvement. A completed execution can be recorded with action, observation, result, failure, timing, resource, verification, and provenance metadata; evaluated by a userspace policy; retrieved for a later query; corrected or invalidated; and operationalized as a bounded skill artifact. This is **experience retention and skill reuse**, not foundation-model retraining.

## State model

```text
RECORDED → EVALUATED → REUSABLE
    │          │           │
    ├──────────┴───────────┴──> CORRECTED → REEVALUATION
    ├──────────────────────────> REJECTED
    └──────────────────────────> EXPIRED
```

The kernel experience record supplies an immutable event sequence and digest. M71 supplies durable semantic content and correction/replay. M72 stores evaluation outcome, confidence, reusable key, and skill reference in userspace. The service must not mark an item `REUSABLE` solely because it was stored.

## One-query workflow

```text
QUERY 1
  → runtime executes action and records observation/result
  → FAISAL kernel records bounded experience sequence and provenance
  → M71 persists content and digest
  → evaluator checks result, policy, source/provenance, and failure state
  → reusable experience or skill artifact is published

QUERY 2
  → service indexes the new query key
  → retrieves only an evaluated, non-expired, non-rejected artifact
  → runtime may propose reuse
  → supervisor rechecks capability, freshness, scope, and current context
  → service records whether reuse succeeded or failed
```

A skill artifact is a userspace reference to an evaluated strategy, not executable authority. The kernel artifact capability permits only retrieval of the kernel-held artifact metadata. It does not grant tool, browser, filesystem, network, device, model, or deployment privilege.

## Correction and trust policy

A correction creates a new durable memory generation and a new evaluation decision. It does not silently mutate an already published skill. The old record becomes superseded or rejected according to service policy, and the new content must be re-evaluated before reuse. Any conflict, stale provenance, missing source, or failed verification prevents `REUSABLE` state.

Confidence is a service-level estimate bounded to parts per million. It is not a probability guarantee, model confidence, or kernel authorization. Freshness, scope, and provenance are independently checked.

## Kernel integration

The service uses `AGI_LC_EXPERIENCE` for bounded kernel event records, `AGI_LC_GET_EXPERIENCE` for query, `AGI_LC_PUBLISH_ARTIFACT` for kernel-generated artifact identity/capability, and `AGI_LC_GET_ARTIFACT` for capability-scoped metadata retrieval. M71 persistent-memory records retain semantic content and durable digests. The service links them by experience sequence and digest.

## Acceptance gates

| Gate | Required result |
|---|---|
| Retention | Query 1 produces a kernel experience sequence and durable M71 record. |
| Evaluation | A successful verified result becomes reusable; an unverified or failed result is rejected. |
| Retrieval | Query 2 retrieves the reusable artifact by key and exact digest. |
| Skill reuse | A later execution reports reuse and records a new experience; it does not execute automatically from the artifact. |
| Correction | A corrected record supersedes the previous one and must pass evaluation again. |
| Provenance | Kernel sequence and artifact source digest remain linked and queryable. |
| Security | Wrong artifact capability and stale content are rejected. |
| Truthfulness | Evidence says retention/operationalization, never model retraining or consciousness. |
