# FAISAL M71 Persistent-Memory Security Review

## Scope

M71 is a userspace persistent-memory service integrated with the FAISAL kernel metadata and checkpoint/recovery interfaces. Semantic content remains in a service-owned journal. The kernel stores bounded metadata, owner lineage, agent identity, authority capability, generation, provenance sequence, freshness, conflict, and checkpoint state.

## Security properties

| Threat | M71 control |
|---|---|
| Unauthorized record mutation | Kernel CREATE/QUERY/UPDATE requests use the returned authority capability; wrong or stale capability is rejected. |
| Model text becomes storage authority | The service accepts an API request only from its trusted caller/session; no natural-language field or model output creates a kernel capability. |
| Journal disclosure | The journal and checkpoint sidecar are created with mode `0600`; the service does not store capabilities, secrets, physical addresses, or browser artifacts. |
| Journal corruption | Each entry has a magic, version, header size, bounded content length, and SHA-256 digest. Invalid digest is rejected. |
| Crash-tail ambiguity | An incomplete final header or payload is truncated to the last valid boundary; a complete digest-corrupt entry is rejected rather than silently repaired. |
| Stale kernel record | A new service session rehydrates metadata through fresh kernel CREATE operations; old session-local IDs and capabilities are not trusted. |
| Checkpoint forgery | The kernel creates the checkpoint sequence and manifest digest; recovery requires matching state and manifest digests plus kernel verification/import sequencing. |
| Recovery before validation | The service closes the execution gate, verifies the journal digest, performs recovery restore/import/continue, and reopens the gate only after success. |
| Resource exhaustion | The first service implementation bounds entries at 64 and content at 4095 bytes per record. |
| False learning claim | The service records and retrieves durable experience only; it does not retrain or modify model weights. |

## Failure model

A failure before journal `fdatasync()` is not acknowledged as durable. A failure after journal durability but before kernel metadata creation can be replayed and reconciled through a future idempotent service policy; M71’s first implementation deliberately returns an error rather than silently claiming completion. A complete journal entry with an invalid digest is a hard corruption failure. A torn final entry is truncated only after earlier entries have passed validation.

The kernel checkpoint is treated as a verified control-plane reference, not as a copy of the semantic journal. The service digest covers durable semantic identity and content digests without session-local kernel record IDs, allowing restart rehydration while preserving checkpoint equivalence.

## Residual risks

M71 is a single-process reference service, not a production distributed database. It does not yet implement authenticated remote replication, encryption at rest, multi-writer consensus, key rotation, quotas across tenants, or crash-consistent transactional coupling between the journal and kernel metadata. Those are explicit future dependencies. Production deployment requires a trusted supervisor, filesystem policy, operator approval, backup/restore policy, and independent monitoring.

## Conclusion

The M71 service provides a measurable persistent-memory substrate with explicit kernel authorization, provenance references, checkpoint/recovery sequencing, and corruption handling. It does not provide semantic understanding, correct knowledge, model learning, or consciousness.
