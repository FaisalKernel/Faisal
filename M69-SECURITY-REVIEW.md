# FAISAL M69 Security Review

## Scope

This review covers ABI-36 graph-operation telemetry and its integration with the existing FAISAL session event ring. M69 adds attribution and measurement records; it does not execute model code, submit hardware commands, expose tensor contents, or authorize privileged operations from model output.

## Security properties

| Property | Enforcement |
|---|---|
| Session isolation | The caller must have an active FAISAL session and matching task lineage. |
| Agent attribution | Graph nodes and telemetry records are associated with the current FAISAL agent; updates reject another agent. |
| Telemetry capability | Begin returns an opaque capability; later updates and queries require the exact ID/capability pair. |
| Graph ownership | Begin requires a graph node owned by the current agent and in READY or RUNNING state. |
| Context references | Optional compute-context IDs require their capability and current-agent ownership. |
| Tensor references | Optional memory-region IDs require their capability and read authorization through the existing memory-region policy. |
| Transport references | Optional transport IDs require a matching active transport capability in the same session. |
| Provenance references | Optional provenance ID/sequence pairs must exist in the same session. |
| Event isolation | Records are delivered through the caller’s existing session queue and observability filtering/sampling policy. |
| Resource bounds | Each session has at most 64 telemetry records; no user-controlled allocation or unbounded payload is introduced. |
| Timestamp integrity | Begin/end timestamps are captured by the kernel; userspace cannot supply them. |
| Model authority boundary | Anomaly scores, provider measurements, and operation labels are observations; they do not grant capabilities or trigger device execution. |

## Threat model

A malicious or compromised model may attempt to fabricate a graph node, reuse another agent’s telemetry capability, attach telemetry to an unauthorized tensor region, claim a provider completed work, flood the event queue, or submit a semantic anomaly conclusion as kernel truth. M69 counters these threats through session lineage, agent checks, exact opaque capabilities, existing memory authorization, session-local transport/provenance checks, fixed record bounds, sampled event delivery, and explicit provider-measurement semantics.

The kernel does not trust `operator_kind`, `queue_delay_ns`, byte counts, provider sequence numbers, or anomaly scores as authoritative facts about model behavior. These values are attributable observations from a trusted runtime or provider integration. They are not used to change scheduling, grant permissions, release secrets, or initiate accelerator work.

## Concurrency and lifetime

The handler executes under the lifecycle file’s ioctl serialization and uses the session graph lock for telemetry records. Existing context and memory locks are acquired only for capability validation and released before the record is updated. The record table is bounded and session-owned. Future provider integrations must define reset, revocation, fence lifetime, and asynchronous completion rules before writing into these records from interrupt or workqueue context.

## Residual risks

M69 does not protect against a trusted userspace runtime lying about provider measurements. It also does not prevent side-channel leakage from vendor tools, model outputs, or device traces. The generic event ring can drop records under pressure; the existing dropped-record accounting must be monitored when lossless forensic evidence is required. High-rate tensor-level instrumentation should use provider tracepoints, perf, or tracefs rather than increasing this bounded ioctl record size.

## Security conclusion

M69 is acceptable as a conservative observability control-plane milestone. It adds auditable graph correlation while keeping semantic interpretation, provider hardware truth, and authorization outside the telemetry ABI. It must not be advertised as model-drift detection, GPU-kernel tracing, or a security proof of accelerator execution.

## References

[1]: https://docs.kernel.org/trace/tracepoints.html "Linux kernel documentation: Using the Linux Kernel Tracepoints"
[2]: https://docs.kernel.org/trace/ring-buffer-map.html "Linux kernel documentation: Tracefs ring-buffer memory mapping"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
