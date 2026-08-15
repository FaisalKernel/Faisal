# FAISAL M69 Research Findings

**Research date:** 2026-08-15
**Kernel base:** Linux `v7.2-rc7` in this repository.

## Findings

| Area | Verified Linux mechanism | M69 implication |
|---|---|---|
| Kernel tracing hooks | Tracepoints are lightweight hooks that are nearly inert when disabled, can carry typed parameters, and can be connected to runtime probes [1]. | Graph telemetry should use explicit opt-in emission and preserve a cheap disabled path. |
| Trace streaming | Tracefs exposes per-CPU ring buffers; mapped consumers can stream without a memory copy, but concurrent readers compete and buffer sizing/overrun remain observable constraints [2]. | FAISAL’s session ring can carry bounded records now; future high-rate integrations should use tracefs/perf rather than an unbounded custom queue. |
| ftrace/perf context | Ftrace already provides event tracing, latency tracing, CPU filters, PID filters, timestamps, and ring-buffer controls [3]. | M69 should add AGI correlation fields and lifecycle records, not replace ftrace/perf or duplicate generic kernel tracing. |
| Existing FAISAL observability | `AGI_LC_OBSERVABILITY` already controls event masks, sampling, counters, and the session record ring. | Extend the existing configuration and ring semantics with a graph-operation event payload. |
| Graph state | FAISAL graph nodes already carry graph/node IDs, device mask, dependencies, priority, deadline, expected runtime, criticality, readiness, and observed runtime. | Telemetry can attribute begin/end/failure to graph and node IDs without interpreting model semantics. |
| Tensor transport | FAISAL tensor transport already records transport kind, collective kind, direction, participants, bytes, chunk size, generation, completion sequence, and provenance IDs. | Telemetry can carry transport IDs and byte counts as opaque correlation data; it must not claim device completion unless a provider reports it. |
| Synchronization | Linux dma-buf uses dma-fence/dma-resv for asynchronous hardware completion and ordering [4]. | A generic FAISAL event should record provider-reported fence/completion metadata, not infer completion from submission. |
| Semantic anomaly detection | Kernel tracing can record counters and signals but does not understand model semantics or detect model drift. | M69 exposes bounded anomaly-signal fields supplied by a trusted userspace evaluator/provider; the kernel records and attributes them but does not classify behavior. |

## Design conclusion

The smallest justified M69 primitive is a **graph-operation telemetry record** associated with a FAISAL graph/node, context, tensor region, transport, and provenance chain. It supports begin, end, failure, checkpoint, and anomaly-signal operations through a new ABI-36 ioctl. Records are bounded per session and delivered through the existing observable event ring using the existing enable/filter/sample policy.

The record stores identifiers, timestamps, device class, operation kind, status, bytes, provider/fence sequence, observed runtime, queue delay, dependency count, and an anomaly score/flags supplied by userspace or a trusted provider. It does not store tensor contents, embeddings, model weights, DOM data, or semantic conclusions. Model drift, attention-layer identity, and anomaly interpretation remain userspace responsibilities.

## Sources

[1]: https://docs.kernel.org/trace/tracepoints.html "Linux kernel documentation: Using the Linux Kernel Tracepoints"
[2]: https://docs.kernel.org/trace/ring-buffer-map.html "Linux kernel documentation: Tracefs ring-buffer memory mapping"
[3]: https://docs.kernel.org/trace/ftrace.html "Linux kernel documentation: ftrace - Function Tracer"
[4]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
