# FAISAL M69 — Graph-Native Operation Observability

**Status:** Implemented and validated in two-vCPU QEMU.
**Base:** Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7`.
**FAISAL ABI:** 36.
**Validation date:** 2026-08-15.

## Objective

M69 adds a bounded graph-operation telemetry plane for AI workloads. It lets a trusted userspace runtime attribute operation timing and resource observations to a FAISAL graph/node while retaining Linux ftrace, tracepoints, perf, tracefs, dma-fence, and provider-specific accelerator tooling as the authoritative lower-level mechanisms.

The kernel records **operational provenance**, not semantic meaning. It can answer which graph node, task, agent, context, tensor region, transport, or provenance sequence was associated with a recorded operation and when the kernel observed begin/end transitions. It cannot determine whether an attention block is semantically correct, whether a model has drifted, or why a vendor GPU queue stalled without provider telemetry.

## ABI-36

`AGI_LC_GRAPH_TELEMETRY` is ioctl `0x61`. A bounded per-session table stores up to 64 records. The operations are `BEGIN`, `END`, `FAIL`, `CHECKPOINT`, `ANOMALY`, and `QUERY`.

| Telemetry data | Behavior |
|---|---|
| Graph/node identity | Required for begin; owned graph nodes are checked against the current agent |
| Agent/task attribution | Captured from the current FAISAL task at begin |
| Context/tensor references | Optional capability-scoped references validated against existing FAISAL objects |
| Transport/provenance references | Optional session-local identifiers with capability or sequence checks |
| Kernel timing | `start_ns`, `end_ns`, and `duration_ns` use kernel boot-time timestamps |
| Provider measurements | Queue delay, observed runtime, byte counts, and provider sequence are recorded as supplied observations |
| Anomaly signal | Bounded score and flags are recorded when the anomaly flag is present; the kernel does not classify the signal |
| Event delivery | Each non-query update emits `AGI_LC_EVENT_GRAPH_OPERATION` through the existing filtered/sampled session event ring |
| Capability scope | Telemetry operations require the session lineage, current agent identity, and telemetry capability |

## Linux composition

Linux tracepoints remain the appropriate low-overhead hooks for subsystem instrumentation, and tracefs/perf remain the appropriate high-rate consumers [1] [2] [3]. M69 therefore avoids creating a second generic tracing framework. Its value is FAISAL-specific correlation: graph IDs, node IDs, agent/task IDs, capability-backed memory references, transport references, provenance sequences, and provider-supplied measurements are carried in one bounded record.

For hardware completion, Linux dma-buf and dma-fence synchronization remain authoritative [4]. M69 does not infer that a device operation completed merely because a userspace runtime submitted an END record. The `PROVIDER_MEASURED` flag marks an observation supplied by a provider or trusted runtime; it is not a kernel-generated proof of hardware execution.

## Validation

The full kernel and module build passed. The static selftest passed in QEMU and emitted:

```text
FAISAL_M69_BOOT_OK
M69_TELEMETRY_BEGIN_OK id=1 start=<kernel timestamp>
M69_TELEMETRY_QUERY_OK
M69_STALE_TELEMETRY_CAPABILITY_REJECT_OK
M69_ANOMALY_SIGNAL_OK score=420000
M69_TELEMETRY_END_OK duration=<kernel duration>
M69_GRAPH_EVENT_DELIVERY_OK
M69_COMPLETED_QUERY_OK
M69_SELFTEST_EXIT=0
FAISAL_M69_TEST_RC=0
```

The raw serial output is in `tools/faisal-build/evidence/m69-qemu.log`. Machine-readable results are in `tools/faisal-build/evidence/m69-graph-telemetry-validation.json`.

## Explicit non-claims

M69 does not provide tensor-content tracing, attention-layer semantic identification, model-drift detection, GPU-kernel introspection, vendor queue diagnostics, automatic anomaly classification, hardware fence creation, unified accelerator scheduling, or measured performance improvement. Tensor contents, embeddings, model weights, browser data, and semantic conclusions are intentionally absent from the kernel ABI.

A production integration still needs provider-specific tracepoints, dma-fence or timeline-fence correlation, driver reset/recovery metadata, trusted runtime attestation, and baseline-versus-FAISAL workload benchmarks.

## References

[1]: https://docs.kernel.org/trace/tracepoints.html "Linux kernel documentation: Using the Linux Kernel Tracepoints"
[2]: https://docs.kernel.org/trace/ring-buffer-map.html "Linux kernel documentation: Tracefs ring-buffer memory mapping"
[3]: https://docs.kernel.org/trace/ftrace.html "Linux kernel documentation: ftrace - Function Tracer"
[4]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
