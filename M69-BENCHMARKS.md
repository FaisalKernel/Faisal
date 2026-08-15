# FAISAL M69 Measurements

M69 measures correctness and telemetry bookkeeping. It does not measure model quality, tensor-layer latency, GPU-kernel stalls, or accelerator throughput.

## Repeated QEMU smoke observations

The ABI-36 kernel booted a two-vCPU QEMU guest and the static graph-telemetry selftest passed three times. Wall time includes QEMU startup, kernel boot, initramfs creation, selftest execution, and guest shutdown.

| Run | Wall time (s) | Result |
|---:|---:|---|
| 1 | 4.208 | `M69_SELFTEST_EXIT=0` |
| 2 | 4.400 | `M69_SELFTEST_EXIT=0` |
| 3 | 4.182 | `M69_SELFTEST_EXIT=0` |

These values are smoke observations only. They are not a baseline comparison, not a kernel-overhead measurement, and not evidence of deterministic latency.

## Validated bookkeeping

The selftest verified that the kernel captured a nonzero begin timestamp, generated a completion duration, preserved a provider-supplied queue delay/runtime/byte/sequence observation, preserved an anomaly score across completion, rejected a stale telemetry capability, delivered a graph-operation record through the session event ring, and returned the completed record by query.

## Required performance study

A meaningful M69 benchmark must compare an upstream Linux build and FAISAL on the same hardware, kernel configuration, compiler, runtime, model, and provider drivers. It should measure disabled-versus-enabled telemetry overhead, begin/end ioctl latency, event-ring emission cost, sampling ratios, dropped-record behavior, graph-node correlation overhead, cross-CPU timestamp ordering, provider fence-correlation latency, and end-to-end inference traces. A separate provider benchmark must measure attention-layer and device-queue behavior through the provider’s supported instrumentation. No M69 performance improvement is claimed until those measurements exist.
