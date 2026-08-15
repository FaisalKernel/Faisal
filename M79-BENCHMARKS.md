# FAISAL M79 Benchmarks and Measurement Limits

## Measurement scope

M79 timings cover QEMU boot, lifecycle-device discovery, session setup, memory-region creation, compute-context negotiation, tensor policy/transport registration, graph telemetry, resource snapshot, power-policy intent, stale-capability tests, and shutdown. They do not measure accelerator execution, model throughput, provider latency, DMA bandwidth, physical power behavior, or production performance.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings; static binary |
| Provider evidence | Unsupported | No accelerator device node or sysfs class in sandbox |
| QEMU smoke run 1 | 3.988505831 seconds | Two-vCPU QEMU, 768 MiB, BusyBox initramfs |
| QEMU smoke run 2 | 4.084134426 seconds | Same harness and environment |
| QEMU smoke run 3 | 3.951014470 seconds | Same harness and environment |
| QEMU smoke run 4 | 4.016144580 seconds | Same harness and environment |
| QEMU smoke run 5 | 3.952204594 seconds | Same harness and environment |
| QEMU smoke-run range | 3.9510–4.0841 seconds | Five runs; includes boot and shutdown |
| Provider metadata fuzz cases | 64 | State, masks, IDs, names, and reserved fields |
| Required regression harnesses | 15/15 passed | M64 and M66–M79 |

## Interpretation

The wall-time values are operational smoke measurements for kernel/userspace contract validation. They are not accelerator measurements and are not comparable to GPU/NPU or provider-specific performance. No baseline comparison or optimization claim is made.

The passing markers establish that FAISAL can negotiate CPU and unsupported device/fabric masks, bind scoped memory and transport capabilities, record graph telemetry, report measured/unavailable/unsupported resource masks, preserve power-policy status, and deny stale handles. They do not prove hardware support.

## Future provider measurements

A provider-enabled M79 continuation must measure device discovery, negotiated provider features, context creation latency, memory placement, DMA-buf/fence transport, graph operation timing, accelerator accounting, power/thermal behavior, fault isolation, reset/recovery, and multi-agent contention on real hardware. Those measurements are intentionally not fabricated here.
