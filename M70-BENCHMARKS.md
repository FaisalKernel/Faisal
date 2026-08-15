# FAISAL M70 Measurements

M70 measures policy negotiation and lifecycle correctness. It does not measure actual CPU frequency, device wake latency, thermal behavior, energy use, or inference latency.

## Repeated QEMU smoke observations

The ABI-37 kernel booted a two-vCPU QEMU guest and the static power-policy selftest passed three times. Wall time includes QEMU startup, kernel boot, initramfs construction, selftest execution, and guest shutdown.

| Run | Wall time (s) | Result |
|---:|---:|---|
| 1 | 4.122 | `M70_SELFTEST_EXIT=0` |
| 2 | 4.069 | `M70_SELFTEST_EXIT=0` |
| 3 | 4.151 | `M70_SELFTEST_EXIT=0` |

These measurements are non-comparative smoke observations. They do not establish power-policy overhead, deterministic behavior, reduced energy, improved wake latency, or improved inference performance.

## Validated policy behavior

The selftest verified an inference policy request with CPU latency, device wake, and power-budget features. In the recovered QEMU configuration, CPU latency QoS was negotiated and applied (`applied=0x1`), while device wake latency and power budget were explicitly reported unsupported (`unsupported=0xa`). A stale capability was rejected, a `REQUIRE_ALL` request was refused with `-EOPNOTSUPP`, a policy event was delivered, and release transitioned the policy to RELEASED.

## Required hardware study

A meaningful M70 benchmark requires identical upstream and FAISAL kernels, configurations, compiler, firmware, drivers, runtime, model, and thermal environment. It must measure CPUFreq policy transition latency, actual versus requested frequency, idle-state residency, CPU PM QoS overhead, devfreq/provider wake latency, GPU/NPU power-state residency, package/device energy counters, thermal throttling, powercap behavior, inference first-token and inter-token latency, steady-state training throughput, and energy per token/sample. Cross-device coordination must be tested on a real platform with calibrated Energy Model or powercap data. No M70 performance improvement is claimed until these experiments exist.
