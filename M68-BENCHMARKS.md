# FAISAL M68 Measurements

M68 is a heterogeneous compute-context control-plane primitive. The validation measures correctness and bounded bookkeeping, not accelerator performance.

## Smoke measurements

| Measurement | Observation | Interpretation |
|---|---:|---|
| Full `bzImage modules` build | Passed | ABI-35 source compiles and links in the recovered configuration |
| Static selftest build | Passed | Userspace ABI layout and ioctl size agree |
| QEMU vCPUs | 2 | Hardware-neutral boot validation only |
| Bound region | 4096 bytes | Context accounting increased to 4096 and returned to zero after unbind |
| Reported active fabric | `0xf` | CPU, DMA-buf, DMA Engine, and IOMMU-SVA framework bits in this build |
| GPU-provider result | No active provider | The selftest confirms the request is reported unsupported rather than fabricated |
| QEMU selftest | Exit 0 | Lifecycle, capability, accounting, and boundary checks passed |

The QEMU run is not a latency or throughput benchmark. No inference, GPU, NPU, HMM migration, DMA transfer, SVA binding, or provider queue was active.

## Required future benchmark

A meaningful heterogeneous benchmark must compare an upstream Linux baseline and FAISAL on identical hardware and driver versions. It should measure model-store-to-device setup time, host-device transfer bandwidth, device-to-device transfer bandwidth, fence completion latency, page-migration fault cost, queue submission cost, CPU orchestration overhead, memory-tier residency, power, recovery after device reset, and multi-agent contention. Each device/provider must be benchmarked through its native supported API and then through any FAISAL integration layer. Until that experiment exists, M68 makes no performance-improvement claim.
