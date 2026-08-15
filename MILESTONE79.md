# FAISAL M79 — Provider-Gated Heterogeneous Accelerator Validation

**Status:** Validated as a provider-neutral, hardware-gated test in QEMU; no real accelerator provider claim.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.

## Scope

M79 adds `tools/faisal-accelerator/faisal_accelerator_validation.c` and its header. The service discovers provider evidence, validates bounded provider metadata, and exercises the existing FAISAL compute-context, memory-region, tensor-policy/transport, graph-telemetry, resource-snapshot, and power-policy interfaces. It keeps provider discovery separate from kernel metadata and reports unsupported hardware explicitly.

The authoritative Linux accelerator documentation describes a common accelerator userspace layer while retaining provider-specific driver and userspace stacks, dedicated accelerator device nodes, and provider-specific negotiation.[1] Linux’s DRM memory-management documentation describes common accelerator memory infrastructure, while dma-buf and UACCE document sharing/synchronization and negotiated accelerator capabilities rather than universal hardware semantics.[2] [3] [4]

The sandbox inspection found six Intel Xeon virtual CPUs, no `lspci` accelerator output, no accelerator device nodes, and no accelerator sysfs class. M79 therefore reports `M79_PROVIDER_UNSUPPORTED` and does not claim GPU, NPU, HBM, VRAM, DMA, SVA, UACCE, or provider-measured execution.

## Implementation and validation

The selftest performs 64 deterministic provider-metadata mutations, creates a scoped CPU-backed memory region and compute context, records active/unsupported device and fabric masks, registers a bounded CPU-fallback tensor transport, completes a graph telemetry operation, queries measured/unavailable/unsupported resource masks, requests inference power-policy intent, and verifies stale context/transport/telemetry capabilities are rejected.

Strict static compilation passed with `-O2 -Wall -Wextra -Werror -Wno-cpp`. QEMU passed the following markers.

```text
FAISAL_M79_BOOT_OK
M79_PROVIDER_UNSUPPORTED_OK
M79_PROVIDER_METADATA_FUZZ_OK iterations=64
M79_CONTEXT_FABRIC_OK active_devices=0x1 unsupported_devices=0xe active_fabric=0xf unsupported_fabric=0x30
M79_TENSOR_TRANSPORT_OK id=1
M79_GRAPH_TELEMETRY_OK id=1 state=2
M79_RESOURCE_MASKS_OK measured=0xa3 unavailable=0x5c unsupported=0x0
M79_POWER_POLICY_INTENT_OK applied=0x1 unsupported=0xa status=-95
M79_STALE_CAPABILITY_REJECT_OK
M79_NO_HARDWARE_CLAIM_OK
M79_SELFTEST_EXIT=0
FAISAL_M79_TEST_RC=0
```

Five repeated M79 QEMU smoke runs passed with wall times from 3.9510 to 4.0841 seconds. The M64 and M66–M78 regression suite plus M79 passed, for fifteen of fifteen harnesses. The failure scan found no M79 failure marker, kernel panic, `BUG`, `Oops`, or general-protection failure.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Provider discovery is separate from metadata | Pass | No provider device/sysfs evidence in sandbox |
| Unsupported hardware is reported honestly | Pass | `M79_PROVIDER_UNSUPPORTED_OK`, `M79_NO_HARDWARE_CLAIM_OK` |
| Compute-context isolation and masks | Pass | CPU active; GPU/NPU/IO unsupported masks retained |
| Tensor transport contract | Pass | Scoped CPU-backed transport registered and stale handle denied |
| Graph telemetry | Pass | Operation completed with bounded context/tensor linkage |
| Resource accounting | Pass | Measured/unavailable/unsupported masks recorded separately |
| Power coordination | Pass | CPU QoS applied; unsupported features/status retained |
| Provider metadata fuzzing | Pass | 64 malformed cases rejected |
| Capability security | Pass | Stale context, transport, and telemetry handles rejected |
| Build, boot, regression | Pass | Strict build, QEMU, M64 and M66–M79 |

## Explicit non-claims

M79 does **not** claim real accelerator hardware support, GPU/NPU execution, HBM/VRAM availability, DMA/RDMA success, SVA/UACCE negotiation, model performance, physical power coordination, or provider-specific correctness in QEMU. Provider completion remains gated on real hardware or an explicitly identified provider with device discovery, isolation, resource-accounting, transport, telemetry, and power evidence.

## References

[1]: https://docs.kernel.org/accel/introduction.html "Linux compute accelerators introduction"
[2]: https://docs.kernel.org/gpu/drm-mm.html "Linux DRM Memory Management"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux Buffer Sharing and Synchronization (dma-buf)"
[4]: https://docs.kernel.org/misc-devices/uacce.html "Linux UACCE framework"
