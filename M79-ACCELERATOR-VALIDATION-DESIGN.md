# FAISAL M79 — Provider-Gated Heterogeneous Accelerator Validation

## Scope

M79 validates FAISAL’s provider-neutral accelerator control plane without fabricating hardware support. The service exercises compute-context negotiation, memory-region binding, tensor-transport metadata, graph-operation telemetry, resource snapshots, and workload-aware power-policy requests. It separately records whether a real accelerator provider is discoverable.

Linux’s accelerator subsystem exposes compute accelerators through a common userspace-facing layer, while driver and hardware-specific userspace stacks remain provider-specific. The documented accelerator device convention is `/dev/accel/accel*` and `/sys/class/accel/accel*`, with driver support and configuration requirements.[1] DRM memory managers provide common infrastructure for accelerator memory placement, including dedicated memory through TTM.[2] dma-buf provides buffer sharing and synchronization, but a generic metadata path is not proof that a real device DMA path exists.[3] UACCE describes negotiated accelerator capabilities and requires userspace to inspect negotiated flags rather than assuming requested capabilities were granted.[4]

## Provider evidence

M79 uses the following states:

| State | Meaning |
|---|---|
| `M79_PROVIDER_AVAILABLE` | A provider device node and provider-specific evidence are present and accepted by the validator. |
| `M79_PROVIDER_UNSUPPORTED` | The current environment has no accepted provider evidence; kernel metadata and CPU fallback remain testable. |
| `M79_PROVIDER_REJECTED` | Provider metadata is malformed, over-broad, or inconsistent and is rejected. |

The current sandbox has no `lspci` accelerator output, no accelerator device nodes, and no accelerator sysfs class. M79 must therefore report `M79_PROVIDER_UNSUPPORTED` in QEMU and may not claim GPU, NPU, HBM, DMA, SVA, UACCE, or provider-measured execution.

## Validation path

The selftest creates a bounded FAISAL lifecycle session and working memory region. It requests an all-device compute context and records the kernel’s active and unsupported device/fabric masks. It then exercises a CPU-backed tensor transport request, begins and ends a graph telemetry operation with provenance and provider-measured flags only where returned by the kernel, queries a resource snapshot, and requests inference power policy intent. Unsupported accelerator requests must fail closed or return explicit unsupported masks; they must not be converted into successful hardware claims.

Provider metadata fuzzing mutates device masks, provider kind, address-space mode, and capability flags. The service rejects impossible combinations and reserved-field mutations before any provider action. Stale context, tensor, telemetry, and power handles are denied by the kernel capability checks.

## Security and accounting boundary

A provider must not receive broader access than the requested device/context capability. Memory-region capabilities remain scoped to the current FAISAL session. Resource and telemetry values are measurements or explicit unsupported states, not semantic truth and not proof of a physical accelerator. Power policy is an intent request subject to provider/kernel availability, not a claim that hardware power state changed.

## Explicit non-claims

M79 does not claim accelerator hardware support, GPU/NPU execution, HBM/VRAM availability, DMA or RDMA success, SVA/UACCE negotiation, model performance, or physical power coordination in the QEMU environment. Real-provider completion requires hardware or an explicitly identified provider, provider-specific device evidence, isolation/resource-accounting tests, tensor transfer validation, telemetry correlation, and power behavior evidence.

## References

[1]: https://docs.kernel.org/accel/introduction.html "Linux compute accelerators introduction"
[2]: https://docs.kernel.org/gpu/drm-mm.html "Linux DRM Memory Management"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux Buffer Sharing and Synchronization (dma-buf)"
[4]: https://docs.kernel.org/misc-devices/uacce.html "Linux UACCE framework"
