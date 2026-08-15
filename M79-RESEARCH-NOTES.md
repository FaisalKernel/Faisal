# M79 Research Notes

Accessed 2026-08-15. The sandbox exposes six Intel Xeon virtual CPUs, no `lspci` output, no accelerator device nodes, and no `/sys/class/accel` or DRM accelerator class. Therefore M79 cannot claim real-provider accelerator support in this environment.

## Official Linux accelerator subsystem

Source: [Linux compute accelerators introduction](https://docs.kernel.org/accel/introduction.html).

The Linux accelerator subsystem provides a common userspace-facing layer for compute accelerators, including standalone ASICs and IP blocks in SoCs/GPUs. Linux documents distinct edge-AI, inference data-center, and training data-center device categories, while noting that device-specific userspace stacks and compilers remain hardware-specific. The accelerator layer uses DRM infrastructure, exposes dedicated accelerator device nodes under `/dev/accel/accel*`, and requires `CONFIG_DRM_ACCEL` plus a driver using the compute-accelerator feature.

M79 consequence: FAISAL’s provider-neutral contracts can be exercised against the current kernel interfaces, but provider discovery and hardware execution must be reported as unavailable when the required device nodes/sysfs/provider evidence are absent.

## DRM memory management

Source: [Linux DRM Memory Management](https://docs.kernel.org/gpu/drm-mm.html).

Linux documents GEM and TTM as DRM memory-management components, with TTM supporting accelerator devices with dedicated memory and resource placement. M79 treats tensor memory placement and device-memory claims as provider evidence, not inferred from generic CPU or QEMU execution.

## dma-buf

Source: [Linux dma-buf documentation](https://docs.kernel.org/driver-api/dma-buf.html).

The dma-buf framework provides buffer sharing and synchronization across hardware drivers and subsystems, with dma-buf objects, dma-fences, and dma-resv coordination. M79 records that a provider-neutral transport contract is not equivalent to a real DMA path; an actual provider must expose and validate the device-specific exporter/importer/fence path.

## UACCE

Source: [Linux UACCE documentation](https://docs.kernel.org/misc-devices/uacce.html).

UACCE targets shared virtual addressing between accelerators and processes through IOMMU/PASID-related mechanisms and exposes device queue character files. Linux notes that negotiated device flags must be checked rather than assumed. M79 applies the same rule: requested accelerator features are distinct from available, unsupported, and provider-measured features.

## M79 implementation rule

The existing FAISAL M68–M70 interfaces can validate bounded request/response semantics, capability fields, resource masks, tensor transport metadata, graph telemetry, and power-policy intent. They cannot prove a physical accelerator exists. M79 therefore has an explicit `provider_available` branch and an honest unsupported result when no real provider evidence is present. QEMU smoke success is only userspace/kernel contract validation.

## References

[1]: https://docs.kernel.org/accel/introduction.html "Linux compute accelerators introduction"
[2]: https://docs.kernel.org/gpu/drm-mm.html "Linux DRM Memory Management"
[3]: https://docs.kernel.org/driver-api/dma-buf.html "Linux Buffer Sharing and Synchronization (dma-buf)"
[4]: https://docs.kernel.org/misc-devices/uacce.html "Linux UACCE framework"
