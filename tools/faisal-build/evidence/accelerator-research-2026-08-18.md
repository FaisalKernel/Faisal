# FAISAL accelerator qualification research — 2026-08-18

## Linux DMA API

Source: https://docs.kernel.org/core-api/dma-api-howto.html

The Linux DMA guide defines which memory may be used with DMA mappings, distinguishes CPU virtual/physical addresses from device bus addresses, and requires correct mapping, cache synchronization, DMA masks, and error handling. It explicitly warns that arbitrary vmalloc, kernel image, module image, or stack addresses must not be used as DMA buffers.

Qualification implication: physical-device evidence must include DMA mask, mapped-buffer and synchronization tests, DMA error-path results, and evidence that the active vendor driver uses the Linux DMA API correctly. A software/QEMU pass cannot satisfy this.

## Linux DRM memory management

Source: https://docs.kernel.org/gpu/drm-mm.html

Linux DRM uses GEM and TTM memory managers; TTM is intended for accelerator devices with dedicated memory and handles buffer-object lifetime, movement, and CPU mappings. The DRM documentation distinguishes UMA from discrete devices with dedicated VRAM.

Qualification implication: GPU evidence must distinguish system memory from dedicated VRAM, record driver-reported total/free VRAM, exercise allocation and reclamation, and bind those measurements to the exact PCI device and driver version. A `devices=1` count is insufficient.

## Pending research sources

The qualification implementation should additionally bind IOMMU group and VFIO evidence, vendor-driver/module provenance, firmware versions, PCI IDs, kernel configuration, DMA-BUF/PRIME or accelerator-specific memory paths, and a physical stress/recovery run. No physical accelerator is visible in the current sandbox, so no hardware result will be claimed.

## Linux VFIO and IOMMU groups

Source: https://docs.kernel.org/driver-api/vfio.html

VFIO exposes direct device access to userspace in an IOMMU-protected environment. DMA is the critical security risk because a device can otherwise read or write system memory. IOMMU groups are the minimum isolation and ownership unit; topology, multi-function devices, bridges, and missing PCIe ACS can reduce isolation granularity.

Qualification implication: physical evidence must record the PCI address, IOMMU group membership, all devices in that group, IOMMU mode/driver, ACS/topology limitations, VFIO or equivalent isolation result, and a negative DMA access test. A device-count-only or `iommu_groups` directory presence claim is insufficient.
