# FAISAL Physical Accelerator Qualification

FAISAL separates **software/QEMU validation** from **physical accelerator qualification**. A QEMU device or a device-count field cannot prove GPU/NPU, VRAM, IOMMU, DMA, or vendor-driver readiness.

## Required physical evidence

The operator must run the read-only inventory collector on the exact host and kernel candidate:

```sh
python3 tools/faisal-build/collect_physical_accelerator_inventory.py physical-accelerator-inventory.json
```

For every GPU, NPU, or accelerator, the signed JSON report must bind the PCI BDF, vendor/device IDs, stable hardware identity, kernel driver/module and firmware versions, module and firmware digests, IOMMU driver and group membership, all devices in the group, PCIe ACS/topology review, DMA mask, mapping/synchronization/unmap/fault-containment tests, physical VRAM total/free measurements, allocation/reclamation/accounting/isolation tests, reset/recovery, stress, multi-tenant isolation, driver error recovery, and a physical workload result.

The report must include an operator-confirmed physical observation and one of the approved hardware-attestation classes: `operator_observed`, `provider_attested`, or `trusted_lab_attested`. The signature key must be an operator-trusted release or qualification key; a model-generated report or synthetic fixture is never evidence.

## Gate invocation

After signing the JSON report and detached signature with the trusted qualification key, run:

```sh
FAISAL_ACCELERATOR_EVIDENCE=/path/to/physical-accelerator-qualification.json \
FAISAL_PUBLIC_KEY=/path/to/trusted-qualification-public.pem \
FAISAL_EXPECTED_SOURCE_REV=$(git rev-parse HEAD) \
FAISAL_REQUIRE_ACCELERATOR_HARDWARE=1 \
FAISAL_ACCELERATOR_VERIFY_REPORT=/path/to/accelerator-verification.tsv \
  tools/faisal-build/verify_accelerator_qualification.sh
```

The gate must emit `FAISAL_ACCELERATOR_QUALIFICATION_OK`. Any missing physical observation, IOMMU group, driver signature, firmware digest, VRAM measurement, DMA protection test, or physical workload result fails closed.

## Current environment boundary

The current sandbox inventory records zero accelerator PCI devices, zero IOMMU groups, and no `/dev/dri`, `/dev/kfd`, or `/dev/vfio`. Its existing accelerator result is QEMU-TCG software validation only. Therefore this repository does not claim physical accelerator qualification until the signed report is collected on a real device host and independently reviewed.
