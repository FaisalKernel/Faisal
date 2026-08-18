# FAISAL Production Candidate Contract

M182 defines the strongest release state that can be honestly established in the current environment. FAISAL is a **bounded production candidate**, not a production-approved kernel.

## Candidate identity

The candidate manifest binds the exact repository control revision, Linux 6.18.44 LTS source revision, `bzImage`, `.config`, required `CONFIG_CFS_BANDWIDTH=y`, and the machine-readable evidence index. Every indexed evidence file is checked by SHA-256. A changed artifact or evidence file invalidates the manifest.

Generate and verify the manifest with:

```sh
python3 tools/faisal-build/prepare_production_candidate_manifest.py \
  --repo /home/ubuntu/agi-kernel/linux \
  --lts-build /home/ubuntu/agi-kernel/build/faisal-lts-6.18.44 \
  --output /path/to/production-candidate.json

FAISAL_PRODUCTION_CANDIDATE_MANIFEST=/path/to/production-candidate.json \
  python3 tools/faisal-build/verify_production_candidate_manifest.py
```

## Bounded qualification scope

The candidate includes the verified Linux 6.18.44 forward-port build, software regressions, tenant and durable QEMU tests, representative TCG soak using the documented ACPI-off profile, signed-structure evidence validators, and fail-closed negative-path tests. These establish a hardened candidate state within the available sandbox; they do not establish live production operation.

## Mandatory production blockers

Production approval remains blocked until the candidate has independent external builder or attested-farm evidence; an operator signing ceremony with protected root, trusted distribution, rotation, and revocation; physical GPU/NPU/VRAM/IOMMU/DMA/vendor-driver qualification; a genuine independent external security review with signed disposition; production PKI and external multi-host replication with live KMS/attestation; live multi-host migration, rollback, and irreversible-action compensation; and a live operator-owned CVE workflow with authenticated upstream synchronization and external-review feedback.

The manifest must remain `bounded_candidate_not_production_approved`, with `approval.status=blocked`, `operator_approved=false`, and `model_output_is_authority=false`. A model, local fixture, QEMU result, or generated report cannot authorize production.

## Release gate

The production gate requires the candidate manifest in addition to every blocker-specific evidence input. It fails closed on a missing manifest, changed artifact, stale or missing evidence, overstated scope, absent blocker, or any unsigned/missing external evidence. Passing the candidate-manifest check does not approve production; it confirms only that the candidate is internally coherent and truthfully bounded.
