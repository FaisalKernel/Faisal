# FAISAL Linux 6.18.44 LTS Requalification

FAISAL distinguishes the original ACPI-on two-vCPU TCG failure from the corrected representative virtualization profile. The original profile remains a rejected diagnostic result and is never converted into a pass.

## Exact representative command

Use the exact LTS build and source revision recorded in the M180 evidence:

```sh
FAISAL_BUILD=/home/ubuntu/agi-kernel/build/faisal-lts-6.18.44 \
FAISAL_SOAK_OUT=/home/ubuntu/agi-kernel/build/m180-requalification/two-vcpu \
FAISAL_SOAK_ROUNDS=3 \
FAISAL_SOAK_ITERATIONS=16384 \
FAISAL_QEMU_SMP=2 \
FAISAL_QEMU_ACPI=off \
FAISAL_QEMU_EXIT_ON_SUCCESS=1 \
FAISAL_QEMU_TIMEOUT_SECONDS=180 \
  tools/faisal-build/run_industry_soak_qemu.sh
```

The bounded comparison profile uses two rounds, 64 iterations per round, one vCPU, the same TCG/ACPI-off profile, and marker-driven exit. The launcher requires boot, fuzz-success, and return-code markers; it rejects timeouts, RCU stalls, kernel diagnostics, and missing markers. The wrapper scans only textual QEMU logs, not binary initramfs files.

## Why ACPI is disabled

The rejected M167 profile used `-M pc` with ACPI enabled. Its preserved log recorded an AML loop timeout while evaluating `_SB.PCI0._PRT`, a failed e1000 interrupt-routing derivation, and repeated `rcu_preempt` stall diagnostics on the two-vCPU TCG guest. M180 uses `-M pc,acpi=off` to remove that emulator firmware path. This is a documented virtualization-profile mitigation, not a kernel or physical-platform claim.

## Evidence verification

The signed M180 JSON report is verified with:

```sh
FAISAL_LTS_SOAK_EVIDENCE=/path/to/m180-lts-soak-requalification.json \
FAISAL_PUBLIC_KEY=/path/to/operator-validation-public.pem \
FAISAL_EXPECTED_SOURCE_REV=<candidate-source-revision> \
  python3 tools/faisal-build/verify_lts_soak_requalification.py
```

The validator binds the Linux 6.18.44 source revision, bzImage, configuration, and `CONFIG_CFS_BANDWIDTH=y`; requires the bounded one-vCPU and representative two-vCPU thresholds; requires documented RCU-stall reproduction and mitigation; and rejects any kernel diagnostic in completed evidence. Model output is never authority.

## Explicit limitations

M180 qualifies the representative two-vCPU TCG profile with ACPI disabled. It does not qualify ACPI/firmware behavior, KVM acceleration, physical CPUs, physical accelerators, vendor drivers, or production deployment. The production release gate remains subject to the independent builder, signing authority, external security review, physical accelerator, replication, deployment, and other outstanding blockers.
