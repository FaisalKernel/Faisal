# FAISAL LTS Soak Requalification Research — 2026-08-18

## Empirical diagnosis

The M167 two-vCPU TCG profile was rejected correctly. Its preserved diagnostic log shows the guest completed the UAPI workload, then QEMU’s ACPI AML evaluation entered a loop timeout while the `rcu_preempt` grace-period kthread was starved on a two-vCPU TCG guest. The log includes `AE_AML_LOOP_TIMEOUT`, `_SB.PCI0._PRT`, `e1000 ... can't derive routing for PCI INT A`, and repeated `rcu: rcu_preempt ... stall` output. The failure was not suppressed.

A reproduction using the original profile (`-M pc`, ACPI enabled, TCG multi-threading, `qemu64`, two vCPUs, 768 MiB, 180-second timeout) reproduced the bounded timeout behavior. A one-vCPU run with the same LTS image also remained in the original timeout path because the harness waited for the guest’s poweroff instead of stopping after a verified fuzz-success marker.

## Mitigation

M180 adds two explicit harness controls. `FAISAL_QEMU_ACPI=off` uses QEMU’s `pc,acpi=off` machine profile, removing the emulated ACPI AML path that caused the observed TCG starvation. `FAISAL_QEMU_EXIT_ON_SUCCESS=1` stops QEMU after the guest has emitted `FAISAL_UAPI_FUZZ_RC=0`; this avoids treating a guest that completed the bounded workload as failed merely because TCG does not implement the requested poweroff path promptly. The harness still rejects timeout, missing boot/workload markers, RCU stalls, and kernel diagnostics.

## Requalification result

The LTS 6.18.44 artifact remained bound to source `105f2b85e4c26305a79f5e584df6ebb705858d33`, bzImage SHA-256 `8766f1019d80598c7982d91d89d7df27385a91ca7ea17d114d8869267204870b`, configuration SHA-256 `2c282274f1f716e2b1135b0a1fb819f99525dbe099ea0d31f1b3a2676f980e06`, and `CONFIG_CFS_BANDWIDTH=y`. With ACPI disabled and marker-driven exit, the bounded one-vCPU profile passed two rounds of 64 iterations, and the representative two-vCPU profile passed three rounds of 16,384 iterations without textual RCU or kernel diagnostics.

## Boundary

This closes the representative TCG-soak blocker for the documented `pc,acpi=off` virtualization profile. It does not qualify ACPI/firmware behavior, physical hardware, KVM acceleration, vendor devices, or production deployment. The original ACPI-on profile remains a recorded rejected diagnostic profile and is not silently relabeled as a pass.

## Sources

- [Linux RCU stall detector documentation](https://www.kernel.org/doc/html/latest/RCU/stallwarn.html)
- [QEMU system emulator documentation](https://www.qemu.org/docs/master/system/index.html)
- [QEMU invocation documentation](https://www.qemu.org/docs/master/system/invocation.html)
- [Linux 6.18.44 source and release records](https://www.kernel.org/)
