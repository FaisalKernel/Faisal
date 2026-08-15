# FAISAL M67 — Deterministic Execution-Domain Control

**Status:** Implemented and two-CPU QEMU-validated as a bounded control-plane prototype.
**Base:** Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7`.
**FAISAL ABI:** 34.
**Validation date:** 2026-08-15.

## Purpose

M67 adds `AGI_LC_EXECUTION_DOMAIN`, a capability-backed execution-domain object for an AGI workload that needs a constrained CPU set and an explicit housekeeping complement. The object validates an online CPU mask, applies the calling task’s affinity using the existing Linux scheduler API, records the resulting CPU and housekeeping masks, and reports which requested isolation features are unavailable in the current kernel/provider configuration.

This is intentionally **not** a replacement scheduler and not a runtime switch for global Linux isolation policy. Linux remains responsible for cpusets, scheduler domains, NO_HZ_FULL, RCU callback offloading, IRQ affinity, PREEMPT_RT configuration, watchdog policy, and device/firmware behavior.

## ABI behavior

| Item | Value | Meaning |
|---|---:|---|
| `AGI_LC_ABI_VERSION` | 34 | UAPI revision after M67 |
| `AGI_LC_EXECUTION_DOMAIN` | `0x60` | Create, query, or release an execution domain |
| Maximum records | 16/session | Bounded control-plane state |
| CPU mask words | 4 × 64 bits | Supports up to 256 CPU IDs in the ABI |
| Required housekeeping | Nonempty complement of applied CPUs | Prevents claiming whole-machine isolation |

Creation requires a nonempty set of online CPUs and rejects a mask that consumes every online CPU. The current task is affined to the requested online set. The response records the applied mask, the complement available for housekeeping, an opaque domain capability, owner identity, and a generation. Query and release require the exact capability. Release marks the object released, increments its generation, and removes it from active lookup.

Optional requests for NO_HZ_FULL, IRQ isolation, and PREEMPT_RT are reported as unsupported feature bits because M67 does not dynamically activate those global or build-time mechanisms. Required requests for those features return `-EOPNOTSUPP`. SMI and NMI control are not offered by the implementation.

## Implementation

The ABI is defined in `include/uapi/linux/agi_lifecycle.h`. The bounded records and control path are in `drivers/misc/agi_lifecycle.c`. The selftest is `tools/testing/selftests/agi_execution_domain_test.c`, and the two-vCPU boot harness is `tools/faisal-build/run_execution_domain_qemu.sh`.

The control path composes with Linux `set_cpus_allowed_ptr()` and does not mutate global IRQ masks, boot parameters, firmware state, or watchdog configuration.

## Verification

The kernel image and static selftest built successfully. QEMU was booted with two virtual CPUs and emitted:

```text
FAISAL_M67_BOOT_OK
M67_DOMAIN_CREATE_OK id=1
M67_DOMAIN_QUERY_OK
M67_STALE_DOMAIN_CAPABILITY_REJECT_OK
M67_NOHZ_BOUNDARY_OK
M67_DOMAIN_RELEASE_OK
M67_SELFTEST_EXIT=0
FAISAL_M67_TEST_RC=0
FAISAL_M67_SELFTEST_EXIT=0
```

Machine-readable evidence is in `tools/faisal-build/evidence/m67-execution-domain-validation.json`; the raw serial log is in `tools/faisal-build/evidence/m67-qemu.log`.

## Limitations

M67 does not prove deterministic latency, eliminate interrupts, suppress SMI/NMI, activate NO_HZ_FULL, redirect managed IRQs, enable PREEMPT_RT, or improve inference SLOs. Firmware-originated SMI activity remains outside the control of this ABI. A production deterministic deployment still requires boot-time Linux isolation configuration, an adequate housekeeping topology, workload discipline, memory pre-faulting/locking, IRQ and device policy, firmware configuration, and measured jitter analysis.

## References

[1]: https://docs.kernel.org/admin-guide/cpu-isolation.html "Linux kernel documentation: CPU Isolation"
[2]: https://docs.kernel.org/timers/no_hz.html "Linux kernel documentation: NO_HZ: Reducing Scheduling-Clock Ticks"
[3]: https://docs.kernel.org/admin-guide/kernel-parameters.html "Linux kernel documentation: The kernel’s command-line parameters"
[4]: https://docs.kernel.org/admin-guide/lockup-watchdogs.html "Linux kernel documentation: Softlockup detector and hardlockup detector"
