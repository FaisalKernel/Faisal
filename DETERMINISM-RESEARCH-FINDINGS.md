# FAISAL Deterministic Execution — Research Findings

**Access date:** 2026-08-15
**Foundation:** Linux v7.2-rc7
**Status:** Research checkpoint; no deterministic-latency guarantee is claimed.

## Verified Linux mechanisms

Linux CPU isolation moves asynchronous housekeeping work to non-isolated housekeeping CPUs. The official CPU-isolation documentation describes scheduler-domain isolation, IRQ affinity, full dynticks, RCU callback offloading, and related tradeoffs. It explicitly requires at least one housekeeping CPU and notes that isolated CPUs still incur costs on kernel entry/exit and may be affected by page faults, SMT, frequency changes, deep C-states, and firmware-originated interrupts such as x86 System Management Interrupts.[1]

`CONFIG_NO_HZ_FULL` avoids scheduling-clock ticks on CPUs with a single runnable task, but it does not disable all interrupts or make arbitrary kernel entry deterministic. The official NO_HZ documentation requires at least one non-adaptive-tick CPU for timekeeping, explains RCU callback offloading, and lists constraints involving POSIX CPU timers, perf events, kernel entry/exit, and remaining sources of OS jitter.[2]

The kernel-parameter documentation defines `nohz_full=`, `irqaffinity=`, `isolcpus=`, and `rcu_nocbs=` as boot-time controls. These parameters configure existing kernel isolation behavior; a FAISAL object should not silently rewrite global boot policy or pretend to override managed IRQ, firmware, or hardware behavior.[3]

The lockup-watchdog documentation states that hardlockup detection may use periodic NMI perf events and that watchdog exclusion on nohz_full CPUs is a tradeoff: excluding watchdog activity helps preserve tickless userspace but reduces lockup detection on those CPUs.[4] FAISAL should expose this as an explicit compatibility and observability state rather than disabling watchdog safety implicitly.

## Design consequence

The smallest justified FAISAL addition is a **per-session execution-domain policy object** that validates a requested CPU mask, requires a nonempty housekeeping complement, records requested policy flags, applies task CPU affinity using existing scheduler interfaces, and reports which guarantees are not available. It may request tickless/IRQ isolation only as metadata and boot-policy compatibility checks; it must not claim to disable SMI/NMI, must not mutate global IRQ affinity without trusted system policy, and must not replace cpusets, housekeeping, NO_HZ_FULL, PREEMPT_RT, or watchdog controls.

## References

[1]: https://docs.kernel.org/admin-guide/cpu-isolation.html "Linux kernel documentation: CPU Isolation"
[2]: https://docs.kernel.org/timers/no_hz.html "Linux kernel documentation: NO_HZ: Reducing Scheduling-Clock Ticks"
[3]: https://docs.kernel.org/admin-guide/kernel-parameters.html "Linux kernel documentation: The kernel’s command-line parameters"
[4]: https://docs.kernel.org/admin-guide/lockup-watchdogs.html "Linux kernel documentation: Softlockup detector and hardlockup detector"
