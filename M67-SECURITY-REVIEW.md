# FAISAL M67 Security Review

## Scope

This review covers ABI-34 `AGI_LC_EXECUTION_DOMAIN`. The object constrains the calling task’s CPU affinity and reports a housekeeping complement; it does not grant authority over global Linux scheduler, IRQ, firmware, or hardware policy.

## Security properties verified

| Property | Enforcement | Evidence |
|---|---|---|
| Session lineage | The caller’s FAISAL lineage must match the session identity | Driver check and QEMU boot |
| CPU scope | Requested CPUs must be online and representable in the bounded ABI mask | Domain creation test |
| Housekeeping safety | The applied mask may not consume every online CPU | Domain creation test on two vCPUs |
| Task isolation scope | Affinity is applied only to the calling task through Linux scheduler APIs | Driver implementation |
| Domain ownership | Query and release require the opaque domain capability | Stale-capability rejection marker |
| Lifetime | Release increments generation and removes the record from active lookup | Release marker |
| Unsupported global policy | Required NO_HZ_FULL/IRQ-isolation/PREEMPT_RT requests return `-EOPNOTSUPP` | NO_HZ boundary marker |
| Firmware boundary | SMI and NMI are not represented as controllable features | ABI and documentation review |
| Model authority | Model output cannot create a kernel domain without the trusted FAISAL session and lineage | Driver/session checks |

## Threat model

A compromised or prompt-injected agent may attempt to occupy every CPU, move unrelated tasks, request a false deterministic guarantee, reuse a stale capability, or treat an isolated CPU as free from firmware interrupts. M67 rejects whole-machine masks, changes only the calling task’s affinity, requires exact capabilities for lifecycle operations, reports unavailable features, and refuses required global isolation mechanisms that it does not implement.

The object does not change `/proc/irq/*/smp_affinity`, managed IRQ policy, cpuset partitions, `nohz_full=`, `isolcpus=`, `rcu_nocbs=`, PREEMPT_RT configuration, watchdog masks, ACPI policy, or firmware settings. Existing Linux security controls remain in force.

## Residual risks

A task affinity mask is not a proof that the CPU receives no interrupts or kernel work. Linux documentation identifies residual tick, RCU, syscall, page-fault, timer, device, frequency, SMT, watchdog, and firmware-originated sources of jitter. In particular, x86 SMI activity is outside this ABI’s control. The selftest validates state transitions and policy boundaries, not worst-case latency.

M67 uses a fixed 16-entry per-session table and a four-word CPU mask. A future production implementation should integrate with a more formal resource object and cgroup/cpuset policy, add explicit task membership and supervisor delegation, and test CPU hotplug and concurrent release paths under lockdep/KCSAN/KASAN configurations.

## Review conclusion

M67 is acceptable as a bounded, capability-scoped execution-domain prototype with QEMU evidence. It must not be described as a deterministic execution guarantee or as an SMI/NMI mitigation. Production use requires trusted-supervisor policy, Linux boot-time isolation configuration, firmware review, and measured jitter testing on the target hardware.

## References

[1]: https://docs.kernel.org/admin-guide/cpu-isolation.html "Linux kernel documentation: CPU Isolation"
[2]: https://docs.kernel.org/timers/no_hz.html "Linux kernel documentation: NO_HZ: Reducing Scheduling-Clock Ticks"
[3]: https://docs.kernel.org/admin-guide/kernel-parameters.html "Linux kernel documentation: The kernel’s command-line parameters"
[4]: https://docs.kernel.org/admin-guide/lockup-watchdogs.html "Linux kernel documentation: Softlockup detector and hardlockup detector"
