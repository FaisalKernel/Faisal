# FAISAL M101 — Deadline-aware AGI execution urgency

## Scope

M101 adds a bounded kernel-native scheduling behavior to the existing FAISAL `AGI_LC_SET_SCHED_HINT` path. A non-zero absolute `CLOCK_MONOTONIC` deadline is converted into a coarse urgency band: expired or sub-5 ms slack maps to full util-clamp minimum, 5–20 ms maps to 75%, 20–100 ms maps to 50%, and larger slack has no deadline-derived boost. `latency_sensitive` provides a bounded 50% floor, while the existing `unblock_credit` and explicit `util_min` remain authoritative inputs. The feature uses Linux’s existing util-clamp scheduler control and does not add an ioctl or change the ABI layout.

The default recovered configuration remains safe: when `CONFIG_UCLAMP_TASK` is absent, the helper is not compiled and the established `-EOPNOTSUPP` behavior remains unchanged. An AGI-oriented configuration enables `CONFIG_CPU_FREQ_GOV_SCHEDUTIL=y` and `CONFIG_UCLAMP_TASK=y`.

## Implementation and validation

| Gate | Result |
|---|---|
| Existing recovered configuration driver build | Passed with `CONFIG_UCLAMP_TASK` disabled |
| AGI-oriented full kernel build | Passed; `bzImage` and `vmlinux` generated |
| Strict static selftest build | Passed for optimized and baseline modes |
| Optimized-kernel QEMU selftest | Passed; urgency reported as `util_min=1024`, hint readback passed |
| Unmodified-kernel QEMU baseline | Passed; baseline correctly reported `util_min=0` |
| Existing graph telemetry regression on optimized kernel | Passed; M69 selftest and kernel diagnostics clean |
| Matched benchmark trials | 10 optimized and 10 unmodified QEMU trials passed |

The measured 32-iteration scheduler-hint benchmark produced the following QEMU-only summary:

| Kernel | Mean per hint | Median per hint | Maximum observed |
|---|---:|---:|---:|
| FAISAL deadline urgency | 39,890 ns | 37,401 ns | 59,125 ns |
| Unmodified FAISAL baseline | 45,159 ns | 40,843 ns | 84,585 ns |
| Difference | -11.66% mean | -8.43% median | -30.09% maximum |

These numbers are a small, noisy QEMU TCG measurement of an ioctl path, not a hardware performance claim. The benchmark data is stored in `tools/faisal-build/evidence/superiority-scheduler-urgency-trials.csv` and the raw QEMU logs are retained separately.

## Security and correctness boundaries

The model does not set kernel authority. The request still requires a valid FAISAL lifecycle session and task lineage, and util-clamp remains a scheduler hint rather than a CPU-bandwidth guarantee. Deadline urgency does not bypass capabilities, cgroups, CPU affinity, scheduler policy, revocation, or independent approvals. An expired deadline raises a frequency-oriented utilization hint; it cannot force execution or prevent starvation by itself.

The implementation deliberately uses coarse bands rather than trusting arbitrary model-provided precision. It does not claim hard real-time behavior, deadline admission control, energy efficiency, fairness improvement, universal scheduler superiority, accelerator coordination, or performance on physical hardware. The next benchmark must include competing runnable work, deadline-miss rates, fairness, CPU frequency, power, and hardware runs before any stronger claim is allowed.

## References

[1]: https://docs.kernel.org/scheduler/sched-ext.html — Linux extensible scheduler class documentation.

[2]: https://docs.kernel.org/mm/damon/index.html — Linux DAMON documentation.

[3]: https://www.kernel.org/ — Linux Kernel Archives release snapshot.
