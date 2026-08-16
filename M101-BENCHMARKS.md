# FAISAL M101 Benchmark Report — Deadline-aware scheduling urgency

## Method

The optimized FAISAL kernel and an unmodified pre-change FAISAL kernel were built from the same repository HEAD, with the same compiler, generated configuration, x86 architecture, QEMU machine, TCG accelerator, one virtual CPU, 512 MiB memory, BusyBox initramfs, static selftest, and userspace ABI. The only behavioral difference was the M101 deadline urgency implementation. Each trial executed 32 `AGI_LC_SET_SCHED_HINT` ioctl operations and reported the mean time per operation from `CLOCK_MONOTONIC` inside the guest.

Ten trials were collected for each kernel. Raw serial logs and the CSV are retained in `tools/faisal-build/evidence/superiority-scheduler-urgency-trials.csv` and the associated `qemu-scheduler-*.log` files. The QEMU results are integration measurements, not physical-hardware performance measurements.

## Results

| Kernel | Samples | Mean per hint | Median per hint | Maximum observed |
|---|---:|---:|---:|---:|
| FAISAL M101 deadline urgency | 10 | 39,890 ns | 37,401 ns | 59,125 ns |
| Unmodified matched baseline | 10 | 45,159 ns | 40,843 ns | 84,585 ns |
| Median difference | — | -11.66% | -8.43% | -30.09% |

The optimized kernel also passed the semantic assertion that a 5 ms-deadline latency-sensitive hint results in `sched_util_min=1024`, while the unmodified kernel passed the control assertion that the same hint leaves `sched_util_min=0`. Both kernels passed hint readback and boot-time diagnostic checks.

## Interpretation

The measured QEMU sample shows lower observed ioctl-path time for M101 in this environment, but the result is not sufficient to claim a general speed improvement. QEMU TCG scheduling noise, guest boot state, and the absence of competing runnable workloads limit the conclusion. The primary demonstrated gain is currently a **new enforceable scheduling signal**: an authorized AGI deadline can influence an existing Linux scheduling/frequency hint without changing ABI or bypassing security policy.

The next benchmark gate must use physical hardware and competing runnable work. It must measure p50/p95/p99 dispatch latency, deadline misses, CPU frequency, energy, fairness, starvation, and background-work throughput. The optimization should be reverted if those measurements show unacceptable regressions.

## References

[1]: https://docs.kernel.org/scheduler/sched-ext.html — Linux extensible scheduler class documentation.

[2]: https://mlcommons.org/benchmarks/inference-datacenter/ — MLCommons scenario and metric methodology.
