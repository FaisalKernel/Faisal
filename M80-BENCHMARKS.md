# FAISAL M80 Benchmarks

## Measurement scope

M80 measured five independent executions of the complete QEMU stress harness after the static userspace rebuild. The timing includes initramfs construction, QEMU boot, the M80 bounded workload, marker validation, and guest shutdown. It is an end-to-end validation timing, not a kernel microbenchmark and not a comparison against upstream Linux.

| Run | Exit code | Elapsed wall time |
|---:|---:|---:|
| 1 | 0 | 5,342 ms |
| 2 | 0 | 5,259 ms |
| 3 | 0 | 5,401 ms |
| 4 | 0 | 5,326 ms |
| 5 | 0 | 5,405 ms |
| **Mean** | — | **5,346.6 ms** |
| **Minimum** | — | **5,259 ms** |
| **Maximum** | — | **5,405 ms** |
| **Population standard deviation** | — | **53.83 ms** |

## Workload and environment

Each run executed 256 malformed-UAPI cases, 8 resource samples, 3 M76 compositions, 8 cancellation passes, 2 rollback injections, audit-retention accounting, and provider-unsupported propagation. QEMU used the recovered FAISAL kernel image, x86_64 TCG, two virtual CPUs, and 768 MiB of guest memory. The guest mounted proc, sysfs, and a mode-1777 tmpfs at `/tmp`.

## Interpretation

All five runs returned exit code zero and emitted every required M80 marker. The measured timing is useful for detecting gross regressions in this harness, but it does not establish scheduler improvement, IPC improvement, memory-bandwidth improvement, accelerator performance, power efficiency, or superiority over upstream Linux. No baseline comparison was performed in this milestone, so no relative-performance claim is made.

The timing spread was 146 ms from minimum to maximum, with a population standard deviation of 53.83 ms. These values describe only this five-run QEMU sample and should not be generalized to physical hardware or production workloads.

## Evidence limits

The benchmark does not include CPU context-switch latency, syscall latency, kernel IPC latency, scheduler tail latency, memory allocation latency, multi-agent scalability, checkpoint throughput, recovery latency in a long-running workload, accelerator scheduling, KASAN/KCSAN overhead, or a native-versus-upstream comparison. Those remain separate benchmark dependencies.

## References

[1]: `MILESTONE80.md` — M80 workload and verification scope.
[2]: `tools/faisal-build/run_cross_subsystem_stress_qemu.sh` — timing target and QEMU environment.
[3]: `tools/faisal-stress/faisal_stress_service.c` — exact scenario bounds.
[4]: `/tmp/faisal-m80-smoke/summary.txt` — raw five-run smoke summary captured during validation.
