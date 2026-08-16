# M81 Benchmarks and Validation Results

## Summary

M81 measures the bounded lifecycle/IPC workload in QEMU rather than claiming general scheduler or IPC improvement. The workload uses eight concurrent sessions, 872 randomized valid inputs, 512 malformed requests, 48 cancellations, and 768 live message round trips.

| Validation | Result |
|---|---:|
| Clean smoke run 1 | 4,494 ms, pass |
| Clean smoke run 2 | 4,518 ms, pass |
| Clean smoke run 3 | 4,525 ms, pass |
| Clean smoke mean | 4,512.3 ms |
| Clean smoke range | 31 ms |
| KASAN + lockdep build | pass |
| KASAN + lockdep QEMU run | pass, 4 vCPU final run |
| KCSAN strict + lockdep build | pass |
| KCSAN strict + lockdep QEMU run | pass |
| Full FAISAL regression | 21/21 harnesses pass |

The clean smoke timings include kernel boot, initramfs construction, QEMU startup, selftest execution, and QEMU shutdown. They are harness wall-clock measurements, not isolated kernel IPC latency measurements. QEMU TCG timing is not a production hardware benchmark.

## Workload Counters

The final clean randomized run reported eight workers and eight passes, 512 malformed UAPI rejections, 16 capability denials, 48 cancellation passes, 768 messages sent and received, 872 randomized inputs, and nonzero queue pressure. The queue-pressure count varies with QEMU scheduling and is observed as a backpressure result rather than used as a fixed performance target.

## Sanitizer Configurations

The KASAN build enabled `CONFIG_KASAN`, `CONFIG_KASAN_GENERIC`, `CONFIG_KASAN_INLINE`, `CONFIG_PROVE_LOCKING`, `CONFIG_DEBUG_LOCK_ALLOC`, and `CONFIG_LOCKDEP`. The KCSAN build enabled `CONFIG_KCSAN`, `CONFIG_KCSAN_STRICT`, `CONFIG_KCSAN_SELFTEST`, `CONFIG_PROVE_LOCKING`, `CONFIG_DEBUG_LOCK_ALLOC`, and `CONFIG_LOCKDEP`. Both were built from the M86-audited source tree with the existing FAISAL configuration as the base.

The sanitizer results are detection results, not performance comparisons. Linux documentation notes that Generic KASAN has significant memory and performance overhead [1], while KCSAN uses sampled watchpoints and can miss races [2]. Lockdep validates observed lock-class dependency behavior and is not a substitute for exercising every path [3].

## Regression and Reproducibility

The tracked full-audit runner now rebuilds the M73 world-state, M77 verified-research, M81 concurrency, and M86 runtime-attestation selftests from current source before executing the 21 harnesses. This prevents stale prebuilt selftests from invalidating a source audit. A verified-research failure appeared only in the suite before the M77 rebuild step; it passed independent reruns and passed the final 21/21 audit after the runner was corrected.

## Non-claims

M81 does not claim lower IPC latency than upstream Linux, better scheduler throughput, race freedom, production sanitizer coverage, long-duration soak stability, accelerator concurrency, or hardware scalability. Those require controlled baseline comparisons, longer runs, real hardware, and broader subsystem coverage.

## References

[1]: https://docs.kernel.org/dev-tools/kasan.html "Linux Kernel Address Sanitizer documentation"
[2]: https://docs.kernel.org/dev-tools/kcsan.html "Linux Kernel Concurrency Sanitizer documentation"
[3]: https://docs.kernel.org/locking/lockdep-design.html "Linux runtime locking correctness validator documentation"
