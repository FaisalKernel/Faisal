# M83 Benchmarks and Validation Results

## Summary

M83 measures a bounded two-journal persistent-memory transaction rather than claiming that it makes Linux storage faster. Each clean run includes QEMU boot, initramfs construction, lifecycle-session setup, baseline writes, injected partial commit, rollback replay, successful commit replay, capability validation, 16 writes per journal, 2,000 protected reads, and QEMU shutdown.

| Validation | Result |
|---|---:|
| Clean smoke run 1 | 6,541 ms, pass |
| Clean smoke run 2 | 5,919 ms, pass |
| Clean smoke run 3 | 5,766 ms, pass |
| Clean smoke mean | 6,075.3 ms |
| Clean smoke range | 775 ms |
| Strict static userspace build | pass; linker emitted expected static-libcrypto glibc warnings |
| Generic KASAN + lockdep QEMU | pass, four vCPU run |
| Strict KCSAN + lockdep QEMU | clean result on eight vCPUs |
| Focused M71/M74/M82 regressions | 3/3 pass |
| Full FAISAL regression | 22/22 harnesses pass |

The timings are QEMU TCG wall-clock measurements and include boot and shutdown. They are not isolated transaction latency, storage throughput, crash-recovery latency, or an upstream baseline comparison.

## Measured Workload

The final test validates one rejected duplicate-target transaction, one injected partial commit after both journal operations, rollback to one baseline record in each journal, one successful two-journal commit, two journal replays, one stale-capability denial, 16 concurrent writer updates per journal, and 2,000 protected reads. The transaction coordinator is bounded at two operations by design.

## Sanitizer Interpretation

The Generic KASAN + lockdep result passed with no KASAN, lockdep, Oops, panic, or kernel-BUG signatures. A four-vCPU strict KCSAN run completed the workload but emitted RCU starvation warnings under instrumentation; that log is retained as a warning and is not counted as the clean KCSAN result. The eight-vCPU strict KCSAN rerun passed without RCU stalls or sanitizer/lockdep signatures. KCSAN’s official documentation describes sampling and possible false negatives, so this result does not establish race freedom [1].

## Regression Reproducibility

The tracked audit runner now rebuilds the M83 transaction selftest from current source and executes its harness after all previous FAISAL harnesses. The final audit completed 22/22. Existing M71 persistent-memory, M74 model-orchestration, and M82 memory-orchestrator harnesses also passed after the shared `fms_reactivate` API addition.

## Non-claims

M83 does not claim lower storage latency, stronger-than-filesystem durability, power-loss atomicity, distributed transaction support, formal verification, race freedom, production readiness, or hardware persistent-memory support. It does not claim that storing a transaction record retrains a model or that any model output authorizes a commit.

## References

[1]: https://docs.kernel.org/dev-tools/kcsan.html "Linux Kernel Concurrency Sanitizer documentation"
[2]: https://man7.org/linux/man-pages/man2/fsync.2.html "fsync(2) — synchronize a file's in-core state with storage device"
