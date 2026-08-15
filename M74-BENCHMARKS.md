# FAISAL M74 Benchmarks and Measurement Limits

## Measurement scope

M74 measurements cover operational service startup, policy checks, FAISAL checkpoint/verification, durable provenance append, rollback sequencing, and QEMU shutdown. They do not measure model quality, inference throughput, semantic accuracy, safety alignment, or upstream Linux performance.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings, static OpenSSL EVP linkage |
| QEMU smoke run 1 | 5.082647853 seconds | Two-vCPU QEMU, 512 MiB, boot through forced poweroff |
| QEMU smoke run 2 | 5.052336163 seconds | Same harness and environment |
| QEMU smoke run 3 | 5.070267551 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.021357302 seconds | Same harness and environment |
| QEMU smoke run 5 | 5.149878810 seconds | Same harness and environment |
| QEMU smoke-run range | 5.0214–5.1499 seconds | Five runs; includes boot and harness overhead |
| Policy mutation cases | 128 | Reserved-field mutations rejected before admission |
| Required regression harnesses | 10/10 passed | M64 and M66–M74 |

## Interpretation

The QEMU wall times include kernel boot, initramfs construction, dynamic lifecycle-device discovery, static process startup, policy checks, checkpoint and recovery ioctls, persistent-memory appends, and shutdown. They are smoke timings only. No baseline against upstream Linux was collected for M74, so no speedup, slowdown, latency-SLO, or efficiency claim is made.

The markers establish that the deterministic policy fixture rejects missing approval, over-budget, duplicate-nonce, unsupported-workload, empty-identity, and malformed reserved-field requests; that an admitted request receives explicit kernel resource budgets; that checkpoint verification and rollback complete; and that model output remains a proposal. They do not establish that the model output is correct or safe.

## Future benchmark work

A production comparison should separately measure policy admission latency, checkpoint/manifest/verification latency, rollback latency, journal append and replay, kernel gate transitions, resource-budget enforcement under contention, memory footprint, and tail latency. Model-serving benchmarks must compare identical models, providers, hardware, runtime versions, and batch/concurrency settings. Those measurements are not fabricated by M74.
