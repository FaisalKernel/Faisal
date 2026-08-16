# FAISAL M100 Benchmarks and Validation Measurements

**Date:** 2026-08-16

## Measurement policy

M100 does not claim a speedup over upstream Linux because no apples-to-apples upstream adapter implementation was benchmarked. The measurements below establish reproducibility and bounded behavior for the new capability. They are not a productivity multiplier claim.

## Host timing

The strict host selftest was executed five times against the production adapter policy. Every run completed all effect, idempotency, ambiguity, revocation, scope, replay, and corruption checks successfully.

| Run | Wall time | Exit status |
|---:|---:|---:|
| 1 | 20 ms | 0 |
| 2 | 21 ms | 0 |
| 3 | 20 ms | 0 |
| 4 | 21 ms | 0 |
| 5 | 20 ms | 0 |

The raw measurements are stored in `tools/faisal-build/evidence/m100-host-benchmark.csv` after evidence collection. The working capture is `build/m100/benchmark-host.csv`.

## Kernel integration

The static selftest booted under the recovered FAISAL Linux v7.2-rc7 kernel in QEMU and acquired the real `/dev/agi_lifecycle` authority path. The recovered configuration has `CONFIG_SECCOMP=y` and `CONFIG_SECCOMP_FILTER=y`, while Landlock is disabled; the M100 implementation therefore exercised its documented seccomp-only fallback in this kernel configuration. QEMU exited with status 0 and emitted `FAISAL_M100_ADAPTER_SANDBOX_QEMU_PASS`.

The aggregate FAISAL audit completed **23/23 harnesses** successfully. One existing execution-domain harness required its built-in retry path; the aggregate summary records that initial retry event and final success. This is regression evidence, not an M100 performance comparison.

## Sanitizers and analysis

| Tool | Build | Run | Interpretation |
|---|---:|---:|---|
| UBSan | Pass | Pass | No undefined-behavior report in the selftest path |
| TSan | Pass | Pass | No race report in the exercised service path |
| ASan + UBSan | Pass | Failed closed under policy | Sanitizer runtime requires behavior outside the production seccomp allowlist; no sanitizer report emitted |
| GCC `-fanalyzer` | Pass | Pass | No analyzer diagnostic for the adapter translation unit |

The ASan result is intentionally not counted as a pass. A future milestone should add a clearly test-only sanitizer-compatible child policy or isolate the effect-application unit from the production seccomp path; production policy must remain narrow.

## Reproducibility

The host selftest was built with GCC 13.3.0-compatible system tooling using `-std=c11 -O1 -g -Wall -Wextra -Werror`, the recovered kernel was booted with QEMU 8.2.2, and the static QEMU binary was linked with the system static OpenSSL archive. Build and runtime logs are retained under `tools/faisal-build/evidence/`.

## References

[1]: https://docs.kernel.org/userspace-api/landlock.html — Linux Landlock userspace API documentation.

[2]: https://docs.kernel.org/userspace-api/seccomp_filter.html — Linux seccomp filter documentation.
