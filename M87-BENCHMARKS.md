# M87 Benchmarks and Validation Results

## Measured Results

| Validation | Result |
|---|---:|
| Clean smoke run 1 | 6,350 ms, pass |
| Clean smoke run 2 | 6,496 ms, pass |
| Clean smoke run 3 | 6,390 ms, pass |
| Clean smoke mean | 6,412.0 ms |
| Clean smoke range | 146 ms |
| Recovered-kernel QEMU | pass |
| Independently built clean-audit image | pass |
| Generic KASAN + lockdep | pass, four vCPUs |
| Strict KCSAN + lockdep | clean result, sixteen vCPUs |
| Focused source rebuild | pass with expected static-libcrypto linker warnings |
| Full FAISAL regression | 23/23 QEMU harnesses pass |

The clean-smoke timing includes source compilation by the harness, initramfs construction, QEMU boot, M86 attestation sampling, all M87 negative and positive checks, M85 checkpoint/canary/rollback activity, and QEMU shutdown. It is a QEMU TCG wall-clock measurement, not isolated cryptographic latency or a comparison against upstream Linux.

## Workload Counters

Each run samples one ABI 37 attestation, binds one runtime signal, rejects one mismatched signal, rejects one degraded attestation, rejects one unsupported provider, rejects one payload mutation, rejects one signature mutation, verifies one valid signed bundle, rejects one missing-operator approval through the existing supervisor, executes one canary-success path, and executes one canary-failure rollback path.

## Sanitizer Interpretation

Generic KASAN + lockdep completed without KASAN, lockdep, Oops, panic, or kernel-BUG signatures. Strict KCSAN + lockdep completed cleanly with sixteen virtual CPUs. The eight-vCPU KCSAN run completed the M87 workload but emitted an RCU starvation warning; it is retained as evidence and is not counted as clean. Increasing the virtual CPU budget to sixteen removed that warning in the recorded clean run. KCSAN is sampling-based and a passing run is not proof of race freedom [1].

## Regression Scope

The tracked runner rebuilds M73, M77, M81, M83, M86, and M87 tests from current source, then runs 23 QEMU harnesses. The final run passed all 23 without retry. The runner preserves both initial and retry logs when a transient QEMU failure occurs; this is a reproducibility feature, not a claim that transient failures are acceptable in production.

## Non-claims

M87 does not claim lower latency, formal verification, complete provenance, hardware-backed or remote attestation, secure-boot measurement, production key provisioning, production readiness, race freedom, or arbitrary kernel repair. It does not execute repair payloads. The model-output boundary is unchanged: a model proposal is not an authorization.

## References

[1]: https://docs.kernel.org/dev-tools/kcsan.html "Linux Kernel Concurrency Sanitizer documentation"
