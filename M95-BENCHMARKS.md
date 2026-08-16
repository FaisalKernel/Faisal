# FAISAL M95: Durable Task Benchmarks and Validation Measurements

**Date:** 2026-08-16
**Measurement environment:** QEMU x86_64 TCG, recovered FAISAL kernel ABI 38, one virtual CPU for final durable-task validation
**Interpretation rule:** These are harness wall times and correctness measurements. They are not a comparison against upstream Linux and do not demonstrate a productivity multiplier.

## End-to-end QEMU smoke timings

| Run | Wall time |
|---|---:|
| Smoke 1 | 6,243 ms |
| Smoke 2 | 6,184 ms |
| Smoke 3 | 6,210 ms |
| Minimum | 6,184 ms |
| Maximum | 6,243 ms |
| Arithmetic mean | 6,212 ms |

The measurements include initramfs construction, QEMU startup, FAISAL kernel boot, lifecycle device-node creation, static selftest execution, journal replay/corruption checks, and QEMU shutdown. They therefore measure the validation harness, not task scheduling latency, journal throughput, model inference, or real workload productivity.

## Correctness and safety coverage

| Gate | Result |
|---|---|
| Strict static userspace build | Passed |
| Host functional selftest | Passed |
| AddressSanitizer + UndefinedBehaviorSanitizer with leak detection | Passed |
| ThreadSanitizer | Passed with no race diagnostics |
| Kernel-integrated QEMU test | Passed |
| Independent QEMU smoke runs | Passed 3/3 |
| Full existing FAISAL regression suite | Passed 23/23 |
| M90 signed-provider regression | Passed |
| M91 provider-gated hardware-attestation regression | Passed |
| Source security scan and shell/diff hygiene | Passed |

The selftest covers idempotent duplicate submission, idempotency conflict, dependency blocking, lease acquisition, heartbeat, completion, retry/backoff, restart recovery, policy cancellation, deadline stop, budget stop, retry-exhaustion dead-lettering, concurrent queries, replay reconstruction, and corrupted-tail fail-closed behavior.

## What is not measured

M95 does not yet include a baseline comparison with upstream Linux, durable journal throughput under sustained load, multi-process writer contention, distributed replication latency, task-selection quality, model quality, tool success rate, energy consumption, accelerator performance, economic value, or end-to-end agent productivity. Those measurements require a stable workload specification and are separate dependencies. No claim of faster execution, 1000× productivity, or superior AI-company economics is made.
