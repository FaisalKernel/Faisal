# FAISAL M94 Benchmark and Validation Report

**Measurement date:** 2026-08-16
**Kernel base:** Linux 7.2-rc7-derived FAISAL tree
**ABI:** 38

## Scope

M94 introduces a bounded intent-lease table and an additive lifecycle ioctl. The measurements below report validation duration and pass/fail outcomes; they do **not** establish a productivity multiplier, throughput improvement, lower latency, or superiority over upstream Linux.

## Dedicated QEMU smoke measurements

The same recovered FAISAL kernel image, static selftest, QEMU machine, memory size, and harness were used for three clean runs. The wall time includes initramfs construction, boot, selftest execution, and shutdown.

| Run | End-to-end wall time |
| --- | ---: |
| Smoke 1 | 4265 ms |
| Smoke 2 | 4120 ms |
| Smoke 3 | 4089 ms |
| Mean | 4158 ms |
| Minimum | 4089 ms |
| Maximum | 4265 ms |

These values describe the harness environment only. They are not a production latency benchmark and were not compared against an upstream baseline.

## Verification matrix

| Validation | Result |
| --- | --- |
| Modified lifecycle driver build | Passed |
| Static M94 selftest build with `-Wall -Wextra -Werror` | Passed |
| Normal QEMU intent-lease selftest | Passed |
| Three clean normal QEMU smokes | Passed 3/3 |
| Generic KASAN + lockdep QEMU selftest | Passed clean with one vCPU |
| Strict KCSAN + lockdep QEMU selftest | Passed clean with one vCPU |
| M90 signed-provider regression | Passed |
| M91 provider-gated hardware-attestation regression | Passed; unsupported gate preserved |
| Complete FAISAL audit | Passed 23/23 harnesses |
| Diff and prohibited-pattern security scan | Passed |

## Functional coverage measured by markers

The dedicated selftest measured successful acquisition, single-use consumption, replay denial, bounded multi-use consumption, query, intent mismatch denial, expiry fail-closed behavior, capability-grant gating, explicit revocation, session invalidation, and clean exit. The final one-vCPU sanitizer configurations observed the same sequence without KASAN, KCSAN, lockdep, or kernel diagnostic markers. Earlier two-vCPU KASAN/KCSAN attempts also completed the selftest but produced QEMU virtual-clock RCU starvation warnings; those logs are preserved as diagnostic artifacts and are not used as the clean sanitizer result.

## Corrected regression measurement

The first post-M94 full-audit attempt failed only in the verified-research harness because its test fixture used a one-second freshness TTL and QEMU virtual-clock latency allowed the record to expire before promotion. The failure was reproduced, diagnosed, and corrected by using the existing `AGI_LC_KNOWLEDGE_MAX_TTL_NS` fixture limit. The final audit then passed all 23 harnesses. This correction changes test robustness; it does not claim a kernel performance improvement.

## Unmeasured dimensions

M94 does not yet measure lease lookup scalability beyond the 64-record bound, lock contention with many concurrent agents, cross-NUMA behavior, accelerator coordination, energy, browser action latency, storage or network throughput, or end-to-end agent productivity. Those measurements require dedicated workloads and a defined upstream or pre-M94 baseline.
