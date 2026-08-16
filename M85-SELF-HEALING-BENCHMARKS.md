# FAISAL M85 — Self-Healing Benchmarks

## Measurement scope

The measurements include complete QEMU startup, Linux boot, initramfs setup, FAISAL lifecycle-device setup, userspace service initialization, all self-healing scenarios, journal/checkpoint operations, and guest shutdown. They are not isolated kernel latency or repair-quality measurements.

## Smoke runs

| Run | Exit | Elapsed |
|---:|---:|---:|
| 1 | 0 | 4964 ms |
| 2 | 0 | 5036 ms |
| 3 | 0 | 5011 ms |
| 4 | 0 | 5064 ms |

Mean elapsed time was **5018.7 ms**, with a minimum of **4964 ms**, maximum of **5064 ms**, and range of **100 ms**. All four runs passed automatic rollback, approved repair, canary-failure rollback, security quarantine, retry-limit quarantine, and audit assertions.

## Regression

The existing M78 deployment-supervisor QEMU harness passed after M85 integration. Its independent approval denial, manifest fuzz rejection, checkpoint verification, canary failure, rollback, audit provenance, successful activation, and model-output non-authority markers all remained valid.

## Interpretation limits

These runs demonstrate repeatable bounded behavior in QEMU. They do not establish that self-healing is faster than manual recovery, that repair candidates are semantically correct, that the system can repair arbitrary errors, or that the system is production-ready. Future performance work should measure detection latency, diagnosis latency, checkpoint overhead, rollback time, canary false positives, recovery success under concurrency, and resource impact under sustained workloads.
