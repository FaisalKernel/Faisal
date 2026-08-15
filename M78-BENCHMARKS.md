# FAISAL M78 Benchmarks and Measurement Limits

## Measurement scope

M78 timings cover QEMU boot, lifecycle-device discovery, M71 journal/session startup, candidate digest validation, kernel checkpoint creation and verification, resource/observability snapshot, deterministic canary failure and rollback, a second successful activation path, and forced shutdown. They do not measure production deployment latency, application health, artifact distribution, hardware canary safety, or model quality.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings, static OpenSSL EVP linkage |
| QEMU smoke run 1 | 4.963650650 seconds | Two-vCPU QEMU, 768 MiB, BusyBox initramfs |
| QEMU smoke run 2 | 5.010334780 seconds | Same harness and environment |
| QEMU smoke run 3 | 5.030189180 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.015584504 seconds | Same harness and environment |
| QEMU smoke run 5 | 5.051033154 seconds | Same harness and environment |
| QEMU smoke-run range | 4.9637–5.0510 seconds | Five runs; includes boot and shutdown |
| Manifest fuzz cases | 64 | Structural and digest mutations rejected |
| Required regression harnesses | 14/14 passed | M64 and M66–M78 |

## Interpretation

The wall-time values are operational smoke measurements. They include kernel boot and shutdown, so they are not deployment-service latency measurements. No baseline Linux comparison was collected, and no optimization or performance improvement is claimed.

The passing markers establish that the test supervisor can bind a candidate digest, require independent approvals, create and verify a kernel checkpoint, observe measured/unavailable/unsupported resource masks, take both a deterministic health-failure rollback path and a successful activation path, and retain bounded audit records. They do not prove that a real application is safe to deploy or that every failure mode will be detected.

## Future measurement work

A production deployment benchmark should separately measure artifact distribution, signature verification, supervisor decision latency, canary warm-up, health-probe coverage, resource-monitor sampling overhead, checkpoint size and restore time, rollback time under concurrent workloads, audit durability, operator interaction latency, and multi-host coordination. Those measurements are not fabricated by M78.
