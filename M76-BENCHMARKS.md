# FAISAL M76 Benchmarks and Measurement Limits

## Measurement scope

M76 measurements cover sequential service startup, durable experience and world-state appends, model checkpoint admission and rollback, browser/tool setup and action, light-agent registration, IPC send/receive/cancel, reflection, observability, deterministic failure recovery, and QEMU shutdown. They do not measure model quality, semantic reasoning, browser-engine performance, production multi-agent scalability, or real-world task success.

| Measurement | Result | Conditions |
|---|---:|---|
| Static selftest build | Pass | GCC strict warnings, static OpenSSL EVP linkage |
| QEMU smoke run 1 | 5.178647065 seconds | Two-vCPU QEMU, 768 MiB, boot through forced poweroff |
| QEMU smoke run 2 | 5.185287396 seconds | Same harness and environment |
| QEMU smoke run 3 | 5.056963716 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.161541444 seconds | Same harness and environment |
| QEMU smoke run 5 | 5.152207396 seconds | Same harness and environment |
| QEMU smoke-run range | 5.0570–5.1853 seconds | Five runs; includes boot and harness overhead |
| Malformed task cases | 64 | Requests rejected before service execution |
| Required regression harnesses | 12/12 passed | M64 and M66–M76 |

## Interpretation

The QEMU wall times include kernel boot, initramfs construction, dynamic lifecycle-device discovery, static coordinator startup, sequential M72–M75 service execution, IPC and cancellation, reflection and observability, the recovery fixture, and shutdown. They are smoke timings only. No upstream Linux or non-integrated baseline was collected for M76, so no speedup, slowdown, scalability, or efficiency claim is made.

The markers establish that the bounded task graph progressed through the existing services, that kernel identity and IPC contracts were exercised, that a queued message was cancelled, and that deterministic recovery closed the deployment gate. They do not establish that the model reasoned correctly, the webpage was safe, or the external task succeeded.

## Future benchmark work

A production comparison should separately measure stage latency, durable journal overhead, kernel-session setup, agent registration, IPC latency and tail behavior, cancellation latency, reflection/observability overhead, recovery time, resource footprint, and scalability under concurrent agents. It should compare identical workloads, models, browser engines, hardware, policies, and runtime versions against a baseline. Those measurements are not fabricated by M76.
