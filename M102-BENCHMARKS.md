# FAISAL M102 benchmark report

## Method

The benchmark measures the complete host selftest lifecycle for the M102 adapter: service open, valid authority fixture, fixed-command registration, verified child execution, duplicate and conflict checks, network-deny probe, filesystem-write-deny probe, revocation, scope validation, journal replay, and corruption fail-closed replay. It is a functional end-to-end timing measurement, not a synthetic syscall microbenchmark and not a comparison against OpenSandbox, srt, gVisor, Firecracker, or another kernel.

Ten trials were run on the same host binary and environment. Every trial returned zero.

| Metric | Measured value |
|---|---:|
| Trials | 10 |
| Successful trials | 10/10 |
| Mean wall time | 0.024109 s |
| Median wall time | 0.023513 s |
| Minimum wall time | 0.022538 s |
| Maximum wall time | 0.028887 s |

The raw CSV is `tools/faisal-build/evidence/m102-benchmark-host.csv`. The benchmark includes process creation, namespace capability probing, Landlock/seccomp setup, output capture, SHA-256 hashing, M99 completion, journal fdatasync, and replay checks. It must not be interpreted as the latency of a single tool invocation in production.

## Validation matrix

| Gate | Result | Interpretation |
|---|---|---|
| Strict userspace build | Pass | Adapter and selftest compile with warnings as errors |
| Static initramfs build | Pass | Binary is suitable for BusyBox QEMU harness |
| Host selftest | Pass | All M102 functional markers passed |
| Recovered FAISAL kernel QEMU | Pass | Lifecycle device and kernel authority path were exercised |
| M100 host regression | Pass | Existing deterministic effect capsule remained intact |
| M100 QEMU regression | Pass | Existing real-kernel sandbox path remained intact |
| UBSan build and run | Pass | No UBSan finding in the completed run |
| GCC analyzer | Pass | No analyzer diagnostic for adapter translation unit |
| TSan build | Pass; runtime limitation | Binary compiled, but production seccomp rejects sanitizer runtime before full test |
| ASan+UBSan build | Pass; runtime limitation | Binary compiled, but production seccomp rejects sanitizer runtime before full test |
| Aggregate 23-harness audit | Incomplete | Existing audit reached harness 18 and failed in `run_cog_kernel_qemu.sh`; failure is outside M102 and is preserved in evidence |

## Performance interpretation

The ten-trial result establishes repeatability for this test environment only. It does not demonstrate superiority over current kernels or sandbox runtimes. A meaningful future comparison must use matched hardware and workloads, include deadline and failure-rate metrics, and compare M102 against a clearly specified baseline such as direct process execution, bubblewrap/srt, gVisor, and Firecracker where available. Security strength, startup time, throughput, output latency, memory footprint, and crash recovery must be reported together.

## References

[1]: https://github.com/opensandbox-group/OpenSandbox — OpenSandbox platform reference.

[2]: https://github.com/anthropic-experimental/sandbox-runtime — sandbox-runtime reference.

[3]: https://github.com/google/gvisor — gVisor runtime reference.

[4]: https://github.com/firecracker-microvm/firecracker — Firecracker runtime reference.
