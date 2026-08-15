# FAISAL M73 Benchmarks and Measurement Limits

## Measurement scope

M73 measurements are operational smoke measurements for a userspace world-state service booted with the FAISAL Linux v7.2-rc7-derived kernel in QEMU. They verify that the service can initialize, exercise the ABI, persist bounded state, and shut down cleanly. They are not evidence of semantic world-model quality, general intelligence, or superiority over upstream Linux.

| Measurement | Result | Conditions |
|---|---:|---|
| Kernel build | 38 seconds | `make O=/home/ubuntu/agi-kernel/build/recovered -j2 bzImage modules`; sandbox build host |
| Static M73 selftest binary | 5,858,128 bytes | GCC static build with OpenSSL EVP, `-O2 -Wall -Wextra -Werror -Wno-cpp` |
| Kernel image | 14,898,176 bytes | `build/recovered/arch/x86/boot/bzImage` |
| QEMU smoke run 1 | 5.148116828 seconds | Two-vCPU QEMU harness wall time, including boot and shutdown |
| QEMU smoke run 2 | 5.098549365 seconds | Same harness and environment |
| QEMU smoke run 3 | 5.238809128 seconds | Same harness and environment |
| QEMU smoke run 4 | 5.039908856 seconds | Same harness and environment |
| QEMU smoke run 5 | 5.086969890 seconds | Same harness and environment |
| QEMU smoke-run range | 5.0399–5.2388 seconds | Five runs; not a latency SLO benchmark |
| Malformed UAPI cases | 64 iterations | Invalid-size world-sync, temporal, and resource-snapshot requests rejected with `EINVAL` |
| Required regression harnesses | 8/8 passed | M64 and M66–M72 QEMU harnesses |

## Interpretation

The QEMU times include kernel boot, initramfs construction, device-node discovery, static process startup, selftest execution, and forced poweroff. They should not be used to compare inference latency, memory bandwidth, scheduler behavior, or upstream Linux performance. No upstream baseline was collected in this M73 pass, so no speedup or regression claim is made.

The functional markers demonstrate exercised code paths: world synchronization and acknowledgement, stale-ack rejection, malformed-input rejection, freshness expiry with retained state, conflict retention and explicit resolution, temporal checking, stale capability rejection, and resource-mask reporting. They do not measure semantic correctness of values received from external sources.

## Future benchmark work

A meaningful performance comparison should use the same compiler, configuration, hardware or virtual machine, kernel command line, workload generator, and measurement protocol for upstream Linux and FAISAL. It should separately measure lifecycle ioctl latency, event enqueue/dequeue latency, persistent-memory append and replay, conflict-index lookup, temporal-check latency, resource-snapshot latency, CPU utilization, memory footprint, and tail latency under ring pressure. Those measurements are intentionally not fabricated by M73.
