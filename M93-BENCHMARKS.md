# FAISAL M93 Benchmarks and Validation Measurements

**Status:** Functional measurements collected; no performance improvement claimed

## Workload

The M93 selftest provisions one Ed25519 key, binds eight M87 service objects, rejects a ninth registration, broadcasts revocation to all eight services, unregisters one service before close, invalidates the remaining seven during provider close, performs controlled restart recovery for seven services, and runs eight concurrent workers through 64 register/bind/unbind/unregister iterations each.

The normal QEMU workload uses the recovered FAISAL kernel, two virtual CPUs, 768 MiB of memory, the real `/dev/agi_lifecycle` M87 service path, and the static M93 selftest. Host sanitizer workloads use `FAISAL_M93_HOST_MODE=1` only for in-memory service fixtures; they do not replace the QEMU device test.

## Results

| Run | Configuration | Result | Host wall time |
| --- | --- | --- | ---: |
| Strict host | `-O2 -Wall -Wextra -Werror -pthread` | Passed; all M93 markers | Not timed |
| Final QEMU | Recovered FAISAL kernel; two vCPUs; 768 MiB | Passed; all markers and `M93_TEST_RC=0` | Not timed |
| ASan + UBSan | Host fixture; leak detection enabled | Passed without diagnostics | Not timed |
| TSan | Host fixture; eight workers × 64 iterations | Passed without race diagnostics | Not timed |
| Smoke 1 | Normal QEMU recovered kernel | Passed | 6809 ms |
| Smoke 2 | Normal QEMU recovered kernel | Passed | 7781 ms |
| Smoke 3 | Normal QEMU recovered kernel | Passed | 7031 ms |

The three final normal-smoke mean was **7207 ms**, rounded to the nearest millisecond. These end-to-end timings include static selftest compilation, initramfs creation, FAISAL kernel boot, QEMU execution, concurrent selftest activity, and shutdown. They are not provider-operation latency measurements, do not isolate registration-table overhead, are not compared with upstream Linux, and do not demonstrate a performance improvement.

## Regression results

The M90 key-provisioning and rotation/revocation contract passed after M93 with the required markers. The M91 provider-gated hardware boundary also passed and continued to report `provider=none status=1`, `device_present=0`, and explicit unsupported status. A two-vCPU M90 run emitted an RCU starvation diagnostic under a slow TCG execution, so the final recorded M90 regression uses a four-vCPU rerun with no RCU or kernel diagnostic matches. This is preserved as an environment-sensitive observation, not suppressed evidence.

## Sanitizer interpretation

The initial host ASan/UBSan attempt aborted before service assertions because the host lacked `/dev/agi_lifecycle`; this diagnostic was preserved during development and led to the explicit host fixture. The final ASan/UBSan run used leak detection and passed. QEMU covered the actual M87 lifecycle. TSan passed the concurrent provider-table schedule without data-race diagnostics.

These are bounded schedule samples. They do not prove race freedom, formal correctness, arbitrary service-destruction safety, production crash recovery, hardware-backed key security, or scalability beyond eight registered services.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
BUILD=/home/ubuntu/agi-kernel/build/recovered \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m93-key-provider-multiservice \
tools/faisal-build/run_key_provider_multiservice_qemu.sh
```

Host sanitizer reproduction requires compiling the selftest with the sanitizer flags recorded in the evidence build logs and running it with `FAISAL_M93_HOST_MODE=1`.

## References

[1]: `tools/faisal-build/evidence/m93-multiservice-smoke.tsv` — final three-smoke timing table.
[2]: `tools/faisal-build/evidence/m93-multiservice-smoke-mean.tsv` — calculated mean.
[3]: `tools/faisal-build/evidence/m93-multiservice-qemu.log` — final QEMU markers.
[4]: `tools/faisal-build/evidence/m93-asan-ubsan-final.log` — final ASan/UBSan output.
[5]: `tools/faisal-build/evidence/m93-tsan-final.log` — final TSan output.
[6]: `tools/faisal-build/evidence/m90-after-m93-qemu.log` — clean M90 regression rerun.
[7]: `tools/faisal-build/evidence/m91-after-m93-qemu.log` — M91 regression.
