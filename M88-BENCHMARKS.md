# FAISAL M88 Benchmarks

**Status:** Clean bounded validation evidence collected

## Method

M88 was measured with the RV-enabled FAISAL kernel built from the repository source tree using the dedicated `build/m88-rv` output directory. The QEMU harness uses x86_64 TCG with two virtual CPUs and 1024 MiB of guest memory unless overridden. The benchmark includes strict selftest compilation, fixture-module compilation, initramfs construction, kernel boot, tracefs/RV interface setup, lifecycle subscription, deterministic fixture delivery, provenance checks, capability-filtering checks, and guest poweroff.

The fixture module intentionally provides a deterministic signal for bridge-path measurement. It is not a production monitor and does not measure physical scheduler-stall detection. The upstream `stall` monitor is nevertheless confirmed available, enabled, monitoring, and reacting in the guest.

## Results

| Run | Exit status | Wall time (ms) | RCU warning count | Required selftest markers |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 0 | 5791 | 0 | 2/2 |
| 2 | 0 | 5712 | 0 | 2/2 |
| 3 | 0 | 6014 | 0 | 2/2 |
| **Mean** | **0** | **5839** | **0** | **2/2** |

The wall-time mean is calculated from the three clean smoke runs in `tools/faisal-build/evidence/m88-rv-bridge-smoke.tsv`; it is a harness end-to-end measurement rather than a claim about bridge event latency in isolation. The individual QEMU console timestamp is not used as a performance metric because guest TCG and kernel timestamp behavior are not a stable host-wall-clock measurement.

The canonical run passed the following markers:

```text
M88_RV_AVAILABLE=stall
M88_RV_ENABLED=stall
M88_RV_MONITORING=1
M88_RV_REACTING=1
M88_RV_THRESHOLD=1000
FAISAL_M88_BOOT_OK
M88_SUBSCRIPTION_SETUP_OK verify_mask=0x20000
M88_RV_PROVENANCE_OK records=1 monitor_hash=0x9679
M88_CAPABILITY_FILTER_OK unsubscribed=1
M88_SELFTEST_EXIT=0
FAISAL_M88_TEST_RC=0
```

The pre-existing recovered-kernel regression completed all 23 harnesses with return code zero. It is retained as compatibility evidence and is intentionally reported separately from M88 because the M88 bridge requires the RV-enabled `build/m88-rv` kernel configuration.

## Interpretation

The measurements demonstrate repeatable boot-to-validation completion, deterministic bridge delivery, correct metadata provenance, subscriber isolation, and no RCU warning lines in the three smoke runs and canonical run. They do not demonstrate an improvement over upstream Linux, physical accelerator performance, real scheduler-stall detection latency, or a production-grade monitor-event rate. No such claims are made.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
BUILD=/home/ubuntu/agi-kernel/build/m88-rv \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m88-rv-canonical \
tools/faisal-build/run_rv_signal_bridge_qemu.sh
```

The complete raw logs, smoke table, build log, kernel configuration normalization log, and 23-harness summary are stored under `tools/faisal-build/evidence/`.

## References

[1]: `tools/faisal-build/evidence/m88-rv-bridge-smoke.tsv` — three clean smoke measurements.
[2]: `tools/faisal-build/evidence/m88-rv-bridge-qemu.log` — canonical QEMU result.
[3]: `tools/faisal-build/evidence/m88-full-23-regression-summary.txt` — recovered-kernel regression summary.
[4]: `tools/faisal-build/run_rv_signal_bridge_qemu.sh` — reproducible benchmark harness.
