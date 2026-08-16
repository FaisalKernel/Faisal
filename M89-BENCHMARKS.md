# FAISAL M89 RV Bridge Sanitizer Benchmarks

**Status:** Bounded validation evidence collected

## Workload

The M89 harness boots an RV-enabled FAISAL kernel, mounts tracefs, opens one subscribed and one unsubscribed lifecycle session, starts eight userspace workers, and executes eight open/configure/release cycles per worker. After the readiness marker and barrier release, a test-only kernel module starts two kernel report workers, each emitting 32 direct bridge observations. The subscribed session must read at least eight valid RV records; the unsubscribed session must remain empty.

The KASAN and KCSAN workloads use the same functional test. The only differences are the instrumented kernel configuration and QEMU virtual-CPU count selected to avoid unrelated RCU starvation from slow TCG sanitizer execution.

## Results

| Run | Kernel configuration | QEMU vCPUs | Result | Diagnostic findings |
| --- | --- | ---: | --- | --- |
| Normal smoke 1 | M88 RV kernel | 8 | Passed; 33 records | 0 |
| Normal smoke 2 | M88 RV kernel | 8 | Passed; 33 records | 0 |
| Normal smoke 3 | M88 RV kernel | 8 | Passed; 33 records | 0 |
| KASAN final | RV + Generic KASAN + lockdep | 1 | Passed; 8 records | 0 KASAN/lockdep/kernel diagnostics; 0 RCU warnings |
| KCSAN final | RV + strict KCSAN + lockdep | 1 | Passed; 8 records | 0 KCSAN/lockdep/kernel diagnostics; 0 RCU warnings |

The final normal smoke host wall times were 8607 ms, 7136 ms, and 7030 ms. Their mean was 7591 ms. Each run also passed malformed-consumer rejection, provenance, capability isolation, and the zero-diagnostic gate. This is an end-to-end QEMU harness timing, not an isolated bridge latency measurement and not a comparison against upstream Linux.

## Corrected finding

An earlier M89 attempt used eight vCPUs with KASAN and produced unrelated RCU starvation warnings due to QEMU TCG sanitizer overhead. Another early fixture attempted to call `rv_react()` from arbitrary kthreads and correctly triggered an invalid lockdep wait-context warning. The fixture was redesigned to call the bridge report function directly, and the final sanitizer configurations use one vCPU with no monitor activation. These findings and corrections are documented in `M89-SECURITY-REVIEW.md`; they are not hidden from the evidence trail.

## Interpretation and non-claims

The results demonstrate bounded concurrent bridge-report and lifecycle-session lifetime coverage under Generic KASAN+lockdep and strict KCSAN+lockdep. They do not demonstrate race freedom, production readiness, hardware scalability, physical scheduler-stall generation, upstream RV monitor correctness, or a performance improvement. The test-only fixture is not a production monitor, and storage of an observation does not imply model learning or repair authorization.

## Reproduction

```bash
cd /home/ubuntu/agi-kernel/linux
QEMU_SMP=1 QEMU_MEM=1024M \
BUILD=/home/ubuntu/agi-kernel/build/m89-rv-sanitizer \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m89-rv-kasan-smp1 \
tools/faisal-build/run_rv_bridge_sanitizer_qemu.sh

QEMU_SMP=1 QEMU_MEM=1024M \
BUILD=/home/ubuntu/agi-kernel/build/m89-rv-kcsan \
ROOTFS=/home/ubuntu/agi-kernel/build/qemu-faisal-m89-rv-kcsan-smp1 \
tools/faisal-build/run_rv_bridge_sanitizer_qemu.sh
```

## References

[1]: `tools/faisal-build/evidence/m89-normal-smoke.tsv` — three normal-kernel smoke measurements.
[2]: `tools/faisal-build/evidence/m89-kasan-qemu.log` — final Generic KASAN+lockdep run.
[3]: `tools/faisal-build/evidence/m89-kcsan-qemu.log` — final strict KCSAN+lockdep run.
[4]: `M89-RV-BRIDGE-SANITIZER-DESIGN.md` — workload and configuration design.
