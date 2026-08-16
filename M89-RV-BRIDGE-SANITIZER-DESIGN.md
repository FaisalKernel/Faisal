# FAISAL M89 RV Bridge Sanitizer Design

**Status:** Validation evidence collected; milestone review in progress

**Base:** Linux v7.2-rc7

## Objective

M89 validates the M88 Runtime Verification bridge under concurrent lifecycle-session creation and release with sanitizer-enabled kernels. The test targets the new registry and report path rather than making a production claim about the upstream RV monitor itself.

The workload combines a persistent subscribed lifecycle session, one unsubscribed isolation session, eight userspace workers, repeated `open()`/`AGI_LC_CREATE`/`AGI_LC_ATTACH_TASK`/`AGI_LC_SUBSCRIBE`/`close()` cycles, and a deterministic in-kernel report source. The userspace workers exercise session lifetime while the kernel fixture concurrently emits bridge observations.

## Two trust-boundary tests

The committed M88 fixture remains the callback-path test: it invokes the upstream `rv_react()` entry point in a validation kernel and proves that the RV reactor hook reaches the bridge. M89 uses a separate fixture that calls the exported GPL bridge function `agi_lc_rv_report("stall", -EIO)` directly from two kernel worker threads. This isolates concurrent bridge registry and record-queue behavior from the upstream reactor wait-map context.

An initial M89 attempt invoked `rv_react()` from arbitrary kthreads and lockdep correctly reported an invalid wait context involving the upstream `rv_react_map` and hrtimer handling. That stimulus was not an appropriate model of a real RV monitor call site. It was removed from the M89 stress fixture rather than suppressing lockdep. M88 retains the deterministic `rv_react()` callback-path evidence, while M89 now tests the bridge’s concurrency contract directly.

## Synchronization protocol

The QEMU initramfs mounts tracefs and confirms the RV interface exists. The selftest opens and configures both persistent sessions, creates eight workers, prints and flushes its setup marker, writes `/tmp/m89-subscribed`, and then participates in a barrier with the workers. The init process waits for that marker before loading the stress fixture. The barrier count is `M89_WORKERS + 1` because the main thread is also a participant.

The stress fixture starts two kernel threads, each emitting 32 bridge reports, and waits for both to complete before module initialization returns. The selftest polls the subscribed session for at least eight valid RV records, joins all lifecycle workers, checks the record structure and metadata tag, and verifies that the unsubscribed session has no readable event.

| Component | Purpose |
| --- | --- |
| Persistent subscribed session | Receives and validates bridge records |
| Persistent unsubscribed session | Tests existing event-mask isolation |
| Eight userspace workers × eight cycles | Concurrent open/configure/release lifetime pressure |
| Two kernel report workers × 32 reports | Concurrent bridge registry and queue pressure |
| Readiness marker | Deterministic subscription-before-stimulus ordering |
| Barrier | Deterministic concurrent start without a timing race |

## Sanitizer kernels

Two dedicated configurations are built from the validated M81 KASAN baseline:

| Configuration | Purpose | QEMU settings |
| --- | --- | --- |
| RV + Generic KASAN + lockdep | Memory-safety and locking validation | 1 vCPU, 1024 MiB |
| RV + strict KCSAN + lockdep | Data-race and locking validation | 1 vCPU, 1024 MiB |

The validation-only `CONFIG_AGI_LIFECYCLE_RV_BRIDGE_TEST` export remains enabled in these kernels because the Kbuild directory also contains the committed M88 callback fixture. The M89 stress module itself calls only the production bridge export and does not require the test hook.

## Limitations

M89 does not claim race freedom, production readiness, hardware scalability, long-duration soak coverage, physical scheduler-stall generation, or upstream RV monitor correctness beyond the M88 callback test. QEMU TCG sanitizer execution is substantially slower than a native kernel run; the workload is intentionally bounded so the evidence is repeatable and interpretable. RCU starvation noise observed with higher virtual-CPU counts was removed by using one vCPU for both KASAN and KCSAN; the final runs contain no RCU, KASAN, KCSAN, lockdep, or kernel-warning diagnostics.

## References

[1]: `M88-RV-BRIDGE-DESIGN.md` — production bridge architecture and callback-path boundary.
[2]: `tools/faisal-rv/faisal_rv_bridge_stress_fixture.c` — M89 direct concurrent report fixture.
[3]: `tools/testing/selftests/agi_rv_bridge_concurrency_test.c` — M89 concurrent lifecycle selftest.
[4]: `tools/faisal-build/run_rv_bridge_sanitizer_qemu.sh` — M89 sanitizer QEMU harness.
