# FAISAL Functional Audit — Clean Build, Boot, and Advanced Runtime Attestation

## Audit conclusion

FAISAL is **functionally operational as a Linux-derived experimental AGI control-plane kernel and userspace service stack** in the tested x86_64 QEMU environment. The current system builds from source, boots a freshly rebuilt kernel image, exposes `/dev/agi_lifecycle`, executes ABI 37 lifecycle operations, and passes the complete 19-harness milestone suite after two audit defects were corrected.

This conclusion is deliberately bounded. FAISAL is not a complete production operating system, does not execute models in the kernel, and does not claim physical accelerator functionality, long-duration reliability, arbitrary self-repair, or sanitizer/fuzzer coverage that was not executed.

## Clean source-to-boot verification

| Audit item | Result |
|---|---|
| Source base | Linux v7.2-rc7-derived FAISAL tree |
| Clean out-of-tree configuration | `build/audit-clean/.config` generated from the validated configuration with `olddefconfig` |
| Clean kernel build | `make O=build/audit-clean -j2 bzImage modules` passed |
| Clean kernel image | 15 MB x86_64 `bzImage` |
| Clean image SHA-256 | `436fbf876786fb5d61051543dcc7a81b96ca0f73bf94b491dbafdf6c6facc742` |
| Fresh-image QEMU boot | Passed |
| Lifecycle device exposure | `/dev/agi_lifecycle` created from sysfs major/minor metadata |
| Fresh-image M78 functional test | Passed |
| Current ABI | 37 |
| Required kernel facilities | initrd, devtmpfs, procfs, sysfs, modules, AGI lifecycle enabled |

The clean-image boot test executed independent approval denial, manifest-fuzz rejection, candidate integrity, checkpoint verification, canary failure, rollback, audit provenance, successful canary activation, and model-output non-authority checks.

## Defects reproduced and corrected

### CogOS harness artifact defect

The full audit reproduced a failure in `run_cog_kernel_qemu.sh`: it attempted to copy `tools/cog-kernel/cog_tester`, but the generated binary was intentionally not tracked. The harness was not self-contained. The fix makes the harness compile the static tester and rebuild the external module from the source Makefile before constructing the initramfs. The harness also now verifies that both artifacts exist before packaging.

### Stale M73 selftest artifact

The first full audit encountered an M73 explicit conflict-resolution failure because the QEMU harness used an older prebuilt selftest binary. Rebuilding the current M73 selftest from the current source eliminated the failure; the clean source and service implementation then passed. The audit response was to add a tracked full-audit runner and treat prebuilt test binaries as disposable build outputs rather than source-of-truth artifacts.

The M73 source was not changed for this issue. The failure exposed a reproducibility weakness in the audit process, not a persistent world-state service defect.

## Complete functional regression

The final current-tree audit passed all **19** QEMU harnesses: M64 security, M66 transport, M67 execution domain, M68 heterogeneous context, M69 graph telemetry, M70 power policy, M71 persistent memory, M72 experience learning, M73 world state, M74 orchestration, M75 browser/tool control, M76 multi-agent composition, M77 verified research, M78 deployment, M79 accelerator validation, M80 stress, M82 memory ecosystem, M84 CogOS module, and M85 self-healing.

The M79 provider-gated accelerator result remains correctly unsupported in QEMU. No unsupported hardware claim was inferred.

## Advanced feature added after audit

The audit-driven M86 runtime-attestation service reuses existing ABI 37 interfaces to sample self-state, resource accounting, observability, verifier identity, capability posture, and generation metadata. It computes a SHA-256 attestation digest and classifies the runtime as healthy, degraded, or unavailable. It is registered as a least-privilege verifier light agent with verification workload classification. It does not modify policy, grant capabilities, authorize model actions, or change kernel state.

M86 QEMU markers:

```text
FAISAL_M86_BOOT_OK
FRA_VERIFIER_IDENTITY_OK
FRA_ATTESTATION_OK valid=0x1f health=0x1f state=1 generation=2
FRA_RESOURCE_OK
FRA_SELF_STATE_OK
FRA_RESAMPLE_OK
FRA_DIGEST_CHANGED_ON_RESAMPLE_OK
FRA_SELFTEST_EXIT=0
FAISAL_M86_TEST_RC=0
```

Three independent M86 smoke runs passed with elapsed times of 4953 ms, 4861 ms, and 5155 ms. The mean was 4989.6 ms and the range was 294 ms. These are complete QEMU harness times, not isolated kernel-performance measurements.

## Remaining limitations

The audit does not establish production readiness, physical accelerator execution, multi-day or multi-week reliability, KASAN/KCSAN/UBSAN/lockdep/syzkaller coverage, randomized full-stack fuzzing, formal proof of all kernel invariants, distributed transactional recovery, or semantic quality of model reasoning. The kernel remains Linux-derived and control-plane-oriented: model execution, planning, browser engines, research reasoning, and semantic memory remain userspace responsibilities.
