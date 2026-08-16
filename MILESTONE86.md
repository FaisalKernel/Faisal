# FAISAL M86 — Clean Functional Audit and Runtime Attestation

## Status

M86 confirms that FAISAL is functionally operational in the tested x86_64 QEMU environment as a Linux-derived AGI control-plane kernel and userspace service stack. The audit built the kernel from source in a fresh out-of-tree directory, booted the newly generated image, verified `/dev/agi_lifecycle`, exercised the deployment supervisor, and ran the complete current 19-harness regression suite.

The audit also added a structured runtime-attestation service over existing ABI 37 interfaces. The service registers as a least-privilege verifier light agent, samples self-state, resource accounting, observability, capability posture, and generation metadata, computes a SHA-256 evidence digest, and classifies the runtime as healthy, degraded, or unavailable.

## Audit results

| Area | Result |
|---|---|
| Clean `olddefconfig` | Passed |
| Clean `bzImage` and modules build | Passed |
| Clean image SHA-256 | `436fbf876786fb5d61051543dcc7a81b96ca0f73bf94b491dbafdf6c6facc742` |
| Fresh-image boot | Passed |
| Fresh-image lifecycle device | Passed |
| Fresh-image M78 selftest | Passed |
| Existing milestone harnesses | 19/19 passed |
| Runtime-attestation recovered-image QEMU | Passed |
| Runtime-attestation clean-image QEMU | Passed |
| Runtime-attestation smoke runs | 3/3 passed |
| Security source scan | No forbidden execution or unsafe-copy patterns found |

## Defects fixed during audit

The CogOS harness previously assumed an untracked `cog_tester` binary and failed before QEMU packaging. It now compiles the static tester and rebuilds the external module from source before creating the initramfs. The full audit also exposed that the M73 selftest binary was stale relative to the current source; rebuilding the selftest restored the expected conflict-resolution marker. A tracked full-audit runner was added so future audits can reproduce the complete suite rather than silently relying on stale test binaries.

## Runtime-attestation markers

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

The clean-image M86 test produced the same successful markers. The three recovered-image smoke runs measured 4953 ms, 4861 ms, and 5155 ms, for a mean of 4989.6 ms and range of 294 ms. These are complete QEMU harness times, not isolated kernel-performance measurements.

## Functional boundary

The kernel and services are functional for the tested control-plane capabilities: lifecycle identity, resource accounting, memory/checkpoint state, events/world state, orchestration, deployment rollback, stress paths, and runtime observation. Model inference, semantic reasoning, browser engines, research interpretation, and high-level planning remain userspace responsibilities. M79 accelerator validation remains explicitly provider/hardware-gated.

## Non-claims

M86 does not claim production readiness, bare-metal hardware coverage, physical accelerator execution, multi-day reliability, KASAN/KCSAN/UBSAN/lockdep/syzkaller coverage, formal proof of all kernel invariants, arbitrary self-repair, hardware-backed remote attestation, secure-boot measurement, or semantic correctness of model output.
