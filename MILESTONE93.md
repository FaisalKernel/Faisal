# FAISAL M93: Multi-Service Provider Lifetime

**Milestone status:** Bounded multi-service registration, revocation broadcast, safe close, controlled restart, and concurrent lifetime validation completed

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 unchanged

**Dependencies:** `FAISAL-M90` userspace key provider, `FAISAL-M91` explicit unsupported hardware/provider gate, and `FAISAL-M92` mutex-protected provider state

## Summary

M93 replaces the single tracked M87 service pointer with a bounded eight-entry registration table. The provider can register multiple services, bind public key metadata to each service, broadcast active-key revocation to all matching services, invalidate every registered service before provider close, and support explicit controlled restart recovery. Table insertion, duplicate detection, binding, unbinding, revocation, compaction, and cleanup remain serialized by the M92 provider mutex.

The selftest adds a capacity-denial case, eight-service revocation coverage, unregister-before-close, provider-close cleanup, seven-service controlled restart recovery, and eight concurrent workers performing 64 complete registration/bind/unbind/unregister iterations each. It does not claim transparent recovery from an arbitrarily crashed provider process; that boundary is recorded explicitly by `M93_PROCESS_CRASH_RECOVERY_NONCLAIM_OK`.

## Implemented files

| File | Role |
| --- | --- |
| `tools/faisal-key-provider/faisal_key_provider.h` | Bounded eight-service state and additive registration APIs |
| `tools/faisal-key-provider/faisal_key_provider.c` | Registration, duplicate handling, table compaction, revocation broadcast, and close invalidation |
| `tools/testing/selftests/agi_key_provider_multiservice_test.c` | Capacity, broadcast, safe-close, restart, and concurrent lifetime selftest |
| `tools/faisal-build/run_key_provider_multiservice_qemu.sh` | Reproducible static-build, initramfs, QEMU, marker, and diagnostic harness |
| `M93-MULTISERVICE-DESIGN.md` | Architecture, synchronization, lifecycle, rollback, and sanitizer boundary |
| `M93-SECURITY-REVIEW.md` | Threat analysis, corrected sanitizer finding, and residual risk |
| `M93-BENCHMARKS.md` | Functional measurements and timing limitations |

## Verification record

| Gate | Result | Evidence |
| --- | --- | --- |
| Strict userspace build | Passed with `-Wall -Wextra -Werror` | `m93-strict-build.log`, `m93-strict-run.log` |
| Eight-service registration and binding | Passed | `M93_MULTI_SERVICE_BIND_OK services=8` |
| Bounded capacity | Passed; ninth service denied | `M93_SERVICE_CAPACITY_DENIAL_OK capacity=8` |
| Revocation broadcast | Passed for eight matching services | `M93_REVOCATION_BROADCAST_OK services=8` |
| Safe unregister-before-close | Passed; seven entries remain | `M93_SAFE_SERVICE_CLOSE_OK remaining=7` |
| Provider close cleanup | Passed; all registered service metadata cleared | `M93_PROVIDER_CLOSE_CLEANUP_OK` |
| Controlled restart recovery | Passed for seven surviving service objects | `M93_CONTROLLED_RESTART_RECOVERY_OK services=7` |
| Concurrent provider-table stress | Passed; eight workers × 64 iterations | `M93_CONCURRENT_TABLE_STRESS_OK workers=8 iterations=64` |
| Real M87 QEMU lifecycle | Passed on recovered kernel | `m93-multiservice-qemu.log` |
| ASan + UBSan | Passed with leak detection and no diagnostics in explicit host fixture | `m93-asan-ubsan-final.log` |
| TSan | Passed without data-race diagnostics in explicit host fixture | `m93-tsan-final.log` |
| Three final QEMU smokes | Passed 3/3 with no diagnostic matches | `m93-multiservice-smoke.tsv` |
| M90 regression after M93 | Passed; clean four-vCPU rerun | `m90-after-m93-qemu.log` |
| M91 regression after M93 | Passed; unsupported provider status preserved | `m91-after-m93-qemu.log` |
| Targeted security scan | Passed; no prohibited authority or process-execution patterns | `m93-security-scan.txt` |
| Diff hygiene | Passed | `git diff --check` |

## Acceptance scope

M93 is accepted as a bounded userspace multi-service provider lifetime contract for the tested service ownership protocol and schedules. Private signing keys remain userspace-only, ABI 37 is unchanged, and M91’s explicit unsupported hardware/provider result remains authoritative.

M93 does not claim race freedom, formal verification, arbitrary unsynchronized service destruction safety, transparent provider-process crash recovery, durable key persistence, HSM/TPM/TEE integration, remote attestation, secure boot, model-output authority, autonomous kernel repair, or production readiness. The system remains an active engineering program rather than a complete AGI operating system.

## Rollback

The implementation can be reverted to `FAISAL-M92` by reverting the M93 implementation and test commit. The governance follow-up records the M93 tag and next dependency separately, so the rollback point remains auditable.

## References

[1]: `M93-MULTISERVICE-DESIGN.md` — design and synchronization model.
[2]: `M93-SECURITY-REVIEW.md` — threat analysis and residual risk.
[3]: `M93-BENCHMARKS.md` — measurements and limitations.
[4]: `tools/faisal-build/evidence/m93-provider-multiservice-validation.json` — machine-readable evidence.
[5]: `tools/faisal-build/evidence/m93-multiservice-qemu.log` — final QEMU output.
