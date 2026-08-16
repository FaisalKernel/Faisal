# FAISAL M92: Userspace Key-Provider Hardening

**Milestone status:** Bounded malformed-input, concurrency, and lifetime hardening validated

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 unchanged

**Dependencies:** `FAISAL-M90` userspace provider and `FAISAL-M91` explicit unsupported hardware gate

## Summary

M92 hardens the M90 userspace key provider for concurrent use. A mutex now protects bounded key slots, active-key selection, generations, private-key ownership, and the tracked M87 service pointer. Lock-assuming internal helpers prevent recursive locking during active-key revocation and provider close. Public APIs reject malformed arguments and uninitialized-provider use.

The executable selftest covers 261 malformed-input cases, four concurrent signer workers, concurrent rotation through three additional keys, 256 revocation attempts, concurrent service bind/unbind, and provider close with a bound service. The test accepts only explicit expected denial codes during revocation races and fails on unexpected outcomes.

## Implemented files

| File | Role |
| --- | --- |
| `tools/faisal-key-provider/faisal_key_provider.h` | Mutex-protected provider state |
| `tools/faisal-key-provider/faisal_key_provider.c` | Locked lifecycle operations and cleanup helpers |
| `tools/testing/selftests/agi_key_provider_hardening_test.c` | Malformed and concurrent stress selftest |
| `tools/faisal-build/run_key_provider_hardening_qemu.sh` | Reproducible QEMU validation harness |
| `M92-KEY-PROVIDER-HARDENING-DESIGN.md` | Design and synchronization model |
| `M92-SECURITY-REVIEW.md` | Threat analysis and residual risks |
| `M92-BENCHMARKS.md` | Functional measurements and limitations |

## Verification record

| Gate | Result | Evidence |
| --- | --- | --- |
| Strict static build | Passed | `m92-strict-build.log` |
| Malformed inputs | Passed, 261 cases | `M92_MALFORMED_INPUTS_OK` |
| Concurrent provider stress | Passed | `M92_CONCURRENT_STRESS_OK` |
| Service lifetime cleanup | Passed | `M92_SERVICE_LIFETIME_OK` |
| Normal QEMU boot | Passed | `m92-key-provider-hardening-qemu.log` |
| ASan + UBSan | Passed without diagnostics | `m92-asan-ubsan-run.log` |
| TSan | Passed without data-race diagnostics | `m92-tsan-run.log` |
| M90 regression after M92 | Passed | `m90-after-m92-qemu.log` |
| M91 regression after M92 | Passed; unsupported status preserved | `m91-after-m92-qemu.log` |
| Three normal smoke runs | Passed 3/3 | `m92-key-provider-hardening-smoke.tsv` |
| Targeted security scan | Passed; 0 high-risk matches | `m92-security-scan.txt` |
| Diff hygiene | Passed | `git diff --check` |

## Acceptance scope

M92 is accepted as bounded userspace provider hardening for the tested schedules and lifetime model. It does not claim race freedom, formal verification, multi-service lifetime safety, process-crash recovery, hardware-backed keys, TPM2 or TEE support, remote attestation, secure boot, model-output authority, or production readiness. M91’s explicit unsupported hardware result remains the authoritative status for the current environment.

## References

[1]: `M92-KEY-PROVIDER-HARDENING-DESIGN.md` — design and synchronization.
[2]: `M92-SECURITY-REVIEW.md` — security review.
[3]: `M92-BENCHMARKS.md` — measurements.
[4]: `tools/faisal-build/evidence/m92-key-provider-hardening-validation.json` — machine-readable evidence.
[5]: `tools/faisal-build/evidence/m92-key-provider-hardening-qemu.log` — final QEMU output.
