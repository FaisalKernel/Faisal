# FAISAL M90: Production Key-Provider Contract

**Milestone status:** Bounded userspace key-provider contract validated; ready for integration review

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 unchanged

**Dependency:** `FAISAL-M89` concurrent RV bridge sanitizer validation

## Summary

M90 closes the key-lifecycle gap in M87 without placing private signing keys in the kernel. The new bounded userspace provider retains ephemeral Ed25519 private-key objects, derives stable public-key identities, assigns monotonic generations, supports active-key rotation, rejects duplicate provisioning, revokes keys, invalidates a bound M87 service when its active key is revoked, and refuses signing after revocation.

M87 now includes the signing-key identity and generation in the bundle digest. A service bound through M90 requires matching identity metadata, so a valid signature from a retired key cannot be accepted by a service bound to a newer key. Existing M87 metadata-free fixtures remain compatible only when no provider-required binding is active.

## Implemented files

| File | Role |
| --- | --- |
| `tools/faisal-key-provider/faisal_key_provider.h` | Bounded provider API and key-slot state |
| `tools/faisal-key-provider/faisal_key_provider.c` | Provision, rotation, revocation, signing, and M87 public-key binding |
| `tools/faisal-runtime-verification/faisal_runtime_verification.h` | M87 key identity and generation fields |
| `tools/faisal-runtime-verification/faisal_runtime_verification.c` | Signed-digest binding and provider-required fail-closed verification |
| `tools/testing/selftests/agi_key_provider_test.c` | Executable M90 lifecycle and authorization selftest |
| `tools/faisal-build/run_key_provider_qemu.sh` | Reproducible QEMU build, boot, and marker gate |
| `M90-KEY-PROVIDER-DESIGN.md` | Architecture and trust boundary |
| `M90-SECURITY-REVIEW.md` | Threat analysis and residual risk |
| `M90-BENCHMARKS.md` | Timing and functional measurements |

## Verification record

| Gate | Result | Evidence |
| --- | --- | --- |
| Strict static userspace build | Passed | M90 QEMU build log with `-Wall -Wextra -Werror -static` |
| Provisioning and duplicate rejection | Passed | `M90_KEY_PROVISION_OK` |
| Provider-bound signed verification | Passed | `M90_PROVISIONED_BUNDLE_VERIFY_OK` |
| Rotation and stale-key isolation | Passed | `M90_KEY_ROTATION_OK`, `M90_OLD_KEY_ISOLATION_OK` |
| Independent approval denial | Passed | `M90_INDEPENDENT_APPROVAL_DENIAL_OK` |
| Retired-key revocation isolation | Passed | `M90_OLD_KEY_REVOCATION_ISOLATED_OK` |
| Active-key revocation fail-closed | Passed | `M90_REVOCATION_FAIL_CLOSED_OK` |
| Three clean smoke runs | Passed 3/3 | `m90-key-provider-smoke.tsv` |
| M87 regression after digest-contract change | Passed | `m87-after-m90-qemu.log` |
| Targeted source security scan | Passed; 0 high-risk matches | `m90-security-scan.txt` |
| Diff hygiene | Passed | `git diff --check` |

## Acceptance scope

M90 is accepted as bounded userspace/provider validation for signed repair-bundle key lifecycle. It does not claim hardware security-module or TPM integration, secure-boot provisioning, remote attestation, encrypted persistent key storage, distributed quorum approval, formal cryptographic proof, kernel-held private keys, automatic repair authorization, model-output authority, or production readiness. The FAISAL implementation program remains active and incomplete.

## References

[1]: `M90-KEY-PROVIDER-DESIGN.md` — implementation boundary and state model.
[2]: `M90-SECURITY-REVIEW.md` — threat model and residual risks.
[3]: `M90-BENCHMARKS.md` — timing and functional evidence.
[4]: `tools/faisal-build/evidence/m90-key-provider-validation.json` — machine-readable validation.
[5]: `tools/faisal-build/evidence/m90-key-provider-qemu.log` — final QEMU runtime output.
[6]: `tools/faisal-build/evidence/m87-after-m90-qemu.log` — backward-compatibility regression.
