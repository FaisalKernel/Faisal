# FAISAL M91: Provider-Gated Hardware Key and Attestation Integration

**Milestone status:** Explicit unsupported-provider validation passed; no hardware support claimed

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 unchanged

**Dependency:** `FAISAL-M90` bounded userspace signed-bundle key provider

## Summary

M91 turns the hardware/provider boundary into executable policy. It inspects observable provider state, distinguishes unsupported from unverified devices, rejects incomplete evidence, and ignores environment metadata as an authority source. The current sandbox exposes no qualifying TPM, TEE, HSM, KMS, or provider credential, so the correct result is `UNSUPPORTED`, not fabricated hardware attestation.

The implementation does not add a fake TPM or TEE driver. It defines the evidence contract required before a future provider can report support: identified provider, observable device, public-key provisioning, verified hardware attestation, rotation, revocation, and secret isolation.

## Implemented files

| File | Role |
| --- | --- |
| `M91-PROVIDER-RESEARCH.md` | Local inspection and authoritative Linux documentation findings |
| `tools/faisal-provider-gate/faisal_provider_gate.h` | Provider result and evidence contract |
| `tools/faisal-provider-gate/faisal_provider_gate.c` | Conservative device probe and incomplete-evidence validator |
| `tools/testing/selftests/agi_provider_gate_test.c` | Metadata-spoof resistance and unsupported-path selftest |
| `tools/faisal-build/run_provider_gate_qemu.sh` | Reproducible QEMU boot and unsupported-result gate |
| `M91-PROVIDER-GATE-DESIGN.md` | Provider boundary and failure model |
| `M91-SECURITY-REVIEW.md` | Threat analysis and residual risks |
| `M91-BENCHMARKS.md` | Unsupported-path measurements and limitations |

## Verification record

| Gate | Result | Evidence |
| --- | --- | --- |
| Strict static userspace build | Passed | M91 QEMU build log with `-Wall -Wextra -Werror -static` |
| Observable provider probe | Passed | `M91_PROVIDER_PROBE_OK provider=none status=1 device_present=0` |
| Environment metadata non-authority | Passed | `M91_ENV_METADATA_NOT_AUTHORITY_OK` |
| Incomplete evidence denial | Passed | `M91_INCOMPLETE_EVIDENCE_DENIAL_OK` |
| Explicit unsupported hardware result | Passed | `M91_HARDWARE_ATTESTATION_UNSUPPORTED_OK reason=no-provider` |
| Three clean QEMU smoke runs | Passed 3/3 | `m91-provider-gate-smoke.tsv` |
| Targeted source security scan | Passed; 0 high-risk matches | `m91-security-scan.txt` |
| Diff hygiene | Passed | `git diff --check` |

## Acceptance scope

M91 is accepted as explicit unsupported-provider validation. It does not claim TPM2 support, TEE support, HSM/KMS support, hardware-backed key provisioning, hardware attestation, secure boot, remote attestation, hardware rotation or revocation, or production readiness. A future provider-specific milestone must begin with an identified real provider or hardware device and must retain the same honest unsupported gate when prerequisites are absent.

## References

[1]: `M91-PROVIDER-RESEARCH.md` — research and local evidence.
[2]: `M91-PROVIDER-GATE-DESIGN.md` — architecture and evidence requirements.
[3]: `M91-SECURITY-REVIEW.md` — threat analysis.
[4]: `M91-BENCHMARKS.md` — measurements and non-claims.
[5]: `tools/faisal-build/evidence/m91-provider-gate-validation.json` — machine-readable validation.
