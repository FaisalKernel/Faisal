# FAISAL M91 Security Review: Provider-Gated Hardware Attestation

**Review status:** Passed explicit unsupported-path validation; hardware/provider integration remains unimplemented because no qualifying provider is available.

## Security objective

M91 prevents FAISAL from treating a nominal TPM, TEE, HSM, accelerator, environment variable, or model assertion as a hardware-backed root of trust without provider-specific evidence. The principal security failure would be a false `SUPPORTED` result that allowed M90 or M87 to rely on an unverified key or attestation source.

## Threat boundaries

| Threat | Required defense | M91 result |
| --- | --- | --- |
| Fake provider environment variable | Probe observable state, not metadata | Passed; `FAISAL_M91_PROVIDER` is ignored |
| Present but unverified TPM/TEE device | Separate `UNVERIFIED` from `SUPPORTED` | Passed by contract |
| Incomplete evidence | Require every key and attestation evidence flag | Passed; validator denies incomplete result |
| No provider in deployment | Return explicit `UNSUPPORTED` | Passed in QEMU and three smoke runs |
| Model or service claims hardware support | Never treat text as authority | No model input is consumed |
| Diagnostic suppression | Fail on kernel diagnostic markers | Harness gate present and clean |

## Local finding

The sandbox exposes no qualifying TPM, TEE, HSM, KMS, or provider credential. M79’s retained evidence independently records provider-neutral accelerator validation with an unsupported provider state. M91 therefore records `provider=none status=1` and does not implement a fake hardware path.

## Probe safety

The probe uses `stat()` against observable device nodes only. It does not open, configure, or claim a TPM or TEE device. A `/dev/tpm*` or `/dev/tee0` node alone yields `UNVERIFIED`, not `SUPPORTED`. This avoids confusing device presence with a verified trust source, trusted application, key provisioning policy, or attestation result.

The evidence validator requires provider identity, device presence, public-key provisioning, attestation verification, rotation verification, and revocation verification. Setting the result status manually cannot satisfy the missing evidence fields.

## Residual risks

M91 does not validate any real TPM, TEE, HSM, KMS, secure-boot measurement, remote-attestation protocol, hardware key rotation, or hardware revocation path. It also does not prove that a future provider implementation will be secure. Those risks remain explicitly open for a future provider-specific milestone and must be revisited only after real provider evidence is supplied.

## References

[1]: `M91-PROVIDER-RESEARCH.md` — authoritative-source findings and local hardware inspection.
[2]: `tools/faisal-provider-gate/faisal_provider_gate.c` — conservative observable probe and evidence validator.
[3]: `tools/testing/selftests/agi_provider_gate_test.c` — executable spoof-resistance and unsupported-path tests.
[4]: `tools/faisal-build/evidence/m91-security-scan.txt` — targeted source scan.
[5]: `tools/faisal-build/evidence/m79-accelerator-validation.json` — prior provider-neutral unsupported-hardware evidence.
