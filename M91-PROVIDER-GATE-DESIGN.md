# FAISAL M91: Provider-Gated Hardware Key and Attestation Design

**Status:** Explicit unsupported-provider validation passed; no hardware support claimed

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37

## Objective

M90 established a bounded userspace key-provider contract while deliberately leaving hardware-backed secrets and attestation provider-gated. M91 makes that gate executable. It probes only observable device/provider state, requires all evidence categories before reporting support, and emits `UNSUPPORTED` or `UNVERIFIED` rather than converting metadata or model claims into authority.

## Evidence requirements

| Evidence category | Required before `SUPPORTED` | Current result |
| --- | --- | --- |
| Identified provider or hardware | Yes | Not available in sandbox |
| Public-key provisioning | Yes | Not demonstrated |
| Hardware-backed attestation | Yes | Not demonstrated |
| Rotation | Yes | Not demonstrated for hardware provider |
| Revocation | Yes | Not demonstrated for hardware provider |
| Secret isolation | Yes | Not demonstrated for hardware provider |
| Security and regression evidence | Yes | Probe and unsupported-path evidence passed |

The probe distinguishes three states. `M91_PROVIDER_SUPPORTED` is reserved for a result with a recognized provider, an observable device, public-key provisioning, verified attestation, rotation, and revocation. A recognized device without identified trusted-application or cryptographic evidence is `M91_PROVIDER_UNVERIFIED`. No exposed provider is `M91_PROVIDER_UNSUPPORTED`.

## Linux integration boundary

The Linux trusted-key documentation describes trust sources such as TPM and TEE and distinguishes protected key material from userspace-visible key blobs. It also states that the consumer must judge whether a trust source is sufficiently safe for its threat environment. [1] The Linux TEE driver documentation describes Trusted Applications as UUID-identified devices on the TEE bus and notes that enumeration depends on the underlying TEE implementation. [2]

FAISAL therefore does not add a generic TPM or TEE claim. A future supported path must identify the actual device, provider implementation, Trusted Application or TPM policy, public-key provisioning mechanism, attestation format, rotation/revocation protocol, and independent validation evidence.

## Non-authority rule

The selftest sets `FAISAL_M91_PROVIDER=tpm2` deliberately. The probe ignores that environment metadata and reports the observed device state. In the current sandbox it reports `provider=none status=1`, followed by `M91_HARDWARE_ATTESTATION_UNSUPPORTED_OK reason=no-provider`. This proves that an environment string, provider metadata, or model output cannot authorize hardware-backed trust.

## Failure behavior

A missing provider remains unsupported. A present but unverified device remains unverified and is denied by the evidence validator. Incomplete evidence is denied even if the caller sets the nominal status to supported. There is no fallback from an unsupported hardware provider to a fabricated attestation; M90’s explicit userspace provider remains the available bounded fallback.

## References

[1]: https://docs.kernel.org/security/keys/trusted-encrypted.html — Linux Kernel, “Trusted and Encrypted Keys.”
[2]: https://docs.kernel.org/driver-api/tee.html — Linux Kernel, “TEE (Trusted Execution Environment) driver API.”
[3]: `M91-PROVIDER-RESEARCH.md` — saved research and local inspection.
[4]: `tools/faisal-provider-gate/faisal_provider_gate.c` — executable provider probe.
[5]: `tools/faisal-build/evidence/m91-provider-gate-validation.json` — machine-readable evidence.
