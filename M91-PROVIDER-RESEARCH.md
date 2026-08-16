# FAISAL M91 Provider-Gated Research Notes

**Date:** 2026-08-16

## Local inspection

The sandbox is a fully virtualized x86_64 environment. No physical TPM, TEE, HSM, KMS, accelerator, or provider credential was exposed through the inspected device nodes or environment. The existing FAISAL M79 evidence explicitly records provider-neutral accelerator validation with `provider_state: unsupported` and `no_hardware_claim: true`.

This means M91 must not fabricate a hardware-backed key or attestation result. The available evidence supports only a provider-gated design review and an explicit unsupported runtime outcome until a real provider or device is identified.

## Authoritative Linux documentation

The current Linux kernel documentation identifies Trusted Keys and Encrypted Keys as kernel keyring key types. Trusted Keys use a trust source, and the documentation distinguishes a userspace-visible encrypted key blob from key material used internally. It lists TPM, TEE, CAAM, DCP, and platform-specific sources as distinct trust-source options and warns that the consumer must assess whether a trust source is sufficiently safe for its threat environment. [1]

The Linux TEE driver documentation states that a Trusted Application is represented on the TEE bus by a UUID, client drivers register supported UUIDs, and matched client drivers communicate with the Trusted Application through the TEE client API. It also states that device enumeration is specific to the underlying TEE implementation. Therefore a generic FAISAL claim of TEE-backed key provisioning would be unsupported without an identified TEE implementation, UUID, driver path, and runtime evidence. [2]

## M91 design conclusion

M90’s userspace provider boundary is the correct fallback for the current environment. M91 should add no fake hardware path. A supported implementation requires an identified provider, public-key provisioning evidence, attestation evidence, rotation and revocation behavior, secret-isolation evidence, and QEMU or hardware regression coverage. In the absence of those prerequisites, M91 acceptance must be `UNSUPPORTED_PROVIDER` rather than `PASS`.

## References

[1]: https://docs.kernel.org/security/keys/trusted-encrypted.html — Linux Kernel, “Trusted and Encrypted Keys,” current v7.2.0-rc7 documentation.
[2]: https://docs.kernel.org/driver-api/tee.html — Linux Kernel, “TEE (Trusted Execution Environment) driver API.”
[3]: `tools/faisal-build/evidence/m79-accelerator-validation.json` — FAISAL provider-neutral unsupported-hardware evidence.
[4]: `tools/faisal-build/evidence/m90-key-provider-validation.json` — FAISAL M90 userspace key-provider boundary and non-claims.
