# FAISAL M90: Production Key-Provider Contract Design

**Status:** Bounded userspace/provider contract validated in QEMU

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 remains unchanged.

## Purpose

M87 introduced signed, content-addressed repair bundles and correctly separated signature verification, attestation health, provider availability, independent approvals, canary execution, and rollback. Its validation fixture generated an Ed25519 key in the selftest and copied the corresponding public key into the M87 service. That is suitable for deterministic testing but is not a production key-lifecycle contract.

M90 adds a small userspace key-provider boundary. The provider owns `EVP_PKEY` private-key objects, derives a stable SHA-256 key identifier from the raw Ed25519 public key, assigns a monotonic generation, supports bounded rotation and revocation, signs only with the current active non-revoked key, and binds only public key bytes plus identity metadata to the M87 verifier. The kernel does not receive a private key, and the provider does not grant repair authority.

## State model

| State or operation | Provider behavior | M87 effect |
| --- | --- | --- |
| Provision | Retain a referenced private key, derive key ID, assign generation, mark active | No service authority is changed until explicit bind |
| Bind | Copy only the active key’s raw public bytes, key ID, and generation | Require key metadata for bundle verification and invalidate stale verified state |
| Rotate | Add a new active key with a higher generation and retire prior active keys | A subsequent bind selects the new public key and generation |
| Revoke retired key | Mark the key revoked and release its private key | Current binding remains valid if it refers to another active key |
| Revoke bound key | Mark revoked, release private key, and invalidate the bound service | M87 verification fails closed and provider signing returns `M90_ERR_REVOKED` |
| Unbind | Clear public key and identity metadata and invalidate verified state | A provider-required service cannot verify a bundle without a fresh bind |

The provider retains at most `M90_MAX_KEYS` slots. This is a bounded validation control plane, not a general-purpose secret database. Production deployment still requires a separately reviewed HSM, TPM, KMS, or equivalent provider implementation.

## Signed-data binding

M90 extends the M87 bundle digest input with `signing_key_id` and `key_generation`. Therefore a rotated key cannot validate a bundle signed for an earlier generation, even if the payload, attestation digest, signal sequence, approvals, and resource policy are otherwise identical. A service bound through M90 sets `trusted_key_required`; verification then rejects absent or mismatched identity metadata before signature acceptance.

The existing metadata-free M87 selftest remains compatible as a legacy fixture because it does not set `trusted_key_required`. M90 production-bound services are not allowed to use that compatibility path: bind and unbind both set the requirement bit, and revocation clears the key material and generation.

## Authorization boundary

> A valid signature proves possession of a provisioned signing key; it does not itself authorize deployment.

M87 continues to require healthy attestation, signal binding, provider availability, bundle and payload digests, supervisor approval, operator approval, integrity measurement, and canary requirement. M90 does not create, infer, or bypass any of those approvals. Model output is not read by the provider and cannot become kernel authority.

## Synchronization and lifetime

The M90 fixture is intentionally single-threaded at the provider API boundary. It stores one optional bound-service pointer and requires an explicit unbind before service destruction. Revoking the currently bound key invalidates that service immediately; a production provider would need a stronger lifetime mechanism, such as reference-counted registration or a service-owned revocation callback, before supporting concurrent service destruction and revocation.

## Testing

The executable selftest covers duplicate provisioning rejection, public-key identity binding, monotonic generation, signed verification before rotation, stale-key isolation after rotation, independent approval denial, retired-key revocation isolation, automatic invalidation of a bound service after active-key revocation, post-revocation signing denial, and cleanup. The M90 QEMU harness runs the test against a recovered FAISAL kernel and also retains an M87 regression run after the digest-contract change.

## Limitations

M90 does not provide hardware-backed secret storage, secure-boot provisioning, remote attestation, encrypted persistent key storage, formal verification of key lifecycle invariants, distributed quorum approval, or production readiness. The implementation is a bounded userspace contract designed to make the trust boundary explicit and testable before a hardware-backed provider is selected.

## References

[1]: `tools/faisal-runtime-verification/faisal_runtime_verification.h` — M87 bundle and verification structures.
[2]: `tools/faisal-runtime-verification/faisal_runtime_verification.c` — M87 digest and approval verification path.
[3]: `tools/faisal-key-provider/faisal_key_provider.h` — M90 provider API and bounded state.
[4]: `tools/faisal-key-provider/faisal_key_provider.c` — M90 provisioning, rotation, revocation, and binding implementation.
[5]: `tools/testing/selftests/agi_key_provider_test.c` — executable M90 contract test.
[6]: `tools/faisal-build/evidence/m90-key-provider-validation.json` — machine-readable evidence.
