# FAISAL M90 Security Review: Userspace Key Provider

**Review status:** Passed bounded source review and executable QEMU validation; production provider remains out of scope.

## Security objective

M90 addresses the lifecycle gap between M87’s signed repair-bundle verifier and a production key-management boundary. The primary threat is not an invalid signature; it is misuse of a valid key, stale trust after rotation, failure to revoke a compromised key, or accidental movement of private key material into the kernel or model runtime.

## Trust boundaries

| Boundary | Trusted input | Required protection | M90 result |
| --- | --- | --- | --- |
| Provider to M87 | Public key bytes, key ID, generation | Never transfer private key material | Enforced by bind API |
| Bundle to verifier | Digest, signature, key identity, policy fields | Bind all signed fields and reject mismatches | Enforced by M87 digest and verification path |
| Provider to signer | Bundle digest | Sign only with active non-revoked key | Enforced by `m90_provider_sign_active()` |
| Rotation to service | New public identity and generation | Invalidate stale verified state | Enforced during bind |
| Revocation to service | Revoked key ID | Clear bound key metadata immediately | Enforced for the tracked bound service |
| Model/runtime to authority | No trusted authority | Require independent policy and operator approvals | Preserved from M87 |

## Findings and corrections

An initial M90 QEMU attempt exposed a state-machine issue in the test rather than a security bypass: M87 requires a service to be in `M87_STATE_SIGNAL_BOUND` before accepting a fresh bundle. The test now explicitly rebinds the active rotated provider key before constructing the independent-approval denial case. This makes the state transition visible and keeps the verifier contract strict.

A second test-order issue was corrected by checking stale old-key rejection before verifying the new bundle, because a successful M87 verification transitions the service to `M87_STATE_BUNDLE_VERIFIED`. No diagnostic was suppressed and no verifier check was weakened.

## Threat analysis

### Private-key disclosure

The provider stores private `EVP_PKEY` references only in userspace. The M87 service receives a 32-byte raw public key, a 32-byte derived key ID, and a generation. The repository contains no kernel modification for M90 and no private key is written to a file by the provider. The QEMU fixture generates ephemeral test keys in memory.

This is not equivalent to hardware-backed secret protection. A compromised provider process can expose its own private key; M90 therefore records the boundary but does not claim HSM, TPM, KMS, secure-boot, or remote-attestation security.

### Stale-key acceptance

The key ID and generation are included in the bundle digest. After rotation, a bundle signed for the old identity fails key-binding verification even if its payload and attestation data remain valid. The selftest records `M90_OLD_KEY_ISOLATION_OK`.

### Revocation failure

Revoking a retired key releases its private key without disturbing the currently bound new key. Revoking the currently bound key clears the service’s public key, key ID, and generation and resets stale verification state. Subsequent provider signing returns `M90_ERR_REVOKED`, and M87 verification returns `M87_ERR_SIGNATURE`. The selftest records `M90_REVOCATION_FAIL_CLOSED_OK`.

The implementation tracks one optional bound service pointer and requires explicit unbind before service destruction. A production concurrent provider must replace this bounded pointer with a lifetime-safe registration mechanism before allowing arbitrary concurrent service close and revocation.

### Approval bypass

The provider never sets supervisor, operator, integrity, or canary approvals. The M90 test mutates `operator_approved` to zero, recomputes and signs the altered bundle with the active key, and confirms M87 rejects it with `M87_ERR_APPROVAL`. A valid provider signature therefore cannot substitute for independent authorization.

### Algorithm and identity confusion

The provider accepts Ed25519 `EVP_PKEY` objects and derives the ID from the raw 32-byte public key. The test does not claim algorithm agility or cryptographic agility. A future provider must version the key identity domain and reject unsupported algorithms rather than silently interpreting a different key type as Ed25519.

## Review gates

The added and modified M90 lines were scanned for process execution, privilege changes, model-authority markers, raw user-copy operations, and livepatch behavior. The scan found zero matches across 972 scanned lines. `git diff --check` passed. The M90 QEMU run, three smoke runs, and post-M90 M87 regression all passed with zero diagnostic matches.

## Residual risks

M90 does not provide encrypted persistent secret storage, hardware-backed key protection, remote key attestation, quorum approval, formal proof, multi-service concurrent revocation, or secure-boot integration. The provider’s private-key memory is subject to ordinary userspace compromise. These are explicit next-stage risks, not silently accepted production claims.

## References

[1]: `tools/faisal-key-provider/faisal_key_provider.c` — provider implementation.
[2]: `tools/faisal-runtime-verification/faisal_runtime_verification.c` — signed-bundle verification and approval gates.
[3]: `tools/testing/selftests/agi_key_provider_test.c` — executable attack and lifecycle checks.
[4]: `tools/faisal-build/evidence/m90-security-scan.txt` — targeted source scan.
[5]: `tools/faisal-build/evidence/m90-key-provider-qemu.log` — final QEMU proof.
