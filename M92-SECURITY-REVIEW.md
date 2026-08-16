# FAISAL M92 Security Review: Key-Provider Hardening

**Review status:** Passed bounded source review, strict build, QEMU, ASan/UBSan, and TSan validation.

## Security objective

M92 reduces the risk that malformed provider inputs, concurrent key lifecycle operations, or service cleanup can corrupt the M90 userspace trust boundary. The provider retains private `EVP_PKEY` objects only in userspace and protects its bounded state with a mutex. It does not create authority, hardware trust, or model-driven approvals.

## Threat analysis

| Threat | Defense | Result |
| --- | --- | --- |
| Null key, ID, data, or signature pointer | Public APIs validate arguments before use | Passed 261 malformed cases |
| Unknown or fuzzed key identity | Lookup returns `M90_ERR_NOT_FOUND` | Passed 256 deterministic IDs |
| Concurrent sign/rotate/revoke | Provider mutex serializes slot and active-key state | Passed TSan run |
| Revocation during signing | Signer accepts only success or explicit revoked-state denial | Passed concurrent stress |
| Revocation during binding | Binder accepts success or explicit no-active-key denial | Passed concurrent stress |
| Provider close with bound service | Internal lock-assuming unbind clears service metadata before key cleanup | Passed lifetime test |
| Recursive lock in revoke/close | Internal unbind helper avoids calling the public locking API under lock | Reviewed and exercised |
| Private-key disclosure to M87/kernel | Binding exports only public key, identity, and generation | Preserved from M90 |
| Hardware trust fabrication | M91 provider gate remains separate and unsupported in this environment | Preserved and regressed |

## Corrected and expected concurrency behavior

The initial stress run failed because the revocation worker can legitimately remove the current active key while signer workers are executing. That is an expected state transition, not a memory-safety failure. The selftest was corrected to accept `M90_ERR_REVOKED` for a sign that races with revocation while continuing to fail on all unexpected errors. It still requires successful rotations, successful or not-found revocation outcomes, nonzero successful signing coverage, and clean service lifetime invalidation.

## Sanitizer evidence

The strict host run passed 512 successful sign operations, three rotations, and 256 revocation attempts. The normal QEMU run passed all required markers. ASan plus UBSan passed without sanitizer diagnostics, and TSan passed without data-race diagnostics. Three additional QEMU smokes passed with zero diagnostic matches. M90 and M91 regression harnesses passed after the provider mutex changes.

These runs are schedule samples, not a proof of race freedom or formal correctness. They do not cover process crashes, arbitrary multi-service registration, key persistence, hardware-backed secrets, or hostile OpenSSL provider implementations.

## Residual risks

The provider still tracks one bound service pointer and assumes explicit unbind or provider close before service destruction. A production multi-service provider requires reference-counted service registrations or an equivalent lifetime protocol. Private keys remain exposed to a compromised provider process because M92 is userspace-only. The M91 hardware gate remains intentionally unsupported until a real provider is identified and verified.

## References

[1]: `tools/faisal-key-provider/faisal_key_provider.c` — mutex and lifetime implementation.
[2]: `tools/testing/selftests/agi_key_provider_hardening_test.c` — malformed and concurrency coverage.
[3]: `tools/faisal-build/evidence/m92-asan-ubsan-run.log` — memory and undefined-behavior sanitizer result.
[4]: `tools/faisal-build/evidence/m92-tsan-run.log` — race-detector result.
[5]: `tools/faisal-build/evidence/m90-after-m92-qemu.log` — M90 regression.
[6]: `tools/faisal-build/evidence/m91-after-m92-qemu.log` — M91 regression.
