# FAISAL M92: Key-Provider Fuzz, Concurrency, and Lifetime Hardening

**Status:** Bounded userspace hardening validated

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37

## Purpose

M90 established userspace key provisioning, rotation, revocation, and provider-bound signed-bundle verification. M92 hardens that provider against malformed arguments and concurrent callers without moving private keys into the kernel or changing M91’s explicit unsupported hardware-provider result.

The provider now protects its bounded key-slot array, active-key selection, private-key ownership, bound-service pointer, and generation state with a `pthread_mutex_t`. Public operations reject uninitialized providers and malformed pointers before entering the critical section. Internal helpers are used when the caller already holds the mutex, avoiding recursive locking during active-key revocation and provider cleanup.

## Concurrent workload

| Worker | Operation | Acceptance behavior |
| --- | --- | --- |
| Four signer workers | Sign bounded 32-byte messages | Success is counted; transient `M90_ERR_REVOKED` is expected during revocation |
| One rotation worker | Rotate through three additional Ed25519 keys | Exactly three successful rotations required |
| One revocation worker | Revoke fuzzed/retired key IDs repeatedly | `M90_OK` and `M90_ERR_NOT_FOUND` are valid outcomes |
| One binding worker | Bind and unbind the M87 service repeatedly | Success or expected no-active-key denial is valid |
| Main thread | Barrier release and final provider close | Service metadata must be cleared on cleanup |

A barrier starts all seven workers together. The provider never exposes a private key to M87; only the existing M90 public-key binding fields are updated under the provider lock.

## Malformed-input contract

The selftest exercises null key IDs, null keys, null signature buffers, nonzero-size null data, random unknown key IDs, and 256 deterministic malformed/unknown key identifiers. The expected errors are explicit argument, key, or not-found errors. No malformed input is converted to a provider success result.

## Lifetime behavior

`m90_provider_close()` acquires the provider lock, unbinds any tracked service through a lock-assuming internal helper, frees each retained `EVP_PKEY`, marks the provider uninitialized, destroys the mutex, and clears the provider structure. The selftest binds a service, closes the provider, and verifies that the service’s public key size, generation, and trust metadata are cleared.

The provider still tracks one bound service pointer and is not a multi-service registry. Supporting arbitrary concurrent service destruction, multiple bound services, or process-crash recovery requires a larger lifetime design and is outside M92.

## Preserved boundaries

M92 does not add hardware-backed key storage, TPM or TEE integration, remote attestation, or secure boot. M91 remains the source of truth for hardware-provider availability and must report `UNSUPPORTED` or `UNVERIFIED` when evidence is absent. Model output remains data and never becomes provider or repair authorization.

## References

[1]: `tools/faisal-key-provider/faisal_key_provider.h` — mutex-protected provider state.
[2]: `tools/faisal-key-provider/faisal_key_provider.c` — locked operations and lifetime helpers.
[3]: `tools/testing/selftests/agi_key_provider_hardening_test.c` — malformed and concurrent workload.
[4]: `tools/faisal-build/evidence/m92-key-provider-hardening-validation.json` — machine-readable evidence.
[5]: `M91-PROVIDER-GATE-DESIGN.md` — retained unsupported hardware boundary.
