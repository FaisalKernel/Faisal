# FAISAL M93 Design: Multi-Service Key-Provider Lifetime

**Status:** Implemented and validated in the bounded userspace provider contract

**Foundation:** Linux `v7.2-rc7`; FAISAL ABI 37 unchanged

**Dependencies:** `FAISAL-M90` userspace Ed25519 key provider, `FAISAL-M91` explicit unsupported hardware/provider gate, and `FAISAL-M92` mutex-protected provider state

## Purpose

M93 replaces the M92 provider’s single tracked service pointer with a bounded multi-service registration contract. The provider can now serve up to eight independently registered M87 runtime-verification services. Registration, binding, unbinding, revocation, close, and restart are coordinated under the provider mutex. The implementation remains a userspace trust boundary: private signing keys stay in the provider process, while M87 services receive only public key material, key identity, generation, and invalidation state.

The feature addresses a concrete M92 limitation. A single pointer could not represent multiple concurrently active verification services, and a service could be closed safely only if the caller performed the correct explicit unbind sequence. M93 makes the set of registered service objects explicit and provides provider-side invalidation before key cleanup or provider destruction.

## Data model

| Object | M93 representation | Lifetime rule |
| --- | --- | --- |
| Provider key state | Existing bounded M90 key slots protected by `provider->lock` | Private `EVP_PKEY` references are freed during provider close or key revocation under the lock |
| Registered service set | `services[M93_MAX_SERVICES]`, with `M93_MAX_SERVICES == 8` and `service_count` | Entries are valid only while registered; unregister clears service metadata and compacts the table |
| Service binding | Public key bytes, key ID, generation, and `trusted_key_required` in the M87 service | Revocation or provider close clears the binding and moves a verified service back to the signal-bound state |
| Registration identity | Service object address, compared while the provider lock is held | A duplicate registration is idempotent; an unknown unregister is a no-op with a successful public return contract |

The table is deliberately bounded. A ninth registration is rejected with `M90_ERR_CAPACITY`, preventing unbounded provider memory growth and making the service fan-out cost explicit. M93 does not add a new kernel ABI or change any ioctl number.

## Synchronization and lifecycle

All public registration and binding operations acquire `provider->lock`. Internal helpers assume the lock is already held. This prevents the recursive-locking error class addressed by M92 while allowing revocation and provider close to invalidate all services atomically with respect to other provider operations.

The normal lifecycle is:

```text
m87_open
  → m90_provider_register_service
  → m90_provider_bind_service
  → service execution
  → m90_provider_unbind_service or m90_provider_revoke
  → m90_provider_unregister_service
  → m87_close
```

`m90_provider_bind_service()` auto-registers a service when capacity permits. `m90_provider_unbind_service()` clears its public binding but deliberately leaves registration present so a service can be rebound without changing table ownership. `m90_provider_unregister_service()` clears service metadata, removes the entry, shifts later entries one position toward the front, nulls the final slot, and decrements `service_count`.

Provider close performs the reverse safety boundary. It first clears every registered service, zeroes the registration table, and sets `service_count` to zero. Only then does it free private key references and destroy the provider mutex. This ordering ensures that no service retains provider-issued trust metadata after the provider has ceased to exist.

## Revocation broadcast

Revocation marks the matching key inactive and revoked, then iterates the current registration table. Any service whose `trusted_key_id` matches the revoked identity is cleared using the lock-assuming invalidation helper. The private key is freed only after all matching service metadata has been invalidated. A service registered with a different key is not modified by the broadcast.

The broadcast is intentionally identity-based rather than pointer-global. It supports active-key revocation across multiple services while preserving the M90 key-generation and fail-closed semantics. The service object remains userspace-owned; the provider does not free it and does not infer that a process crash has been repaired merely because a stale pointer was absent from the table.

## Controlled restart and crash boundary

The M93 selftest closes the first provider, verifies that all surviving service bindings are cleared, creates a fresh provider and key, and re-registers the surviving service objects. It then concurrently exercises registration, binding, unbinding, and unregistering with eight independent service objects for 64 iterations each.

The marker `M93_PROCESS_CRASH_RECOVERY_NONCLAIM_OK` records the boundary honestly. M93 validates controlled provider restart and non-claiming of process-crash recovery; it does not implement transparent recovery of an arbitrarily crashed provider process, durable key persistence, or automatic reclamation of a service object that was destroyed without unregistering. Such recovery requires an external supervisor and an ownership or reference protocol beyond this bounded userspace provider.

## Sanitizer execution boundary

The real M87 lifecycle is exercised in QEMU, where `/dev/agi_lifecycle` is available. Host ASan/UBSan and TSan runs use `FAISAL_M93_HOST_MODE=1` to initialize zeroed in-memory M87 service structures without opening a kernel lifecycle device. This is an explicit test fixture boundary, not a production mode and not a sanitizer diagnostic suppression. The initial host run failed before reaching the M93 assertions because it attempted to open a device unavailable outside QEMU and then triggered OpenSSL leak reporting during early failure cleanup. The selftest was corrected to make the host fixture explicit; the final sanitizer runs pass with leak detection enabled and without diagnostics.

## Compatibility and rollback

M93 preserves ABI 37, existing M90 public key-provider APIs, the M91 unsupported-provider result, and the M87 service structure. The new registration APIs are additive userspace interfaces. Rollback is a Git revert to `FAISAL-M92`, which restores the single-service provider implementation and its previously validated evidence. No kernel image or stable kernel ABI change is required for rollback.

## Verification references

[1]: `tools/faisal-key-provider/faisal_key_provider.h` — M93 bounded service-table declarations and additive APIs.
[2]: `tools/faisal-key-provider/faisal_key_provider.c` — locked registration, compaction, revocation broadcast, and provider-close invalidation.
[3]: `tools/testing/selftests/agi_key_provider_multiservice_test.c` — sequential, capacity, restart, and concurrent lifecycle tests.
[4]: `tools/faisal-build/run_key_provider_multiservice_qemu.sh` — reproducible QEMU harness and diagnostic gates.
[5]: `M92-KEY-PROVIDER-HARDENING-DESIGN.md` — preceding mutex and userspace key-ownership design.
[6]: `M91-PROVIDER-GATE-DESIGN.md` — preserved unsupported hardware/provider boundary.

## References

[1]: `tools/faisal-key-provider/faisal_key_provider.h`
[2]: `tools/faisal-key-provider/faisal_key_provider.c`
[3]: `tools/testing/selftests/agi_key_provider_multiservice_test.c`
[4]: `tools/faisal-build/run_key_provider_multiservice_qemu.sh`
[5]: `M92-KEY-PROVIDER-HARDENING-DESIGN.md`
[6]: `M91-PROVIDER-GATE-DESIGN.md`
