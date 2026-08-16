# FAISAL M93 Security Review: Multi-Service Provider Lifetime

**Review status:** Passed targeted source review, strict build, QEMU, ASan/UBSan, TSan, three final smoke runs, and M90/M91 regressions.

## Security objective

M93 reduces lifetime and revocation risks created when a userspace key provider serves multiple M87 runtime-verification services. The provider now owns a bounded registration table, invalidates every registered service before provider key cleanup, broadcasts active-key revocation to matching services, and exercises concurrent registration and removal under the M92 mutex discipline.

The design does not expand authority. Private Ed25519 keys remain inside the userspace provider. Service bindings contain public material and metadata only. Model output is not consulted by the provider, and M91’s explicit unsupported hardware/provider result remains unchanged.

## Threat analysis

| Threat | Defense | Result |
| --- | --- | --- |
| A ninth service causes unbounded state growth | Fixed eight-entry table rejects further registration with `M90_ERR_CAPACITY` | Passed `M93_SERVICE_CAPACITY_DENIAL_OK capacity=8` in QEMU and host sanitizers |
| Duplicate registration creates duplicate revocation targets | Registration searches for the service pointer while holding the mutex and returns success without adding a second entry | Covered by the registration API and concurrent workers |
| Unregister compaction skips or duplicates an entry | The lock-held compaction loop shifts each later slot toward the removed index, nulls the final slot, and decrements `service_count` | Passed sequential unregister, provider-close cleanup, and TSan stress |
| Revocation leaves a matching service trusted | Revocation marks the key revoked and clears every registered service with the matching key ID before freeing the private key | Passed eight-service broadcast marker |
| Revocation clears a service bound to another key | Broadcast compares the service’s key ID with the revoked identity rather than clearing all services indiscriminately | Preserved M90 key-identity semantics; M90 regression passed |
| Provider close leaves stale binding metadata | Close clears all registered services and the table before freeing keys and destroying the mutex | Passed `M93_PROVIDER_CLOSE_CLEANUP_OK` |
| Service close races with provider access | The supported protocol requires unregister or provider close before object destruction; QEMU uses explicit unregister-before-`m87_close` | Passed `M93_SAFE_SERVICE_CLOSE_OK`; arbitrary unsynchronized destruction remains outside scope |
| Concurrent table operations race | Public register, bind, unbind, unregister, revoke, and close operations serialize through one provider mutex; workers use separate service objects | Eight workers × 64 iterations passed TSan without race diagnostics |
| Provider process restart is mistaken for transparent crash recovery | The selftest creates a fresh provider and explicitly re-registers surviving service objects; the marker states non-claiming of process-crash recovery | Controlled restart passed; transparent crash recovery is not claimed |
| Private signing key is exposed to a service or kernel | Binding exports only public key bytes, key ID, generation, and required-state metadata | Preserved from M90 and verified by M90 regression |
| Unsupported environment metadata fabricates hardware trust | M91 provider gate is not modified and still reports `provider=none status=1` with explicit unsupported status | M91 regression passed |
| Host sanitizer fixture hides an actual service bug | Host mode is explicit, limited to zeroed in-memory service structs, and real `/dev/agi_lifecycle` integration remains QEMU-tested | ASan/UBSan with leak detection and TSan passed; fixture limitation documented |

## Corrected sanitizer finding

The first M93 ASan/UBSan attempt aborted before entering the service assertions because the host process attempted `m87_open()` against a lifecycle device that exists only in the FAISAL QEMU environment. The resulting early failure path also produced OpenSSL provider allocations in leak reporting. This was not treated as a pass and was preserved as diagnostic history outside the final evidence set.

The selftest now uses an explicit `FAISAL_M93_HOST_MODE=1` fixture for host sanitizer runs. That mode initializes service structs in memory and never claims kernel-device coverage. The final run used `detect_leaks=1` and completed all M93 markers without AddressSanitizer, LeakSanitizer, UBSan, or runtime-error diagnostics. QEMU separately exercised the real M87 open/close path.

## Authority and isolation review

M93 cannot authorize a repair, deployment, browser action, model action, or privileged kernel operation. The provider only verifies and exposes public signing metadata to the already existing M87 service contract. Hardware-backed trust is explicitly unavailable in the current environment, and provider metadata remains non-authoritative under M91.

The provider’s mutex protects its own state but cannot protect a service object after the owner violates the documented unregister-before-destruction protocol. The implementation intentionally does not free caller-owned service memory, and no pointer quarantine or reference-counting protocol is claimed.

## Residual risks and limitations

M93 provides a bounded userspace lifetime contract, not a general object-lifetime system. It does not prove race freedom, formal correctness, memory safety under arbitrary hostile OpenSSL providers, durable key recovery, transparent process-crash recovery, hardware-backed secrets, TPM/TEE/HSM integration, remote attestation, secure boot, or production readiness. A future production service manager should add explicit ownership transfer, reference counting or generation-based reclamation, and supervisor-mediated recovery before allowing untrusted service processes to disappear without unregistering.

## References

[1]: `tools/faisal-key-provider/faisal_key_provider.c` — registration, compaction, revocation, and close implementation.
[2]: `tools/faisal-key-provider/faisal_key_provider.h` — bounded state and API contract.
[3]: `tools/testing/selftests/agi_key_provider_multiservice_test.c` — capacity, broadcast, restart, and concurrent stress coverage.
[4]: `tools/faisal-build/evidence/m93-asan-ubsan-final.log` — final memory and undefined-behavior sanitizer result.
[5]: `tools/faisal-build/evidence/m93-tsan-final.log` — final race-detector result.
[6]: `tools/faisal-build/evidence/m93-multiservice-qemu.log` — final real-device QEMU validation.
[7]: `tools/faisal-build/evidence/m90-after-m93-qemu.log` — M90 regression.
[8]: `tools/faisal-build/evidence/m91-after-m93-qemu.log` — M91 unsupported-provider regression.
