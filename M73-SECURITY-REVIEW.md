# FAISAL M73 Security Review

## Security scope

M73 is a bounded userspace world-state service above FAISAL ABI 37. It consumes kernel-managed event and temporal interfaces and stores content through the M71 persistent-memory service. The review covers the trust boundary between model/runtime output, the M73 service, the FAISAL lifecycle device, and durable state.

## Threat model

The service assumes that observations, model-produced values, browser data, network data, and external sources may be incorrect or hostile. A model response is untrusted input. A malicious or compromised userspace caller may attempt to forge event order, bypass freshness, overwrite a conflicting fact, reuse a stale capability, submit malformed UAPI structures, or cause unbounded memory/journal growth.

| Threat | M73 control | Residual risk |
|---|---|---|
| Model or tool output mutates state without authority | World updates occur through the service and M71/FAISAL capability checks; model output is not passed as kernel authority | A trusted supervisor must still validate application-level policy |
| Forged event order | Kernel sequence is authoritative; service records loss/non-contiguous state and does not synthesize transitions | A full event-consumer replay/resync implementation remains a future expansion |
| Stale observation used as current truth | Deadline expiry marks the record `STALE` while retaining it for revalidation; authoritative callers must reject stale state | Callers must honor the state field and not treat storage as truth |
| Silent conflict winner | Different digests retain separate durable records and provenance; only explicit resolution creates a new generation | Resolution policy remains outside the kernel and must be supervised |
| Stale temporal capability reuse | Temporal query with a modified capability is rejected in QEMU with `EACCES` | Capability secrecy and lifecycle remain dependent on the kernel session boundary |
| Malformed UAPI input | Selftest submits 64 invalid-size world-sync, temporal, and resource-snapshot requests and requires `EINVAL` | Broader fuzzing across all ABI fields is future work |
| Invalid confidence or oversized keys | Service rejects confidence above the ABI limit and bounds entity/property/value lengths | Static maximums limit capacity by design |
| Journal exhaustion or memory exhaustion | M73 uses fixed-size fact and key buffers and M71 bounded records | Capacity exhaustion is an explicit error, not an automatic eviction policy |
| Resource snapshot overclaim | Measured, unavailable, and unsupported masks are returned separately and reported without interpretation as semantic truth | Hardware-specific accelerator measurements remain provider-gated |

## Authority and provenance

The world-state service is an indexer and persistence coordinator, not an authority issuer. A fact contains a kernel event sequence, observation-time/freshness data, provenance sequence, M71 record ID, M71 authority capability, confidence, and generation. The kernel session identity is used as the world-sync consumer ID for acknowledgements. Persistent content is digested with the OpenSSL EVP SHA-256 interface before insertion into M71.

The service does not fabricate missing transitions. If the kernel reports dropped events, a loss sequence, or an observed non-contiguous range, `resync_required` is retained. Recovery must obtain a fresh source snapshot or explicit source update before derived state is trusted again. The current M73 selftest validates the bounded sequence guard and UAPI rejection paths; an induced ring-overflow resynchronization test is not claimed because the current harness does not provide an independent event producer.

## Conflict handling

Conflict detection occurs when a second digest is observed for the same entity/property. The earlier and newer records remain in the bounded index and durable journal. No automatic winner is selected. `fws_resolve_conflict()` requires an explicit higher-level caller choice and records another durable generation with its own provenance and capability. Resolved historical records are retained for audit and are not deleted.

## Action boundary

M73 never turns a world-state record, confidence value, temporal state, memory capability, or model response into a filesystem, network, browser, process, device, or privileged action grant. Any future action must pass its own FAISAL capability, security policy, trusted-supervisor, and operator approval gates. The service reports state; it does not authorize behavior.

## Review conclusion

The M73 implementation meets the demonstrated security gates for capability-scoped session use, provenance-linked durable records, stale-capability rejection, bounded inputs, explicit conflict handling, and honest resource-mask reporting. It is not a complete semantic verification system, does not make external observations true, and does not remove the need for independent policy review before production deployment.
