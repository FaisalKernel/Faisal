# FAISAL M73 — Temporal World-State Service

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Userspace world-state indexing over FAISAL world synchronization, temporal records, resource snapshots, selective subscriptions, provenance-linked M71 persistent memory, freshness handling, and explicit conflict resolution.

## Implementation

M73 adds `tools/faisal-world/faisal_world_state_service.c` and its header. The service opens the M71 persistent-memory service, registers the memory-role session, subscribes to selected FAISAL event classes, configures a bounded world-event subscription, and queries/acknowledges the kernel world-sync sequence. Kernel sequence is treated as the authoritative ordering signal; userspace monotonic time is used only for freshness deadlines.

World facts are bounded by entity and property keys. Values are SHA-256 digested with OpenSSL EVP and persisted through the M71 memory service. The in-memory index retains the memory record ID, capability, provenance sequence, generation, confidence, event sequence, and freshness/conflict state. A repeated identical observation is deduplicated. A different digest for the same entity/property retains the prior and new records and marks the key as conflicted. An explicit higher-level resolution records a new durable generation and marks prior generations resolved; it does not grant an action capability.

M73 creates and checks a kernel temporal record against a current world sequence. It also requests a resource snapshot and preserves the kernel distinction between measured, unavailable, and unsupported fields. The service rejects stale temporal capabilities and malformed UAPI requests in the selftest. The M71 session identity exposure is required so world-sync acknowledgements use the correct consumer ID.

## Validation

The static service/selftest build passed with `-O2 -Wall -Wextra -Werror -Wno-cpp` and static OpenSSL linkage. The FAISAL kernel `bzImage` and modules rebuilt successfully in 38 seconds on the sandbox build host. The two-vCPU QEMU harness passed the boot marker, all M73 functional and negative-path markers, selftest exit marker, and harness result marker. Five repeated QEMU smoke runs completed successfully; wall times ranged from 5.0399 to 5.2388 seconds. These times include QEMU boot and harness overhead and are not an AGI workload-performance benchmark.

```text
FAISAL_M73_BOOT_OK
M73_MALFORMED_UAPI_REJECT_OK iterations=64
M73_WORLD_QUERY_OK newest=1 generation=2
M73_WORLD_ACK_OK sequence=1
M73_SEQUENCE_GUARD_OK
M73_BOUNDED_INPUT_REJECT_OK
M73_FRESH_LOOKUP_OK generation=1
M73_FRESHNESS_EXPIRY_OK
M73_CONFLICT_DETECTED_OK retained=2
M73_CONFLICT_RESOLUTION_OK generation=3 retained=3
M73_TEMPORAL_CHECK_OK record=1 generation=2
M73_STALE_TEMPORAL_REJECT_OK
M73_RESOURCE_SNAPSHOT_OK measured=0xa3 unavailable=0x5c unsupported=0x0
M73_WORLD_STATE_SYNC_OK
M73_SELFTEST_EXIT=0
FAISAL_M73_TEST_RC=0
```

The required regression harnesses for M64 and M66–M72 also passed. No kernel panic, `BUG`, `Oops`, or M73 selftest failure marker was observed in the captured validation logs. The current evidence is an operational smoke validation, not a comparison against upstream Linux performance or a semantic-quality evaluation.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Event ordering and acknowledgement | Pass | World query, monotonic sequence guard, stale-ack rejection, and final sync markers |
| Loss policy | Implemented | Query records kernel loss/non-contiguous conditions as `resync_required`; no fabricated transitions are emitted |
| Freshness | Pass | Expired record remains queryable and is marked `STALE` |
| Conflict | Pass | Two generations are retained; explicit resolution creates generation 3 |
| Self-state | Pass | Snapshot reports measured and unavailable masks separately |
| Temporal | Pass | Kernel record is created and checked against the current sequence; stale capability is rejected |
| Security boundary | Pass | Malformed requests, invalid confidence, and stale acknowledgement/capability paths are rejected |
| Build and boot | Pass | Kernel build and QEMU boot markers |
| Regression | Pass | M64 and M66–M72 harnesses |

## Explicit non-claims

M73 provides measurable operational state representation and synchronization primitives. It does **not** prove human-like awareness, consciousness, semantic truth, complete world coverage, causal inference, automatic conflict resolution, model retraining, general intelligence, or permission to act. A retained memory record is not retraining. A resource measurement is not semantic truth. A temporal record orders and constrains observations; it does not make a fact true. Model output never equals kernel authorization, and production deployment still requires an independent trusted supervisor and operator approvals.

## Evidence

The design contract is in `M73-WORLD-STATE-DESIGN.md`; the security review is in `M73-SECURITY-REVIEW.md`; benchmark limits and smoke data are in `M73-BENCHMARKS.md`; machine-readable evidence is in `tools/faisal-build/evidence/m73-world-state-validation.json`; and raw M73 and regression logs are in `tools/faisal-build/evidence/`.
