# FAISAL M88 Runtime Verification Signal Bridge Design

**Status:** Validated in the bounded QEMU test environment

**Kernel base:** Linux v7.2-rc7

**UAPI ABI:** 37; additive constants only

## Purpose

M88 connects Linux Runtime Verification (RV) monitor violations to the existing FAISAL lifecycle verification-event channel. The bridge provides a kernel-originated, provenance-bearing observation that trusted userspace supervision can consume. It does not turn an RV observation into a repair authorization, capability grant, reactor selection, or model command.

The design preserves the architectural boundary that model inference, reasoning, semantic memory, browser logic, and repair policy remain in userspace. The kernel supplies an authenticated observation source and enforces lifecycle-session event filtering.

## Data path

The upstream RV reactor path is extended in `kernel/trace/rv/rv_reactors.c`. When `rv_react()` processes a monitor violation and `CONFIG_AGI_LIFECYCLE_RV_BRIDGE` is enabled, it calls `agi_lc_rv_report(monitor->name, -EIO)`. The bridge implementation resides in `drivers/misc/agi_lifecycle.c`; its kernel-only declaration is in `include/linux/agi_lifecycle_rv.h`.

`agi_lc_rv_report()` computes a deterministic FNV-1a hash of the monitor name, retains the low 16 bits for compact provenance, increments a global 64-bit sequence counter, and encodes the bridge tag, monitor hash, and sequence into the existing verification-record metadata field. It then broadcasts an `AGI_LC_EVENT_VERIFY` record with `AGI_LC_VERIFY_FLAG_RV_OBSERVATION` to registered lifecycle sessions. The event is delivered only when the receiving session's existing event mask includes the verification event bit.

| Field | M88 meaning |
| --- | --- |
| `record.type` | `AGI_LC_EVENT_VERIFY` |
| `record.flags` | `AGI_LC_VERIFY_FLAG_RV_OBSERVATION` |
| `record.status` | Source status; the bridge uses `-EIO` for an RV violation observation |
| `record.correlation` | Bridge sequence value |
| `record.metadata` | `AGI_LC_RV_METADATA_TAG`, monitor hash, and low sequence bits |
| `record.session_id` | Lifecycle session identity assigned by the existing driver |

For the deterministic `stall` fixture, the expected low-16-bit FNV-1a monitor hash is `0x9679`, and the canonical QEMU run delivered metadata with the RV tag and that monitor provenance.

## Synchronization and lifetime

Sessions register in `open()` and deregister in `release()` on a dedicated `agi_lc_rv_sessions` list protected by `agi_lc_rv_sessions_lock`. The report path holds this spinlock while walking the session registry and invokes the existing event-queue delivery path for each subscribed session. The registry lock is separate from the lifecycle queue lock to avoid introducing a new nested lock dependency between RV fan-out and per-session record management.

The report path does not retain session pointers after the registry lock is released. Session removal is performed under the same registry lock, so release-time lifetime is serialized with bridge delivery. The existing per-session event mask remains the authorization boundary for delivery.

## Configuration and compatibility

The bridge is controlled by `CONFIG_AGI_LIFECYCLE_RV_BRIDGE`, which requires the FAISAL lifecycle driver and the upstream RV reactor framework. The UAPI additions are constants and masks only; ABI version 37 is unchanged. Existing lifecycle records, ioctls, and event consumers remain compatible.

`rv_react()` is exported through `EXPORT_SYMBOL_GPL` only when `CONFIG_AGI_LIFECYCLE_RV_BRIDGE_TEST` is enabled. This second symbol is validation-kernel-only and exists solely for the deterministic fixture module. Production configurations should leave the test hook disabled. The bridge itself does not require exporting `rv_react()`.

## Validation fixture boundary

`tools/faisal-rv/faisal_rv_bridge_fixture.c` is a test-only loadable module. It constructs a minimal synthetic monitor named `stall` and invokes the same exported `rv_react()` path used by upstream monitor violations. It is not an upstream monitor, not a production reactor, and not evidence that a physical workload generated a scheduler stall. Its purpose is deterministic validation of callback plumbing, metadata encoding, event delivery, and capability filtering in QEMU.

The harness separately confirms that the upstream `stall` monitor is available, enabled, monitoring, and reacting. The fixture is loaded only after the selftest has configured both lifecycle sessions, using an explicit `/tmp/m88-subscribed` readiness marker rather than a timing-sensitive sleep.

## Failure behavior

If no lifecycle session subscribes to verification events, the bridge performs no userspace delivery. If a session is unsubscribed, it must not receive the observation. If metadata validation fails, the selftest exits nonzero. The bridge does not attempt recovery, patching, or reactor mutation. Higher-level attested repair supervision may treat the event as one input to policy, but kernel capability checks and independent supervisor/operator approvals remain mandatory.

## Alternatives considered

A userspace-only trace reader would lose the direct kernel-to-lifecycle provenance boundary and would require a separate race-prone correlation mechanism. A new syscall or new event ABI would unnecessarily expand the stable interface because the existing verification record already carries status, correlation, metadata, session identity, and event-mask filtering. A global queue lock for RV sessions would increase lock nesting risk; the dedicated registry lock avoids coupling the new registry lifetime to unrelated queue operations.

## Limitations and future work

M88 validates the bridge contract and its deterministic fixture path in QEMU. It does not claim hardware accelerator integration, physical scheduler-stall reproduction, or automatic repair. Future work may add additional upstream RV monitors and source-specific status mappings, but each source must preserve the observation-only boundary, capability filtering, provenance, and independent repair authorization gates.

## References

[1]: `kernel/trace/rv/rv_reactors.c` — upstream RV reactor integration point and M88 bridge hook.
[2]: `drivers/misc/agi_lifecycle.c` — lifecycle session registry and RV observation delivery.
[3]: `include/uapi/linux/agi_lifecycle.h` — additive M88 observation flags and metadata masks.
[4]: `tools/testing/selftests/agi_rv_signal_bridge_test.c` — executable provenance and isolation assertions.
[5]: `tools/faisal-build/run_rv_signal_bridge_qemu.sh` — bounded QEMU validation harness.
