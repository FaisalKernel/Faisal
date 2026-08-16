# FAISAL M88 Security Review

**Status:** Reviewed and validated for the bounded QEMU configuration

**Scope:** Kernel RV-to-lifecycle observation bridge, validation fixture, selftest, and QEMU harness

## Security objective

M88 adds a kernel-originated observation path without allowing an RV signal, userspace model output, or fixture event to become authorization. The bridge reports that an upstream Runtime Verification reactor path observed a monitor violation. It does not grant capabilities, select reactors, approve repairs, mutate policy, or load a replacement kernel.

> Model output is never kernel authorization. Authorization continues to require kernel-enforced capabilities, process/session identity, security policy, and the independent trusted-supervisor and operator gates already validated by M87.

## Threat model

The relevant threats are a compromised or confused userspace supervisor, a malicious lifecycle client, a malformed or spoofed userspace record, a malicious loadable module in a validation kernel, event-subscription abuse, metadata forgery, and concurrency errors during session close. The bridge assumes the kernel and the upstream RV core are trusted computing base components; it does not attempt to make an untrusted kernel module trustworthy.

| Threat | M88 control | Evidence |
| --- | --- | --- |
| Unsubscribed client receives RV data | Existing per-session event-mask filtering | `M88_CAPABILITY_FILTER_OK unsubscribed=1` |
| Userspace fabricates a kernel RV source | Bridge is invoked from the kernel RV reactor path; UAPI constants identify observations but do not authorize actions | Canonical QEMU provenance record |
| Metadata collision or sequence ambiguity | Fixed RV tag, monitor hash field, and monotonic bridge sequence | `M88_RV_PROVENANCE_OK records=1 monitor_hash=0x9679` |
| Session use-after-free during report/release | Dedicated registry spinlock serializes list traversal and removal | Code review of `agi_lc_rv_sessions_lock`; QEMU lifecycle exercise |
| Test fixture exposed in production | `rv_react` export is gated by `CONFIG_AGI_LIFECYCLE_RV_BRIDGE_TEST` | M88 build config and Kconfig help text |
| Fixture mistaken for production monitor evidence | Fixture and harness explicitly document deterministic test-only scope | `M88-RV-BRIDGE-DESIGN.md` and source comments |
| Prompt injection becomes repair authority | No repair path exists in the bridge; existing M87 attestation and approval gates remain above it | M87 regression retained; M88 is observation-only |
| Kernel source introduces obvious process execution or model hooks | Added/modified lines scanned for process execution, privilege escalation, model-authority, and unsafe user-copy patterns | `tools/faisal-build/evidence/m88-security-scan.txt` |

## Code-review findings

The bridge uses a separate registry lock rather than nesting the existing lifecycle queue lock. Reports compute metadata before taking the registry lock and do not retain session references after the protected traversal. Registration occurs only after a successful lifecycle session open, and release removes the node under the same lock.

The RV observation flag is additive and is checked by the selftest together with the metadata tag, monitor hash, negative status, nonzero session identity, nonzero correlation, and sequence/correlation consistency. The unsubscribed session remains open during the stimulus and is polled after delivery, directly testing the capability-filtered event boundary.

The test hook is intentionally narrower than the production bridge. `EXPORT_SYMBOL_GPL(rv_react)` is compiled only for a validation kernel with `CONFIG_AGI_LIFECYCLE_RV_BRIDGE_TEST=y`; production configurations can enable the observation bridge while leaving the fixture export disabled. The fixture itself has no userspace input, no privilege-changing code, no process execution, and no repair action.

## Residual risks

The low 16-bit monitor hash is a compact provenance discriminator, not a cryptographic identity. Consumers must treat the RV tag, hash, sequence, session identity, and trusted kernel origin as a structured observation and should retain the source configuration and kernel build digest. A future source registry could provide stronger monitor identifiers if collision resistance becomes a requirement.

The canonical run exercises the deterministic fixture path and confirms the upstream `stall` monitor interface is present and enabled. It does not claim that a real hardware or scheduler workload generated a stall. The test-only configuration must not be used as a production security boundary.

The existing lifecycle driver and Linux kernel remain a large trusted computing base. M88 does not replace LSM, capabilities, namespaces, seccomp, module-signing policy, or kernel lockdown. It adds no new privilege escalation path by design.

## Acceptance decision

The M88 security review passes for the bounded validation environment because the bridge is observation-only, event delivery is capability-filtered through the existing session mask, lifetime synchronization is explicit, the test export is validation-only, the added/modified lines contain no scanned high-risk process-execution or model-authority pattern, and all canonical QEMU and regression evidence is available. Residual risks are documented rather than silently promoted to production guarantees.

## References

[1]: `M88-RV-BRIDGE-DESIGN.md` — architecture and trust-boundary design.
[2]: `drivers/misc/agi_lifecycle.c` — locking, session lifetime, and delivery implementation.
[3]: `kernel/trace/rv/rv_reactors.c` — upstream RV callback and validation-only export gate.
[4]: `tools/faisal-build/evidence/m88-security-scan.txt` — targeted security-scan output.
[5]: `tools/faisal-build/evidence/m88-rv-bridge-qemu.log` — canonical QEMU runtime evidence.
