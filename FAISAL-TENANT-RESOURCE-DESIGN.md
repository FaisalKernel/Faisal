# FAISAL Tenant Resource Enforcement Design

## Scope

M151 extends M150 with kernel-validated ownership of a userspace-created cgroup v2 child. The kernel does not invent a private cgroup filesystem or bypass cgroup v2 lifecycle policy. A privileged deployment manager creates the hierarchy through the standard cgroup2 filesystem, opens the child directory, and passes the descriptor to `AGI_LC_TENANT_CGROUP`. The lifecycle driver obtains a referenced cgroup object, requires the target to be a direct child of the caller’s current cgroup, binds its identity to the session, and releases the reference on explicit release or file teardown.

> **Authority boundary:** cgroup creation remains a standard cgroup v2 filesystem operation; FAISAL owns and verifies the bound hierarchy after creation. A model, planner, or untrusted process cannot select an arbitrary cgroup or escape its parent hierarchy.

## Cgroup ownership ABI

`AGI_LC_TENANT_CGROUP` supports `BIND`, `QUERY`, and `RELEASE`. Binding requires a cgroup2 directory file descriptor and validates the current lineage, optional sandbox binding, cgroup v2 type, direct-parent relationship, stable cgroup ID, and session ownership token. The ioctl returns the bound cgroup ID, parent cgroup ID, session owner token, and generation. Queries and release require the current task to remain in the owned hierarchy or its parent owner context. A stale or unrelated hierarchy fails closed.

The global lifecycle sandbox guard accepts the session’s original sandbox identity or a task in the owned cgroup hierarchy. This permits a supervisor to manage workers after moving them into the owned child while preserving the original sandbox identity requirements.

## Hard CPU-time throttling design

The current ABI exposes CPU budget metadata and aggregate CPU accounting but does not claim hard CPU-time throttling. The production implementation should use cgroup v2 `cpu.max` as the enforcement primitive rather than a bespoke scheduler. A future `AGI_LC_TENANT_CPU_POLICY` operation should carry:

| Field | Contract |
|---|---|
| `period_us` and `quota_us` | Bounded values mapped to `cpu.max`; quota must not exceed period times the configured CPU count |
| `burst_us` | Optional bounded burst mapped only when the kernel and cgroup controller support it |
| `mode` | `ADMISSION`, `THROTTLE`, or `QUERY`; unsupported modes fail closed |
| `overrun_action` | `EVENT`, `THROTTLE`, `CANCEL`, or `QUARANTINE`, each policy-gated |
| `generation` | Monotonic policy generation preventing stale updates |
| `correlation` | Audit record correlation; never authority by itself |

The lifecycle driver should apply the policy only to a cgroup already bound through `AGI_LC_TENANT_CGROUP`, require `CAP_RESOURCE_DELEGATE` or an equivalent active capability grant, and verify the cgroup remains a descendant of the owner hierarchy immediately before update. The kernel should read `cpu.stat`/scheduler accounting for evidence and emit an event when throttled time crosses policy thresholds. It must not claim deterministic latency because CPU quotas do not eliminate firmware, interrupt, scheduler, or host virtualization jitter.

## GPU/NPU accelerator accounting design

The existing accelerator ABI already separates device registration, workload declaration, and device accounting. The next production extension should add a tenant claim bound to `(tenant_cgroup_id, device_id, generation)` and require every accounting record to carry that claim. The claim should specify:

| Dimension | Required behavior |
|---|---|
| Compute time | Accumulate device-reported execution nanoseconds with saturating arithmetic |
| Device memory | Account resident or allocated bytes only when the driver reports authoritative values |
| Submissions | Count accepted queue submissions and rejected submissions separately |
| Isolation | Require the device driver or mediated framework to enforce tenant ownership; lifecycle metadata alone is not isolation |
| Revocation | Stop accepting new submissions after claim generation revocation; existing work is reported as draining or failed |
| Capability | Require a device-specific delegated capability; model output never authorizes a claim |

NVIDIA, AMD, Intel, NPU, and vendor-specific accelerators must provide authoritative driver callbacks or mediated-device accounting. If a driver cannot provide trustworthy ownership or counters, FAISAL must return `UNSUPPORTED` and retain no false budget claim. The current QEMU environment has no physical accelerator qualification.

## Benchmark contract

The M151 benchmark compares a high-concurrency atomic accounting path with a serialized budget-check model using the same operation count and byte size. It measures synchronization and arithmetic overhead on the host, not the actual kernel ioctl path. Production qualification requires a native kernel benchmark with tracepoints, cgroup `cpu.stat`/memory events, representative worker counts, and physical accelerator telemetry.

## Failure and recovery

A missing cgroup, stale file descriptor, wrong parent, revoked session, stale generation, unsupported controller, driver-without-authoritative-counters, or provider error must return an error or `UNSUPPORTED` status without partially updating policy. Explicit release clears the FAISAL reference but does not delete the cgroup directory; the deployment manager owns directory removal after workers leave. Session teardown releases the kernel reference so cgroup removal cannot be pinned indefinitely by FAISAL.

## Explicit non-claims

This design does not claim that the current implementation creates cgroups from kernel code, hard-throttles CPU time, or enforces GPU/NPU isolation. It establishes the secure ownership boundary and ABI design needed for those future integrations while preserving Linux cgroup v2 and accelerator-driver semantics.
