# FAISAL M70 Security Review

## Scope

This review covers ABI-37 workload-aware power-policy records and their composition with Linux CPU PM QoS. M70 records workload intent and applies a bounded CPU latency request when the kernel configuration supports it. It does not program GPU/NPU registers, bypass thermal protection, or grant authority based on model output.

## Security properties

| Property | Enforcement |
|---|---|
| Session lineage | The caller must have a live FAISAL session and matching task lineage. |
| Agent ownership | Query and release require that the policy owner matches the current FAISAL agent. |
| Opaque capability | Policy ID alone is insufficient; the exact random capability is required. |
| CPU-mask scope | Requested CPUs must be online and within the bounded execution-domain mask width. No CPU affinity or policy membership is changed. |
| PM QoS lifetime | The request is held in a session-owned record and removed on explicit release or file close. |
| Required features | `REQUIRE_ALL` returns `-EOPNOTSUPP` before creating a partial policy. |
| Provider target scope | An arbitrary device ID does not create power authority. Device power features are negotiated only from a registered provider advertising power control. |
| Thermal authority | No M70 path disables thermal trips, cooling, emergency poweroff, or platform power limits. |
| Resource bounds | A session can own at most 16 records; no unbounded allocations or user-sized kernel buffers are introduced. |
| Event isolation | Policy events use the existing per-session bounded event ring. |
| Model authority boundary | Profile, utilization, latency, and budget values are requests/metadata. They do not authorize privileged actions or device execution. |

## Threat model

A compromised agent may attempt to hold a system-wide low-latency request indefinitely, claim a GPU power budget, use another agent’s policy capability, specify offline CPUs, exhaust policy slots, or use a fabricated inference profile to override thermal safety. M70 limits these attacks with per-session bounds, agent/capability checks, CPU-online validation, explicit unsupported reporting, automatic close cleanup, and the fact that PM QoS aggregation remains shared with other kernel clients.

The CPU latency request is an availability-sensitive operation: a malicious authorized workload can prevent deeper idle states while its file remains open. This is not a privilege escalation, but it can increase energy use. Production policy should therefore be mediated by a trusted supervisor, cgroup/resource policy, operator approval, and monitoring of open lifecycle sessions.

## Provider and hardware boundaries

The generic lifecycle driver does not possess a reference to an arbitrary device’s runtime-PM, Devfreq, thermal, or Powercap backend. It therefore reports device wake latency, no-power-off, power budget, thermal coordination, and accelerator-provider features as unsupported unless a future provider registers an explicit contract. It does not infer hardware support from a userspace string or from the requested device ID.

Thermal controls retain priority over workload intent. A PM QoS latency request cannot guarantee a frequency, prevent thermal throttling, prevent a device from being power-gated, or suppress emergency shutdown. Energy Model presence is not treated as calibrated energy measurement.

## Concurrency and teardown

The lifecycle file’s ioctl serialization protects policy-table updates. The request object is stored inside the bounded session record, and cleanup runs before the session is freed. Release is idempotence-protected by the policy state; a second release returns `-EALREADY`. A provider-specific asynchronous implementation must add its own device reference, reset, fence, and removal synchronization before sharing this record.

## Residual risks

M70 does not rate-limit the number of policy state transitions beyond the bounded record table and event ring. Repeated create/release operations can consume records until the session closes. The event ring may drop records under pressure, so it is unsuitable as the sole source for billing or forensic accounting. PM QoS values are latency requirements, not proof that the system met a latency SLO.

## Security conclusion

M70 is acceptable as a conservative intent/enforcement-reporting milestone. It creates no generic accelerator privilege, leaves thermal and hardware power control with Linux providers, and keeps authorization independent of model output. It should not be described as cross-device power coordination until a real platform provider, trusted supervisor, and hardware validation suite exist.

## References

[1]: https://docs.kernel.org/power/pm_qos_interface.html "Linux kernel documentation: PM Quality Of Service Interface"
[2]: https://docs.kernel.org/admin-guide/pm/cpufreq.html "Linux kernel documentation: CPU Performance Scaling"
[3]: https://docs.kernel.org/power/powercap/powercap.html "Linux kernel documentation: Power Capping Framework"
[4]: https://docs.kernel.org/driver-api/thermal/sysfs-api.html "Linux kernel documentation: Generic Thermal Sysfs driver How To"
