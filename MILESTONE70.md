# FAISAL M70 — Workload-Aware Power Policy

**Status:** Implemented and validated in two-vCPU QEMU.
**Base:** Linux `v7.2-rc7`, local tag `upstream-v7.2-rc7`.
**FAISAL ABI:** 37.
**Validation date:** 2026-08-15.

## Objective

M70 adds a bounded workload-aware power-policy control plane. An AGI runtime can express whether a task is inference, training, background learning, or recovery work; request a CPU latency constraint; identify a CPU mask; and report a desired device or power budget. The kernel applies only the Linux power-management mechanisms that are actually available and returns an explicit negotiated result for everything else.

This is an **intent and enforcement-reporting primitive**, not a replacement for CPUFreq, Devfreq, thermal, Powercap, DTPM, Energy Model, Runtime PM, or accelerator-provider drivers. CPUFreq policies remain hardware-control domains, Devfreq drivers remain responsible for arbitrary-device frequency changes, and platform thermal/powercap controls remain authoritative [1] [2] [3] [4] [5] [6].

## ABI-37

`AGI_LC_POWER_POLICY` is ioctl `0x62`. A session owns a bounded table of 16 policy records. Operations are `SET`, `QUERY`, and `RELEASE`.

| Policy field | Behavior |
|---|---|
| Profile | Inference, training, background, or recovery phase. This is attribution metadata, not a governor selection. |
| CPU latency | When Linux `CONFIG_CPU_IDLE` is available and the feature is requested, the driver adds a session-lifetime CPU PM QoS latency request. It is removed on release or file close. |
| CPU mask | Optional online-CPU mask is validated against Linux’s online CPU set; M70 does not change affinity or CPUFreq policy membership. |
| Utilization bounds | Bounded scheduler-scale hints are recorded for the userspace planner; M70 does not directly alter utilization clamps. |
| Device/provider fields | Device IDs and power budgets are reported as unsupported unless a registered provider explicitly advertises power control. |
| Thermal and Energy Model | Framework capability bits are not claimed merely from the existence of FAISAL metadata. Platform/provider integration is required. |
| Capability | Each policy receives an opaque capability; query and release require the exact policy ID/capability pair and current agent ownership. |
| Lifetime | Release removes the CPU PM QoS request and transitions the record to RELEASED. Session close removes any remaining request. |
| Events | Set and release emit `AGI_LC_EVENT_POWER_POLICY` through the existing bounded session event ring. |

## Linux composition

Linux PM QoS aggregates multiple requests and uses the effective constraint rather than allowing a single caller to overwrite other clients [3]. M70 composes with that mechanism by adding and removing one request per active FAISAL policy. A policy therefore cannot erase another driver’s latency requirement, and closing the lifecycle file provides automatic cleanup.

CPUFreq policy objects represent groups of CPUs that share a hardware performance-scaling interface; the actual frequency may still be constrained by hardware coordination, thermal limits, or power limits [1]. M70 consequently does not set a frequency or promise a next-token latency. Devfreq similarly requires device-specific status and target callbacks, so arbitrary GPU/NPU power control remains provider-owned [2].

Thermal zones and cooling devices remain the platform protection path [4]. Powercap exposes platform-specific zones and constraints, while DTPM supplies a hierarchy but requires platform backends to perform actual power limiting [5] [6]. The Energy Model can be calibrated in microwatts or use an abstract scale; M70 does not convert an uncalibrated model into energy claims [7].

## Validation

The full kernel and module build passed. The static selftest passed in a two-vCPU QEMU guest and verified CPU PM QoS negotiation, partial unsupported reporting, stale capability rejection, required-feature refusal, event delivery, release cleanup, and final state.

```text
FAISAL_M70_BOOT_OK
M70_POWER_POLICY_SET_OK id=1 applied=0x1 unsupported=0xa
M70_POWER_POLICY_QUERY_OK generation=1
M70_STALE_POLICY_CAPABILITY_REJECT_OK
M70_REQUIRED_FEATURE_REFUSAL_OK
M70_POWER_POLICY_EVENT_OK
M70_POWER_POLICY_RELEASE_OK generation=2
M70_SELFTEST_EXIT=0
FAISAL_M70_TEST_RC=0
```

M66, M67, M68, and M69 regression boot tests must be rerun against the ABI-37 kernel before the milestone is tagged. The raw M70 serial output is stored in `tools/faisal-build/evidence/m70-qemu.log`, and machine-readable evidence is stored in `tools/faisal-build/evidence/m70-power-policy-validation.json`.

## Explicit non-claims

M70 does not claim GPU or NPU power-gating control, device wake-latency control, CPU/GPU thermal arbitration, cross-device power-budget enforcement, Energy Model calibration, DVFS frequency selection, inference latency improvement, reduced energy use, or protection against thermal throttling. It also does not make model output an authorization source. A trusted supervisor and provider-specific driver integration are still required for production power actions.

## References

[1]: https://docs.kernel.org/admin-guide/pm/cpufreq.html "Linux kernel documentation: CPU Performance Scaling"
[2]: https://docs.kernel.org/driver-api/devfreq.html "Linux kernel documentation: Device Frequency Scaling"
[3]: https://docs.kernel.org/power/pm_qos_interface.html "Linux kernel documentation: PM Quality Of Service Interface"
[4]: https://docs.kernel.org/driver-api/thermal/sysfs-api.html "Linux kernel documentation: Generic Thermal Sysfs driver How To"
[5]: https://docs.kernel.org/power/powercap/powercap.html "Linux kernel documentation: Power Capping Framework"
[6]: https://docs.kernel.org/power/powercap/dtpm.html "Linux kernel documentation: Dynamic Thermal Power Management framework"
[7]: https://docs.kernel.org/power/energy-model.html "Linux kernel documentation: Energy Model of devices"
