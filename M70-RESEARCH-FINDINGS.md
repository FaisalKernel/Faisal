# FAISAL M70 Research Findings

**Research date:** 2026-08-15
**Kernel base:** Linux `v7.2-rc7` in this repository.

## Verified boundaries

| Area | Verified Linux mechanism | M70 implication |
|---|---|---|
| CPU performance scaling | CPUFreq separates a common core, governors, and hardware-specific scaling drivers. Policy objects represent CPUs sharing a hardware performance-control interface. Governors and drivers may bypass one another, as with `intel_pstate` [1]. | FAISAL must not assume one CPU maps to one controllable frequency or that a generic ioctl can force a frequency. It should express workload intent and report policy scope. |
| Device performance scaling | Devfreq is a standard framework for dynamic voltage/frequency scaling of arbitrary devices. Drivers provide status and target callbacks; governors select frequency and the device driver performs the hardware operation [2]. | GPU/NPU frequency control remains provider-owned. M70 can report requested device classes and provider support without directly programming devices. |
| CPU latency QoS | PM QoS aggregates CPU latency requests and exposes per-device latency/flag requests. Requests are handles with explicit add/update/remove lifetime [3]. | The safest kernel action for an inference latency policy is a scoped CPU PM QoS request, automatically removed on policy teardown. It is not a frequency or wake-latency guarantee. |
| Device latency tolerance | Per-device PM QoS supports resume latency, active-state latency tolerance, and `NO_POWER_OFF` flags where a device implements the required callback [3]. | M70 may negotiate/report device-PM-QoS capability, but must return unsupported when no concrete device/provider handle exists. |
| Thermal control | Thermal zones expose temperatures/trips and cooling devices expose throttle states; platform thermal management remains the authority for protection and throttling [4]. | Workload policy cannot override thermal emergency behavior or claim a safe thermal budget without platform data. |
| Powercap/DTPM | Powercap exposes hardware/platform power zones and constraints; DTPM provides a hierarchical interface but no generic power-limiting backend, which platform drivers must supply [5] [6]. | Cross-CPU/GPU budget coordination requires platform powercap/DTPM/provider support. M70 records requested budgets and reports unavailable backend control rather than simulating it. |
| Energy Model | Energy Model provides driver-supplied power/performance tables to scheduler, thermal, and powercap users. Values may be microwatts or an abstract scale, and non-microwatt values cannot produce real energy units [7]. | M70 must distinguish framework presence from calibrated energy accounting and never manufacture joule or watt claims. |
| Existing FAISAL control | Resource demand, accelerator workload, execution-domain, and graph telemetry objects already carry workload, priority, deadline, latency sensitivity, device class, and attribution. | M70 should extend existing policy vocabulary with a bounded workload-aware power-policy record, not create a second agent-resource identity model. |

## Design conclusion

The smallest justified M70 primitive is a **scoped workload-aware power-policy intent**. A caller submits inference, training, or background-learning phase, latency sensitivity, minimum CPU utilization, maximum idle/wakeup tolerance, optional CPU mask, and an optional power budget. The kernel validates the FAISAL session/agent, creates a bounded policy record, applies only the generic CPU PM QoS latency request when the build supports it, and reports the rest as negotiated/unsupported capabilities. Policy release removes the PM QoS request.

The primitive does not change CPUFreq governors, devfreq providers, thermal trips, powercap zones, or accelerator hardware. It cannot keep a GPU powered when no provider handle exists. A future provider integration must supply device lifetime, runtime-PM, devfreq, fence, thermal, and powercap contracts before M70 can act on accelerator power state.

## Sources

[1]: https://docs.kernel.org/admin-guide/pm/cpufreq.html "Linux kernel documentation: CPU Performance Scaling"
[2]: https://docs.kernel.org/driver-api/devfreq.html "Linux kernel documentation: Device Frequency Scaling"
[3]: https://docs.kernel.org/power/pm_qos_interface.html "Linux kernel documentation: PM Quality Of Service Interface"
[4]: https://docs.kernel.org/driver-api/thermal/sysfs-api.html "Linux kernel documentation: Generic Thermal Sysfs driver How To"
[5]: https://docs.kernel.org/power/powercap/powercap.html "Linux kernel documentation: Power Capping Framework"
[6]: https://docs.kernel.org/power/powercap/dtpm.html "Linux kernel documentation: Dynamic Thermal Power Management framework"
[7]: https://docs.kernel.org/power/energy-model.html "Linux kernel documentation: Energy Model of devices"
