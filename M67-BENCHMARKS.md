# FAISAL M67 Measurements

M67 is a policy and affinity control-plane primitive. It does not claim deterministic latency or a jitter reduction.

In the validated two-vCPU QEMU run, the guest reached the execution-domain test at approximately 1.9 seconds of guest kernel time and powered down at approximately 2.3 seconds. The create, query, stale-capability, required-NO_HZ boundary, and release operations completed within that smoke run. These observations are not a comparative benchmark and do not measure interrupt or scheduler jitter.

A valid jitter benchmark requires a fixed target machine, a baseline Linux boot configuration, a matching FAISAL boot configuration, pinned workloads, `cyclictest`/`rtla-osnoise`-style tracing or equivalent tracepoints, repeated trials, maximum and percentile latency, IRQ/NMI/SMI observations where available, CPU-frequency and SMT controls, and correctness checks. M67 intentionally leaves that experiment for a later hardware-aware milestone rather than converting one QEMU boot into a performance claim.
