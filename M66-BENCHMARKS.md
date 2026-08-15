# FAISAL M66 Measurements

M66 is a control-plane authorization object, not a data-plane transport implementation. No claim of lower latency, higher throughput, reduced CPU overhead, or improved collective performance is made.

The validated QEMU run booted the x86_64 `bzImage` and reached the M66 selftest at approximately 3.2 seconds of guest kernel time; the transport registration, query, stale-capability denial, zero-copy boundary, and revoke operations completed before guest power-down at approximately 3.6 seconds. These values are **smoke-test observations only**, not a benchmark and not a comparison against Linux or any RDMA/DMA-BUF provider.

A meaningful performance benchmark requires a selected provider path, real or software-loopback transport, repeated trials, a baseline using the provider’s ordinary API, CPU and memory counters, tail latency, and correctness checks for completion and data integrity. That work is intentionally deferred rather than replaced by an unmeasured claim.
