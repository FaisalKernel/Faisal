# FAISAL M71 Measurements

M71 measures persistence, kernel metadata integration, checkpoint/recovery sequencing, and journal corruption handling. It does not measure semantic retrieval quality, model learning, inference latency, or production database throughput.

The static M71 selftest passed three repeated two-vCPU QEMU runs. Each run performed a durable put, digest-checked get, stale-capability rejection, checkpoint creation, simulated crash mark, service restart replay, verified restore, incomplete-tail recovery, and complete digest-corruption rejection.

| Measurement | Observation | Interpretation |
|---|---|---|
| Kernel and modules build | Passed | ABI and kernel integration compile successfully. |
| Static service/selftest build | Passed with `-Wall -Wextra -Werror -Wno-cpp` | Userspace service has no project warnings beyond the intentional kernel-header warning suppression. |
| QEMU stress runs | 3 of 3 passed | Repeatability smoke evidence only. |
| Journal content bound | 4095 bytes per record | Fixed service limit, not a database capacity claim. |
| In-memory replay bound | 64 records | Fixed reference-service limit. |
| Digest algorithm | SHA-256 | Content-integrity check, not semantic truth verification. |

A meaningful baseline requires comparing the service with a userspace-only journal and a production storage design under identical filesystem, sync mode, record size, concurrency, crash injection, and hardware conditions. Required measurements include put/query latency, `fdatasync()` cost, replay time, checkpoint time, recovery time, CPU/memory overhead, lock contention, journal growth, corruption detection time, and multi-agent scaling. No M71 performance improvement is claimed.
