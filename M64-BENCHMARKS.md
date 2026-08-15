# FAISAL M64 Measurements

M64 measures authorization and provenance-binding correctness. It does not measure model performance, semantic provenance quality, or a general security overhead improvement.

The static M64 selftest passed three repeated two-vCPU QEMU runs. Each run covered tensor scoped-capability allow, cross-agent denial, tensor provenance bind/query, context provenance binding, and clean exit. Wall-clock values were not used as a performance claim because they include guest startup, kernel boot, initramfs construction, and shutdown.

A proper performance comparison must measure upstream Linux plus the FAISAL kernel on identical hardware and configuration, including capability-check latency, provenance bind/query latency, lock contention under concurrent agents, event-ring overhead, memory footprint of bounded binding records, and the cost of generation validation. Security correctness takes priority over an optimization that weakens scope or revocation guarantees.

No M64 performance improvement is claimed.
