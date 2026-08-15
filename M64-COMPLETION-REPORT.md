# FAISAL M64 Security Completion Report

**Status:** Completed retroactively on the current ABI-37 FAISAL tree.
**Current base:** Linux `v7.2-rc7`; current head before this completion is `FAISAL-M70`.
**Validation date:** 2026-08-15.

## Reason for completion

M64 agent-oriented security design and its selftest were present as uncommitted work, but provenance binding remained a `-EOPNOTSUPP` stub in the lifecycle dispatcher. That made the scoped capability/provenance foundation incomplete. The live dependency graph selected M64 security stabilization before persistent memory, browser/tool supervision, and multi-agent services.

## Implemented primitive

The lifecycle driver now implements `AGI_LC_PROVENANCE_BINDING` with bounded, session-owned records. A binding is accepted only when the caller has a live FAISAL lineage, the provenance action/sequence exists in the same session and belongs to the current agent, and the target tensor or compute context matches its exact capability and current generation.

| Operation | Enforcement and result |
|---|---|
| Bind tensor provenance | Requires readable authorized tensor capability, valid tensor policy, and matching tensor generation; stores binding ID, provenance ID/sequence, and generation in the tensor policy. |
| Bind context provenance | Requires current-agent active context, exact context capability, and matching context generation; stores the same bounded reference in the context record. |
| Query binding | Requires the binding ID and current agent; returns the original scoped relationship. |
| Revoke binding | Clears the target resource’s binding reference, marks the binding cancelled, increments binding generation, and emits an audit event. |
| Stale/cross-agent access | Returns denial without changing the target resource. |
| Resource bounds | Maximum 64 binding records per session; no model data, physical addresses, or unbounded payloads are stored. |

## Validation evidence

The full ABI-37 kernel and modules build passed. The static selftest passed three repeated M64 QEMU runs and the M66, M67, M68, M69, and M70 regression harnesses.

```text
FAISAL_M64_BOOT_OK
M64_TENSOR_SCOPE_ALLOW_OK
M64_CROSS_AGENT_REJECT_OK
M64_TENSOR_PROVENANCE_BIND_OK id=1
M64_TENSOR_PROVENANCE_QUERY_OK
M64_CONTEXT_SCOPE_AND_PROVENANCE_OK
M64_SELFTEST_EXIT=0
FAISAL_M64_TEST_RC=0
```

## Explicit boundaries

M64 proves only a kernel-held relationship among agent lineage, provenance record, resource identity, capability, and generation. It does not prove model causality, token-level provenance, semantic ownership, correct reasoning, trusted model output, or hardware execution. Linux LSM, DAC, namespaces, cgroups, seccomp, DMA/IOMMU, provider drivers, and independent trusted-supervisor policy remain required.

## Rollback

The implementation can be reverted as a small follow-on commit while retaining the tagged FAISAL-M70 kernel. Production deployment still requires independent supervisor and operator approval.
