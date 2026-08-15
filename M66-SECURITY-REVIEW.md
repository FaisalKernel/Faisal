# FAISAL M66 Security Review

## Scope

This review covers the ABI-33 `AGI_LC_TENSOR_TRANSPORT` object and its integration with FAISAL tensor memory regions. The feature is a kernel control-plane authorization layer; it is not a replacement for Linux credentials, DAC, LSM, Landlock, seccomp, cgroups, RDMA protection domains, DMA-BUF attachment rules, IOMMU mappings, or accelerator-driver validation.

## Security properties verified

| Property | Enforcement | Evidence |
|---|---|---|
| Tensor resource identity | Registration requires `region_id`, region capability, and current region generation | M66 selftest registration marker |
| Tensor access direction | Send, receive, and bidirectional requests map to read, write, or read/write region access | Driver branch and QEMU registration |
| Region lifetime | Revoked or generation-mismatched regions are denied | Generation comparison in the memory-region lock |
| Transport ownership | Query and revoke require the exact opaque transport capability | M66 stale-capability rejection marker |
| Bounded resource use | 32 records per session; bytes and chunk bytes are nonzero and bounded by region size | UAPI validation and QEMU registration |
| Collective metadata bounds | Non-collective requests require one participant; collective requests require at least two and a bounded participant index | UAPI validation and selftest AllReduce registration |
| Unsupported hardware promise | `REQUIRE_ZERO_COPY` returns `-EOPNOTSUPP` because no provider-specific zero-copy proof exists | M66 zero-copy boundary marker |
| Revocation | Revoke marks the object revoked, increments generation, and removes it from active lookup | M66 revoke marker |
| Physical-address confidentiality | No physical or bus address is accepted or returned by the ABI | UAPI structure review |

## Threat model

A compromised model or prompt-injected userspace agent may attempt to register another agent’s tensor, reuse an old region generation, request bidirectional access with read-only authority, forge a transport capability, or infer that a metadata registration guarantees a zero-copy path. The implementation rejects stale or incorrect tensor capabilities, applies direction-specific memory authorization, requires exact transport capabilities for control operations, and explicitly rejects the unsupported zero-copy requirement.

The transport object does not itself authorize a device to DMA. Actual device access remains subject to the Linux device driver, DMA API, IOMMU, DMA-BUF attachment and fence rules, RDMA protection and memory-registration rules, and existing process/security policy. The kernel does not interpret model output as authority; a userspace caller must already possess the FAISAL session lineage and tensor-region capability.

## Residual risks

The current restored FAISAL task-state substrate is a bounded reconstruction required to make the surviving lifecycle driver buildable after the original full tree was lost. It provides task metadata and accounting helpers, but it is not a complete upstream-quality replacement for a production task-integrated implementation. Its fixed 1024-entry state table and limited network accounting require further lifecycle cleanup and subsystem-hook work before production use.

M66 records transport metadata but does not attach a real `struct dma_buf`, RDMA memory region, NIC queue, fence, or accelerator context. Therefore it cannot prevent a provider-specific driver or userspace library from making an independent policy error. The appropriate next step is an integration milestone for one selected upstream provider path, with hardware or software-loopback tests and measured transfer correctness.

No Spectre/Meltdown performance claim, neural subgraph sandboxing claim, direct-GPU-memory claim, or collective-computation performance claim is made.

## Review conclusion

M66 is acceptable as a bounded, capability-scoped control-plane prototype validated in QEMU. It is not sufficient for production distributed accelerator transport. Deployment requires the existing trusted supervisor and operator approval gates, plus provider-specific validation of DMA, IOMMU, RDMA, DMA-BUF, and fence behavior.

## References

[1]: https://docs.kernel.org/infiniband/user_verbs.html "Linux kernel documentation: Userspace verbs access"
[2]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[3]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
