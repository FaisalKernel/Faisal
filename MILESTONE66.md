# FAISAL M66 — Capability-Scoped Tensor Transport Control

**Status:** Implemented and QEMU-validated as a control-plane primitive.
**Upstream base:** Linux `v7.2-rc7`, verified from the kernel.org snapshot and recorded locally as `upstream-v7.2-rc7`.
**FAISAL ABI:** 33.
**Validation date:** 2026-08-15.

## Purpose

M66 introduces a bounded FAISAL tensor-transport object for distributed AGI workloads. It records and authorizes a tensor-region transport request using an opaque transport capability, tensor-region capability, region generation, transport class, direction, bounded byte/chunk sizes, device identifiers, participant metadata, and optional provenance references.

The primitive is deliberately a **control-plane reservation and authorization object**. It does not execute a network transfer, interpret a neural graph, access GPU physical memory, or implement AllReduce in the kernel. Existing Linux RDMA, DMA-BUF, DMA, IOMMU, device-driver, fence, socket, and userspace collective-library paths remain responsible for actual data movement and hardware synchronization.

## ABI additions

| Item | Value | Meaning |
|---|---:|---|
| `AGI_LC_ABI_VERSION` | 33 | UAPI revision after M66 additions |
| `AGI_LC_TENSOR_TRANSPORT` | `0x5f` | Register, query, or revoke a transport object |
| Transport classes | RDMA, DMA-BUF, socket-ring | Metadata classes only; no implicit hardware provider |
| Collective metadata | AllReduce, Broadcast, ReduceScatter, AllGather | Participant description only |
| Directions | Send, Receive, Bidirectional | Determines required tensor-region access |
| Capacity | 32 records/session | Bounded control-plane state |

Registration requires a live tensor-policy memory region, exact region capability, current region generation, valid tensor metadata, bounded transfer length, and a nonzero correlation identifier. Receive and bidirectional requests require the corresponding tensor write permissions. Query and revoke require the opaque transport capability. Revoke invalidates the record and increments its generation.

Requests carrying `AGI_LC_TRANSPORT_REQUIRE_ZERO_COPY` return `-EOPNOTSUPP` because the current implementation has no provider-specific zero-copy guarantee. This is intentional: it prevents a metadata object from being mistaken for proof that an RDMA or GPU driver will avoid copies.

## Implementation

The UAPI is defined in `include/uapi/linux/agi_lifecycle.h`. The lifecycle driver stores bounded per-session records in `drivers/misc/agi_lifecycle.c`, validates tensor-region capability and generation under the existing memory-region lock, and records registration/revocation events. The restored FAISAL task-state substrate is implemented in `kernel/faisal.c` and exposed through `include/linux/faisal.h`.

The executable test is `tools/testing/selftests/agi_tensor_transport_test.c`. The reproducible boot harness is `tools/faisal-build/run_transport_qemu.sh`.

## Verification evidence

The restored kernel and static selftest were built with GCC 13.3.0. The full `bzImage` and modules build completed successfully. QEMU x86_64 booted the exact image and initramfs, created `/dev/agi_lifecycle` through devtmpfs, and emitted all required markers:

```text
FAISAL_M66_BOOT_OK
M66_TRANSPORT_REGISTER_OK id=1
M66_TRANSPORT_QUERY_OK
M66_STALE_CAPABILITY_REJECT_OK
M66_ZERO_COPY_BOUNDARY_OK
M66_TRANSPORT_REVOKE_OK
M66_SELFTEST_EXIT=0
FAISAL_M66_TEST_RC=0
FAISAL_M66_SELFTEST_EXIT=0
```

The full machine-readable evidence is stored in `tools/faisal-build/evidence/m66-transport-validation.json`; the raw serial log is stored in `tools/faisal-build/evidence/m66-qemu.log`.

## Limitations

M66 does not measure or claim lower latency, higher throughput, GPU-to-GPU DMA, RDMA completion, NIC offload, hardware collective execution, NCCL replacement, or accelerator support. No physical address is exposed. No Linux RDMA or DMA-BUF security boundary is replaced. A provider-specific follow-up milestone would be required to bind a transport record to a real DMA-BUF attachment, RDMA memory registration, device fence, and measured data path.

## References

[1]: https://docs.kernel.org/infiniband/user_verbs.html "Linux kernel documentation: Userspace verbs access"
[2]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[3]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
[4]: https://docs.kernel.org/networking/af_xdp.html "Linux kernel documentation: AF_XDP"
