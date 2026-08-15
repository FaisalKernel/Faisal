# FAISAL M68 Security Review

## Scope

This review covers ABI-35 extensions to `AGI_LC_COMPUTE_CONTEXT`. M68 adds heterogeneous device/fabric negotiation and bounded accounting; it does not submit accelerator work or grant direct device authority.

## Security properties

| Property | Enforcement or behavior | Validation |
|---|---|---|
| Session lineage | The caller must own the FAISAL lifecycle session lineage | QEMU selftest session setup |
| Agent identity | A requested agent must match the caller’s FAISAL agent; created contexts record the current agent | Driver path and context query |
| Context capability | Query, bind, unbind, and close require the opaque context capability and agent match | Stale-capability marker |
| Memory capability | Region binding requires the existing region capability and valid read/write scope | Bind marker with a real 4096-byte region |
| Device honesty | GPU/NPU/I/O request bits are reported unsupported when no provider is attached | GPU-provider-boundary marker |
| Fabric honesty | Active fabric bits come from compiled Linux framework configuration; unsupported requests remain visible | Negotiation marker and evidence JSON |
| DMA safety | No CPU physical, bus, DMA, VRAM, or PASID address is accepted or returned | UAPI and code review |
| Memory accounting | Only capability-authorized region sizes contribute to bounded `bytes_accounted` | Bind/unbind markers |
| Model authority | Model output alone cannot create a context; lifecycle/session/agent checks remain required | Driver authorization path |
| Lifetime | Context close transitions state and increments generation; session teardown frees bounded records | Close marker and existing session cleanup |

## Threat model

A compromised model or prompt-injected agent may request GPU/NPU access, claim that a DMA buffer is zero-copy, guess a device address, reuse a stale capability, or inflate resource accounting. M68 addresses these threats by treating all device/fabric fields as requests, deriving active framework bits from the kernel build, keeping unsupported device classes explicit, requiring exact capabilities, and using existing region authorization for memory accounting.

The implementation does not call DMA, dma-buf, HMM, IOMMU, UACCE, DRM, or provider queue operations. This is deliberate: those interfaces have provider-specific lifetime, locking, address-translation, fence, and hardware-reset semantics. Bypassing them from a generic lifecycle ioctl would create a security boundary failure.

## Residual risks

Compile-time framework availability is not runtime hardware capability. The active IOMMU-SVA bit means that the corresponding Linux framework is built, not that an accelerator, ATS, PRI, PASID, or SVA binding exists. Likewise, DMA-buf and DMA Engine availability does not guarantee a compatible buffer exporter, importer, channel, or accelerator.

The current context record is a bounded per-session prototype. Production integration should bind a specific provider file descriptor or trusted driver object, negotiate hardware capabilities through that provider, account device memory through the provider/cgroup subsystem, handle device reset and revocation, and add concurrency testing under KASAN, KCSAN, lockdep, and fault injection.

## Security conclusion

M68 is acceptable as a conservative heterogeneous-first control-plane milestone. It improves attribution and capability reporting without falsely turning the CPU-centric lifecycle driver into a universal accelerator driver. It must not be advertised as hardware isolation, GPU/NPU scheduling, SVA activation, or zero-copy transport.

## References

[1]: https://docs.kernel.org/core-api/dma-api-howto.html "Linux kernel documentation: Dynamic DMA mapping Guide"
[2]: https://docs.kernel.org/driver-api/dma-buf.html "Linux kernel documentation: Buffer Sharing and Synchronization (dma-buf)"
[3]: https://docs.kernel.org/mm/hmm.html "Linux kernel documentation: Heterogeneous Memory Management (HMM)"
[4]: https://docs.kernel.org/arch/x86/sva.html "Linux kernel documentation: Shared Virtual Addressing (SVA) with ENQCMD"
