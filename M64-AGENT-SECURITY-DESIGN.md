# FAISAL M64 Agent-Oriented Security Design

> **Completion note (2026-08-15):** This document records the original M64 design. The implementation was later completed and validated on the current ABI-37 tree; see `M64-COMPLETION-REPORT.md` and `tools/faisal-build/evidence/m64-agent-security-validation.json`. Historical references below to ABI 32 and the earlier M63 base describe the design-time state, not the current runtime ABI.

## Scope and decision

M64 adds a narrow, kernel-enforced security layer for **FAISAL tensor regions and compute contexts**. The primitive being authorized is a kernel-generated capability bound to a resource identity and generation, not a file descriptor, pathname, UID, or model-generated instruction. The change composes with Linux DAC, credentials, capabilities, namespaces, cgroups, seccomp, and LSM policy; it does not replace them.

The checked-out foundation is Linux **7.2.0-rc7** with FAISAL M63 committed and tagged `FAISAL-M63`. M63 is ABI version 31 and already provides memory-region capabilities, tensor policy metadata, graph nodes, compute-context capabilities, agent identity, capability grants, and provenance action/result records. M64 increments the FAISAL UAPI to ABI 32 and extends those existing objects rather than adding a new system call or replacing `task_struct`.

> Linux LSM is an enforcement framework rather than a policy by itself; active security modules enforce access through kernel hooks and security fields.[1] Landlock is a stackable LSM for process self-restriction and future children, with filesystem, network, and selected IPC scopes.[2] Seccomp filters system calls and arguments, but does not understand tensor objects or neural semantics.[3]

## Security boundary

Linux remains the process-level boundary. DAC and LSM evaluate ordinary object access, namespaces constrain object visibility, cgroups and rlimits account for resources, seccomp constrains system-call attack surface, and device subsystems retain ownership of device and DMA policy. FAISAL adds a second, resource-level decision for an AGI runtime that has already passed Linux’s ordinary checks.

The authorization path is:

```text
calling Linux task
  -> FAISAL lineage and agent attribution
  -> trusted-authority-issued grant
  -> grant capability token and requested rights
  -> exact tensor-region or compute-context scope
  -> resource capability and generation
  -> operation allowed or denied
  -> auditable FAISAL event and provenance reference
```

A model output, prompt, natural-language request, graph label, or userspace claim is untrusted input. It cannot create a grant, select a resource, bypass a revocation, or change Linux security policy. Capability issuance continues to require the existing trusted-authority validation and the target agent’s existing FAISAL registration/capability.

## M64 objects and ABI changes

The ABI-32 change appends scope metadata to `struct agi_lc_capability_grant`. Existing unscoped grants remain expressible with `scope_kind = AGI_LC_CAP_SCOPE_NONE`; new scoped grants must select exactly one of `AGI_LC_CAP_SCOPE_TENSOR` or `AGI_LC_CAP_SCOPE_CONTEXT` and provide the matching resource identifier, resource capability, and current resource generation. The grant’s existing `rights` field remains the authority mask. M64 adds explicit tensor-read, tensor-write, and compute-execute rights to that mask without changing the meaning of pre-existing rights.

The extended capability grant carries the following conceptual fields:

| Field | Meaning | Enforcement use |
|---|---|---|
| `scope_kind` | None, tensor region, or compute context | Rejects ambiguous or mixed scopes. |
| `scope_access` | Read/write/execute attenuation for the selected resource | Prevents a grant from exceeding the intended resource operation. |
| `scope_id` | Region ID or context ID | Identifies the kernel object, never a file descriptor. |
| `scope_capability` | Kernel-generated resource capability | Proves possession of the resource authority. |
| `scope_generation` | Resource generation at grant time | Rejects stale bindings after revocation or lifecycle mutation. |

The capability-check request is extended with the same scope selector and returns the allowed rights, allowed scope access, status, and audit sequence. An exact scope check requires the grant token, the target agent identity/capability, the resource capability, and the current resource generation. A wrong agent, wrong scope, wrong resource capability, revoked grant, stale generation, or insufficient access returns denial and records the attempt.

M64 also adds a provenance-binding operation. It binds an existing kernel provenance action/result record to either a tensor region or a compute context after validating the target resource capability and the caller’s scoped authority. The tensor-policy record and compute-context record expose the bound provenance identifier and sequence in GET results. Thus every FAISAL tensor-region policy has an explicit provenance slot; an unbound tensor is represented as provenance absent, not as silently trusted.

The new provenance binding stores no model weights, token stream, embedding contents, physical addresses, or browser data. It stores only a bounded reference to a kernel-held provenance record, the target resource identity, generation, binding generation, and audit correlation. Binding, query, replacement, and revoke operations are bounded by the existing session tables and are serialized by the resource locks already used by M63.

## Resource authorization rules

A tensor scope refers to the existing FAISAL memory-region object that carries tensor shape, stride, alignment, NUMA/tier policy, access mask, capability, and generation. The kernel does not infer tensor semantics from bytes. A scoped tensor grant can authorize only the requested tensor access bits and only for the exact region capability and current generation. It cannot authorize physical contiguity, DMA, accelerator commands, or access to another region.

A compute scope refers to the existing M63 compute-context object. The context capability and generation are required, and the context must remain active. A scoped compute grant can authorize control-plane compute-context operations represented by the M64 rights. It does not grant device access, queue submission, DMA, model execution, or authority over tasks outside the context. Existing Linux device and accelerator policy remains authoritative.

A graph node may be associated with an agent and a compute context in userspace, but M64 does not interpret neural operators or prove a graph’s semantic safety. A userspace scheduler must perform a scope check before issuing a tensor operation or context operation and must treat a denial as a hard authorization failure. Kernel graph metadata is not a substitute for capability checks.

## Provenance contract

A provenance reference records attribution and lineage for an operation; it is not a claim that the kernel understands the model’s internal reasoning. A binding is accepted only for an existing provenance record visible in the same FAISAL session and only when the requested resource capability and generation are valid. Provenance binding is therefore a verifiable reference relationship:

```text
agent -> task/lineage -> published action/result -> tensor region or compute context
```

The binding is retained across GET while the resource and provenance record remain valid. Replacing or revoking a resource invalidates the binding through generation checks. Publishing a new provenance record does not automatically mutate an existing tensor. Userspace must explicitly bind the record, and the operation is audited.

M64 does **not** implement token-level provenance, model-weight attribution, causal proof of a generated output, semantic ownership of an embedding, or neural-subgraph sandboxing. Those require userspace model/runtime instrumentation and independent evaluation. The kernel can prove only the identity, resource, capability, generation, and provenance references it actually stores and checks.

## Threat model and acceptance criteria

The threat model includes a compromised model, prompt injection, malicious or confused agent, cross-agent confused deputy behavior, stale capability reuse, forged resource IDs, forged provenance IDs, malformed ioctl input, resource revocation races, and attempts to use a valid capability on a different object. It does not assume that Linux kernel memory corruption is solved by M64; kernel hardening, KASAN/KCSAN/lockdep, fuzzing, code review, and normal Linux security updates remain required.

| Threat | Required M64 control | Acceptance evidence |
|---|---|---|
| Agent B reuses Agent A’s tensor grant | Grant target agent/capability and exact scope must match | Selftest receives `EACCES`; QEMU marker. |
| Valid grant is used on another tensor | Exact region ID, resource capability, access, and generation check | Cross-region denial test. |
| Valid grant is used on another context | Exact context ID, capability, active state, and generation check | Cross-context denial test. |
| Revoked or stale resource is reused | Grant and resource generation validation | Revocation/stale-generation test. |
| Forged provenance reference is attached | Existing session provenance lookup and resource authorization | Invalid provenance denial test. |
| Model output becomes authority | Grant path still requires trusted authority; user input is never parsed as authority | Existing secure-capability regression plus M64 authority test. |
| Tensor lacks traceable origin | Tensor GET exposes absent or valid bound provenance reference | Bind/query selftest. |
| Linux sandbox is bypassed | No removal of DAC/LSM/Landlock/seccomp checks | Security review and unchanged Linux policy tests. |

The implementation is accepted only if it builds, boots in QEMU, passes existing lifecycle, secure-capability, tensor-policy, graph, and compute-context tests, and passes a new M64 selftest covering scoped tensor grant, scoped context grant, cross-agent rejection, cross-resource rejection, stale-generation rejection, provenance bind/query, invalid provenance rejection, and revocation. No performance improvement or hardware-isolation claim is made without a measured benchmark.

## Locking and lifetime

Capability records, resource records, context records, and provenance records are session-private and bounded. M64 reuses the existing session lock and resource/context locks; it must not introduce a global unbounded registry. A scope check takes the relevant lock, validates object validity, capability, generation, ownership/recipient, and rights, records the result, then releases the lock before copying data to userspace. A resource close or revoke increments generation or marks the object invalid before releasing the same lock, so a concurrent check cannot accept a stale object after revocation becomes visible.

The design deliberately avoids dereferencing userspace pointers after validation, exposing physical addresses, or using file descriptors as the authority identity. It uses fixed-size UAPI structures with zero-checked reserved fields and bounded table entries. All failure paths return a specific denial or validation error and emit an audit event where the existing event path permits it.

## Compatibility and rollback

ABI 32 is explicit. Existing ABI-31 applications must not silently issue ABI-32-sized structures; the kernel returns the existing size/validation error and userspace must negotiate the reported ABI. Unscoped capability behavior remains unchanged after recompilation against the new header. The patch is isolated to the FAISAL misc-device UAPI and control-plane tables, with no changes to Linux VFS, scheduler, LSM, seccomp, DMA, or accelerator drivers.

Rollback is the prior `FAISAL-M63` tag. If M64 tests reveal a regression, revert the M64 commit and boot the M63 kernel image. Production deployment remains subject to an independent trusted supervisor and operator approval.

## References

[1]: https://docs.kernel.org/security/lsm.html "Linux Security Modules: General Security Hooks for Linux"
[2]: https://man7.org/linux/man-pages/man7/landlock.7.html "landlock(7) - Linux manual page"
[3]: https://man7.org/linux/man-pages/man2/seccomp.2.html "seccomp(2) - Linux manual page"
[4]: https://docs.kernel.org/security/credentials.html "Credentials in Linux"
