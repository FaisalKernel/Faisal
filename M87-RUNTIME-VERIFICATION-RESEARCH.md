# M87 Runtime Verification and Artifact Integrity Research

## Sources consulted

Linux Runtime Verification (RV) is described as a trace-based monitor that compares actual execution against a formal specification. The upstream documentation distinguishes monitors from reactors: monitoring detects or evaluates behavior, while a reactor may log, enforce, or take stronger action. The documented user interface separates enabling monitors from enabling reactions, and lists trace output as the default reaction [1]. M87 therefore treats runtime signals as observations and keeps repair authorization behind an independent supervisor, operator approval, and artifact-integrity gate.

The upstream fs-verity documentation describes read-only file integrity protection using a Merkle tree and a file digest that can be measured in constant time. It states that fs-verity alone detects corruption, while authentication can be layered through trusted userspace, IMA appraisal, IPE, or built-in signatures. It also warns that built-in signature verification is not by itself a complete authentication policy [2]. M87 can bind a content-addressed repair artifact to a measured digest, but it must not claim that a digest alone proves trust or authorizes deployment.

The IMA template documentation describes measurement records containing digest, name, signature, buffer, and inode metadata fields, and allows template formats to be selected through kernel configuration or boot parameters [3]. M87 uses this as provenance design guidance only; it does not silently assume that IMA is enabled in the QEMU configuration or that an IMA measurement is present.

## Implementation impact

M87 should consume the M86 runtime-attestation digest and runtime-verification signals as inputs to a userspace policy supervisor. It should verify a repair bundle’s content digest and signature, bind the bundle to the sampled attestation digest and signal sequence, require the existing M78/M85 independent supervisor and operator approvals, require canary and rollback, and fail closed when provider-gated or hardware-backed attestation is unavailable. Model output must remain an untrusted proposal and cannot authorize any action.

## References

[1]: https://docs.kernel.org/trace/rv/runtime-verification.html "Linux Runtime Verification"
[2]: https://docs.kernel.org/filesystems/fsverity.html "fs-verity: read-only file-based authenticity protection"
[3]: https://docs.kernel.org/security/IMA-templates.html "IMA Template Management Mechanism"
