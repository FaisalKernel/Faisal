# FAISAL M87 — Runtime-Verification Signal Integration and Attested Repair Gating

## Status

M87 is validated as a **bounded userspace integration layer** that binds M86 runtime attestation to M85 trusted-supervisor repair workflows. It verifies that a runtime signal carries the current attestation digest, verifies a content-addressed repair bundle and Ed25519 signature, rejects unavailable hardware/provider attestation, requires independent supervisor/operator/integrity/canary approvals, and delegates repair, canary, activation, and rollback to the existing M78/M85 supervisor.

M87 does not enable arbitrary kernel self-modification. It does not treat model output as authority. It does not claim that a synthetic selftest signal is a production tracefs Runtime Verification monitor, hardware-backed attestation, secure-boot measurement, or remote attestation.

## Implementation

| Artifact | Purpose |
|---|---|
| `tools/faisal-runtime-verification/faisal_runtime_verification.[ch]` | Attestation-bound signal and signed repair-bundle policy layer |
| `tools/testing/selftests/agi_runtime_verification_test.c` | Executable positive and negative authorization test |
| `tools/faisal-build/run_runtime_verification_qemu.sh` | Source-building clean-image QEMU harness |
| `tools/faisal-build/run_full_faisal_audit.sh` | Source rebuild and 23-harness regression runner |
| `M87-RUNTIME-VERIFICATION-RESEARCH.md` | Upstream RV, fs-verity, and IMA research provenance |
| `tools/faisal-build/evidence/m87-*` | Build, QEMU, sanitizer, benchmark, security, and regression evidence |

The implementation intentionally composes existing layers. M86 remains read-only and least-privilege. M87 uses the M86 digest as a binding value, M78 candidate digest and approval checks as the deployment integrity gate, and M85 canary/rollback/quarantine as the execution policy. The repair payload is treated as an opaque content-addressed artifact; M87 does not execute it or load kernel code.

## Verified Acceptance Results

The final QEMU selftest passed attestation sampling, signal-digest binding, mismatched-signal denial, degraded-attestation denial, unsupported-provider denial, payload digest tamper denial, signature tamper denial, valid signed-bundle verification, model-authority denial, attested repair with canary success, and canary-triggered rollback.

The workload passed on the independently built clean-audit kernel image, the recovered kernel, Generic KASAN + lockdep with four vCPUs, and strict KCSAN + lockdep with sixteen vCPUs. An eight-vCPU KCSAN run completed the workload but emitted an RCU starvation warning under instrumentation; that warning is retained and not suppressed. The clean sixteen-vCPU rerun had no KCSAN, lockdep, KASAN, Oops, panic, or RCU-stall signatures.

The final tracked regression runner rebuilt M73, M77, M81, M83, M86, and M87 selftests from current source and passed **23/23 QEMU harnesses**. The runner preserves an initial failure log and retries once; the definitive final run required no retry.

## Upstream Design Alignment

Linux Runtime Verification is documented as trace analysis against a formal behavioral specification, with monitor and reactor roles separated [1]. M87 uses the same authority distinction at the service boundary: signals are observations, while repair reactions require independent policy and approval. Linux fs-verity provides read-only Merkle-tree verification and a measurable file digest, but its documentation warns that a digest mechanism alone is not a complete authentication policy [2]. M87 therefore requires a signature, bundle/attestation binding, existing supervisor approvals, canary, and rollback rather than treating a hash as authorization. IMA’s template mechanism provides a model for retaining digest, name, signature, and metadata provenance fields [3]; M87 records its own bounded provenance contract and does not assume IMA is configured.

## Limitations

The current selftest generates a trusted fixture key and a structured runtime signal in userspace. It proves the binding and authorization contract, not the deployment of a kernel tracefs RV monitor or a hardware trust root. Provider masks are software/provider-gated policy inputs; hardware-backed and remote attestation remain unsupported unless a provider is explicitly integrated and validated. The bundle payload is not executed by M87. Production use would require a trusted key provisioning policy, signed content-addressed bundle storage, filesystem and power-loss testing, operator workflow integration, and an independently trusted execution mechanism.

M87 does not claim lower latency, security completeness, formal verification, race freedom, production readiness, or autonomous kernel patching. A model may propose a bundle through a higher-level system, but no model output can satisfy the cryptographic signature, attestation binding, supervisor approval, operator approval, integrity measurement, provider, canary, or rollback gates.

## References

[1]: https://docs.kernel.org/trace/rv/runtime-verification.html "Linux Runtime Verification"
[2]: https://docs.kernel.org/filesystems/fsverity.html "fs-verity: read-only file-based authenticity protection"
[3]: https://docs.kernel.org/security/IMA-templates.html "IMA Template Management Mechanism"
