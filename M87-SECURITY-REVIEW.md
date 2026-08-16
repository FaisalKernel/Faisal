# M87 Security Review — Runtime-Verification and Attested Repair

## Threat Model

M87 assumes runtime signals, model proposals, repair payloads, local files, and provider metadata may be malicious or stale. The kernel authorization boundary remains independent from all model and signal content. M87 therefore requires multiple independent checks before delegating a repair to M85.

| Threat | Control | Test result |
|---|---|---|
| Spoofed runtime signal | Signal must carry the exact current M86 attestation digest and nonzero sequence | `M87_SIGNAL_MISMATCH_DENIAL_OK` |
| Degraded self-state presented as healthy | M87 requires `FRA_STATE_HEALTHY` before binding or verification | `M87_DEGRADED_ATTESTATION_DENIAL_OK` |
| Provider downgrade or unsupported hardware claim | Required provider must be present in the service’s explicit provider mask | `M87_PROVIDER_GATE_DENIAL_OK` |
| Payload substitution | SHA-256 payload digest is recomputed before signature acceptance | `M87_PAYLOAD_DIGEST_DENIAL_OK` |
| Signature substitution | Ed25519 signature covers the bundle digest | `M87_SIGNATURE_DENIAL_OK` |
| Context replay | Bundle digest includes attestation digest, signal sequence, provider, budgets, and approval flags | Valid bundle only passes current context |
| Missing independent approval | Supervisor, operator, integrity, and canary flags are required and M78 recomputes candidate state | `M87_MODEL_AUTHORITY_DENIAL_OK` plus M78 checks |
| Canary detects unsafe repair | Existing M85/M78 checkpoint and rollback path is delegated, not bypassed | `M87_CANARY_ROLLBACK_OK` |
| Arbitrary kernel modification | M87 contains no module loading, livepatch, exec, privileged capability, or kernel-write primitive | Source scan passed |
| Compromised model proposes repair | Model output never enters the cryptographic or approval authority path | Explicit design invariant |

## Trust Roots and Residual Risk

The QEMU selftest creates a temporary Ed25519 key pair in process. This proves signature verification mechanics but is not a production trust root. A production implementation requires independently provisioned public keys, revocation and rotation policy, bundle storage access control, and a trusted supervisor/operator workflow. M87 does not claim that a local userspace key fixture defeats a compromised host.

Linux fs-verity supports read-only Merkle-tree verification and digest measurement, but upstream documentation cautions that builtin signature verification alone is not a complete authentication policy [1]. M87 follows the same principle: a digest, signature, provider bit, or model recommendation alone cannot authorize repair. The existing M78/M85 approvals and canary/rollback gates remain mandatory.

The service consumes a structured userspace runtime signal for this milestone. It does not prove that a kernel tracefs Runtime Verification monitor generated the signal. Upstream RV explicitly separates monitoring from reaction, and M87 preserves that distinction by treating signals as observations and repair as separately authorized reaction [2].

## Sanitizer Results

The final M87 workload passed on Generic KASAN + lockdep with four virtual CPUs. Strict KCSAN + lockdep passed at sixteen virtual CPUs with no KCSAN, lockdep, Oops, panic, or RCU-stall signatures. An eight-vCPU KCSAN run completed the workload but emitted an RCU starvation warning under instrumentation; this log is preserved as a limitation and was not suppressed.

## Model-Authority Boundary

A model may propose a repair bundle or summarize an observed failure, but the proposal cannot set `supervisor_approved`, `operator_approved`, `integrity_measured`, the bundle signature, the attestation digest, or the provider proof. Those values are controlled by independent mechanisms and policy. M87 does not claim consciousness, self-awareness, model retraining, or autonomous kernel rewriting.

## References

[1]: https://docs.kernel.org/filesystems/fsverity.html "fs-verity: read-only file-based authenticity protection"
[2]: https://docs.kernel.org/trace/rv/runtime-verification.html "Linux Runtime Verification"
