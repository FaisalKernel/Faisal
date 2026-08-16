# M87 Runtime-Verification Design

## State Flow

M87 uses a monotonic service flow:

```text
M86 sample
   ↓
healthy attestation digest
   ↓
attestation-bound runtime signal
   ↓
content-addressed bundle digest
   ↓
Ed25519 signature and provider gate
   ↓
M78 candidate digest and independent approvals
   ↓
M85 checkpoint and canary
   ├── healthy → activate through existing supervisor
   └── unhealthy → rollback through existing supervisor
```

A signal is an observation. It contains a sequence, severity, status, correlation, and the M86 attestation digest that was current when the signal was created. M87 rejects a signal when its digest differs from the sampled digest, when its sequence is zero, when its severity is outside the bounded range, or when the attestation is not healthy.

## Bundle Digest and Signature

The bundle digest covers the bounded bundle identifier, payload digest, attestation digest, signal sequence, provider requirement, policy generation, CPU and memory budgets, canary window, and approval/canary flags. The Ed25519 signature covers the resulting SHA-256 bundle digest. The payload itself is opaque to M87 and is never executed by the verifier. This prevents a valid signature over one policy context from being replayed under a different attestation, signal, provider, budget, or approval context.

The selftest generates an Ed25519 key pair in process. That is a test trust fixture only. A production deployment must provision a trusted public key through an independent trust root and bind key identity, bundle storage, revocation, and operator policy to the deployment environment.

## Provider Gating

The current M87 service advertises only `M87_PROVIDER_SOFTWARE`. A bundle requiring hardware or remote attestation is rejected even if its digest and signature are valid. This preserves the project’s hardware/provider-gated truth boundary: metadata or a provider bit is not proof of an accelerator or hardware trust root.

## Supervisor Composition

After verification, M87 constructs an M78 candidate whose state digest is the M86 attestation digest and whose build identifier is the bundle identifier. M78 recomputes the candidate digest and requires supervisor, operator, integrity, and canary approvals. M85 then performs the existing detection, diagnosis, checkpoint, canary, activation, rollback, quarantine, and retry-limiting flow. M87 does not bypass or replace these controls.

## Failure Behavior

| Failure | M87 outcome |
|---|---|
| Attestation unavailable or degraded | Reject before signal/bundle authorization |
| Signal digest mismatch | Reject signal binding |
| Payload digest mismatch | Reject bundle |
| Signature mismatch | Reject bundle |
| Required provider unavailable | Reject bundle |
| Missing independent approval | Reject bundle or delegated M78 admission |
| Canary failure | Delegate M85 rollback and report rolled-back state |
| Security/unknown supervisor failure | Preserve M85 quarantine/failure behavior |

## Boundary

The implementation is a userspace control-plane service. It does not add a kernel syscall, tracefs RV monitor, module loader, livepatch operation, or arbitrary repair executor. The kernel remains responsible for lifecycle identity, capability enforcement, resource observation, and checkpoint verification. Runtime verification and repair policy remain in trusted system services above the kernel.
