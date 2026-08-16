# FAISAL M86 — Runtime Attestation Security Review

M86 adds a userspace runtime-attestation service over existing FAISAL ABI 37 operations. It samples self-state, resource accounting, observability counters, verifier identity, and capability posture. It is intentionally read-only with respect to policy and workload authorization.

## Security properties

| Property | M86 behavior |
|---|---|
| Identity | Registers as `AGI_LC_LIGHT_AGENT_ROLE_VERIFIER` with `AGI_LC_WORKLOAD_VERIFICATION` |
| Authority | Does not grant, revoke, or check capabilities for other agents |
| Mutation | Does not change scheduling, resource budgets, policy, model state, or kernel memory |
| Evidence | Computes a SHA-256 digest over sampled ABI records and validity mask |
| Completeness | Requires self-state, resource, observability, identity, and capability fields |
| Degraded state | Failed/cancelled tasks, denied network operations, or dropped observations classify the sample as degraded |
| Unavailable state | Missing required ABI observations classify the sample as unavailable |
| Input bounds | All records are fixed-size UAPI structures; no external variable-length payload is accepted |
| Error behavior | Failed ioctls return explicit errors; no fallback silently claims health |

The attestation digest is evidence of the sampled record, not a proof that the machine is secure or that model output is correct. A verifier can compare digests across samples, but semantic interpretation remains a trusted userspace policy decision.

## Threat boundaries

M86 does not accept model instructions, shell commands, repair artifacts, browser content, or network payloads. It cannot authorize deployment, self-healing, capability changes, or kernel modification. The verifier identity is least-privilege by role and workload classification.

## Review limits

The review does not claim hardware-backed attestation, remote verification, secure-boot measurement, cryptographic signing of the running kernel, or resistance to a compromised kernel. Those capabilities require additional platform and provider evidence.
