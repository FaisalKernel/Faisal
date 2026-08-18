# FAISAL Agent Handoff-Approval Lease

## Purpose

The handoff lease is a provider-neutral control-plane primitive for transferring bounded responsibility between autonomous agents. It separates **proposal**, **approval**, and **consumption** so a model-generated handoff cannot self-authorize a new agent, capability, task generation, or tool surface.

The lease binds objective and task identities, source and target agent generations, source and target capability masks, coordinator generation, expiry, nonce, context digest, reason digest, and approval digest. It produces a durable receipt after a valid target consumes the lease.

## State machine

```text
PROPOSED → APPROVED → CONSUMED
     │          │
     └──────────┴──→ REVOKED
     │
     └──────────────→ EXPIRED
```

A lease requiring approval cannot be consumed while proposed. Approval requires an unexpired lease, a nonzero approver identity and generation, and a supplied approval digest. Consumption requires the exact target identity and generation, a target capability mask containing the required capability mask, the original nonce, and a current time before expiry. A consumed, revoked, or expired lease cannot be replayed or transitioned again.

Leases without explicit approval are admitted directly to `APPROVED` only when the caller explicitly requests that policy. This is a policy choice recorded in the lease, not an implicit model privilege.

## Durability and verification

Every state transition is appended to an `fsync`-backed journal with a monotonic record sequence and SHA-256 continuity chain. Replay validates record structure, previous-record digest, lease digest, and state fields before rebuilding the latest lease state. Tampering or partial records fail closed.

## Security boundaries

Agent names, model outputs, handoff reasons, tool descriptions, MCP metadata, and external content are untrusted data. The lease does not execute tools, alter privileged kernel code, grant universal authority, bypass the capability broker, or approve irreversible external actions. The approval digest is evidence of an approval decision; it is not a cryptographic claim about a human unless an external operator-attestation system supplies that evidence.

The implementation is compatible with MCP Tasks and Skills-over-MCP concepts, OpenAI-style handoffs and guardrails, and existing FAISAL coordination/agent-runtime contracts, but it does not depend on any provider SDK or protocol server.

## Validation and rollback

Validation includes strict compilation, 31 functional cases, 10,000 malformed-input cases, ASan/UBSan, ThreadSanitizer, a durable proposal/approval/consume benchmark, current coordination and agent-runtime regressions, current inference/model-router regressions, and the previous M223 fixture repair for request sequence and logical routing time. The previous frontier tag is the rollback checkpoint. Platform ABI remains 47 and privileged kernel code is unchanged.
