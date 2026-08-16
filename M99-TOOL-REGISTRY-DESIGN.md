# FAISAL M99 — Capability-Scoped Tool Registry and Execution Broker

**Status:** Implementation and validation candidate

**Date:** 2026-08-16

## Problem

M98 can safely decide that a mission may continue, but it still needs a stable boundary between a model-selected action and a real external tool. A process name, natural-language instruction, or model provenance digest is not enough to establish what a tool is allowed to do, what it costs, whether it is currently revoked, or how its result must be verified.

Current agent-security guidance identifies expanded attack surface, privilege creep, behavioral misalignment, obscure event records, prompt injection, identity confusion, and broad access as material risks [1] [2] [3]. FAISAL therefore needs a deterministic registry and admission boundary before it grows into a general tool ecosystem.

## First-principles contract

M99 models a tool as a capability-scoped, versioned contract rather than an executable string. A registered tool has an immutable identity, operation class, resource mask, risk class, CPU and monetary cost estimate, implementation digest, provenance/verification flags, registry generation, and revocation generation. A mission can invoke it only through a fresh admission record bound to the M94 authority lease, M98 mission/task/branch state, model-provenance digest, input digest, continuity context, risk ceiling, and remaining budgets.

> **Model output selects a candidate; only a current registry entry plus a trusted authority reference can admit an invocation.**

## State machines

| Object | States | Transitions |
|---|---|---|
| Tool | `REGISTERED`, `REVOKED` | Register → registered; explicit revoke → revoked; all later admission/execution fails closed |
| Invocation | `ADMITTED`, `EXECUTING`, `COMPLETED`, `FAILED`, `REVOKED` | Admission checks metadata and authority; execute checks revocation generation; completion requires result and verification |
| Mission | M98 state machine | M99 delegates mission commit to M98, which delegates causal evidence and authority to M96 and continuity to M97 |

## Admission sequence

The broker performs the following deterministic sequence:

1. Query the M98 mission and require an execution-pending state with a valid causal branch and remaining step budget.
2. Resolve the tool ID in the registry and require `REGISTERED` state and matching generation.
3. Reject risk above the mission ceiling, missing independent approvals, missing provenance, or insufficient CPU/money budget.
4. Compare the tool operation/resource contract to the M94 authority reference; the model cannot supply or synthesize this authority.
5. Persist an invocation record before entering execution.
6. Recheck revocation and generation at execution time.
7. Persist a completed or failed result; successful completion delegates evidence-complete commit to M98/M96 and produces a Continuity Capsule through the existing path.

The current implementation deliberately does **not** call arbitrary shell commands, launch arbitrary processes, access external networks, or interpret tool descriptions as executable code. The selftest uses a deterministic fixture result to prove the admission and verification contract without introducing a new privilege boundary.

## Persistence and failure behavior

The `.tools` journal is append-only and fixed-format. Every record has a magic, version, size, monotonic sequence, kind, and canonical SHA-256 digest. Replay validates all fields, generations, states, and digests. A partial header, malformed record, sequence regression, invalid state, or digest mismatch fails closed at service startup. Tool revocation is itself durable; an invocation whose captured revocation generation no longer matches cannot execute or complete.

## Compatibility and rollback

M99 is a userspace service and leaves ABI 38 unchanged. It composes M94–M98 through existing headers and APIs. Existing browser, research, deployment, and provider services remain independent. Rollback is a Git revert and removal of the standalone service/harness; no kernel data migration is required beyond deleting the `.tools` journal created by an M99 deployment.

## Explicit limits

M99 does not establish hardware-backed agent identity, universal remote authorization, prompt-injection immunity, truthful registry metadata, exactly-once remote effects, sandboxing of every tool implementation, distributed consensus, or complete AGI. It proves a bounded local contract and provides the next controlled boundary for later tool adapters.

## References

[1]: https://www.nccoe.nist.gov/news-insights/new-concept-paper-identity-and-authority-software-agents — NIST NCCoE, “New Concept Paper on Identity and Authority of Software Agents.”

[2]: https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai — CISA and international partners, “Guide to Secure Adoption of Agentic AI.”

[3]: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF — “Careful Adoption of Agentic AI Services.”
