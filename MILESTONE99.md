# FAISAL M99 — Capability-Scoped Tool Registry and Execution Broker

**Status:** Validated and committed as `FAISAL-M99`

**Date:** 2026-08-16

## Objective

M99 creates the missing controlled boundary between M98 mission autonomy and real external actions. The service is deliberately not a shell launcher, browser, network client, or model runtime. It is a durable registry and admission broker that makes a tool invocation an auditable, bounded, revocable object.

## Implemented contract

The new `tools/faisal-tool/` service provides:

| Capability | Implementation |
|---|---|
| Tool identity | Fixed tool ID, stable name, registry generation, implementation digest, operation class, and resource mask |
| Risk and cost | Persisted risk class, CPU cost, monetary cost, mission ceiling check, and budget admission |
| Model separation | Model provenance is retained as evidence; it cannot register, authorize, or execute a tool by itself |
| Authority | Fresh structured M94 authority must match the registry operation/resource contract and is captured per invocation |
| Approval | Tools can require independent supervisor/operator approval nonces from M98 policy |
| Provenance | Invocation binds mission, task, branch, capsule, agent, authority lease, event sequence, input digest, and model digest |
| Revocation | Durable revocation generation invalidates admission or execution when the registry changes |
| Verification | Required verification rejects unverified results and persists a failed invocation state |
| Replay | Fixed-format `.tools` append-only journal restores tool and invocation state |
| Concurrency | Mutex-protected queries validated by four workers |
| Fail closed | Corrupt headers, sequence regressions, invalid states, and digest mismatches reject service startup |

The broker’s execution method only transitions an admitted invocation into `EXECUTING`; the current selftest supplies a deterministic fixture result. It does not launch arbitrary commands or external network operations. This keeps M99’s first boundary safe and testable while leaving adapter-specific sandboxing and irreversible-side-effect controls for later milestones.

## Validation

The final candidate passed strict host and static builds, host selftest, real-kernel QEMU with `--require-kernel`, ASan/UBSan, TSan, three clean QEMU smokes, M95/M96/M90/M91 regressions, full 23/23 FAISAL audit, fixed-string security scan, and the bounded direct-versus-governed benchmark.

The QEMU selftest proves: real kernel tool authority, registration, duplicate rejection, model non-authority, invocation admission, revocation, revoked execution denial, high-risk policy denial, approval-aware admission, broker execution state, verified completion through M98/M96/M97, unverified-result denial, concurrent query locking, registry replay, corruption fail-closed behavior, and exit 0.

## Architectural significance

M99 makes tool use a capability and evidence problem rather than a string-dispatch problem. M98 can choose a plan, but a tool must still be known, scoped, affordable, approved where required, currently unrevoked, bound to a real authority lease, and verifiably completed. This is the foundation for safe browser, research, filesystem, network, deployment, and accelerator adapters.

## Explicit limitations

M99 does not provide a universal agent identity standard, hardware-backed identity, remote authorization, prompt-injection immunity, arbitrary tool sandboxing, exactly-once remote effects, distributed registry consensus, truthful metadata, or complete AGI. No production tool adapter is enabled. External actions remain intentionally unimplemented beyond the deterministic fixture.

The current memory bounds are 32 registered tools and 32 invocation records. Production deployment requires a reviewed multi-tenant capacity model, power-loss testing, adapter sandboxing, output sanitization, idempotency, effect receipts, independent approvals for irreversible actions, and long-duration soak testing.

## Rollback

M99 is userspace-only and does not change ABI 38. Rollback is a Git revert and removal of the `.tools` journal and standalone broker. M94–M98 remain independently usable.

## Next dependency

The next frontier dependency is **M100 verified tool-adapter sandbox**, beginning with a non-network deterministic adapter and then a separately gated browser/research adapter. Each adapter must prove effect scoping, input/output sanitization, per-invocation revocation, resource isolation, idempotency, and independent approval before it can be exposed to M98 missions.
