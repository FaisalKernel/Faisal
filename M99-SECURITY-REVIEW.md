# FAISAL M99 — Tool Registry and Execution Broker Security Review

**Status:** Validation-backed bounded review

**Date:** 2026-08-16

## Scope

This review covers `tools/faisal-tool/`, the M99 selftest, benchmark fixture, and QEMU harness. M99 is a userspace registry and execution-admission broker. It composes the M94 kernel intent lease, M95 durable task service, M96 causal authority fabric, M97 Continuity Capsules, and M98 Mission Autonomy Control Loop. It does not add an ioctl, syscall, capability right, or kernel code.

## Security properties

| Property | Implementation and evidence |
|---|---|
| Model output is not authority | Admission requires a nonzero structured `fts_authority_ref` whose operation, resource, identity, grant, and lease fields match the registered tool. The selftest emits `M99_MODEL_OUTPUT_NOT_AUTHORITY_OK`. |
| Real kernel authority | The QEMU fixture grants only `AGI_LC_CAP_PRIVILEGED_API` for `AGI_LC_INTENT_OP_TOOL` with CPU resource scope, then acquires the ABI-38 M94 lease. QEMU reports `kernel=1`. |
| Least privilege | Tool metadata contains one operation class and one resource mask. Admission requires the authority resource mask to cover the registered resource mask; broad or missing scope is rejected. |
| Risk and cost governance | Tool risk must be within the M98 mission ceiling; CPU and monetary estimates must fit remaining mission budgets. A high-risk tool is rejected by the selftest. |
| Independent approval | Tools marked `M99_TOOL_FLAG_REQUIRES_INDEPENDENT_APPROVAL` require persisted supervisor and operator nonces from M98 policy. |
| Provenance | Invocation records retain mission/task/branch/capsule IDs, authority lease ID, agent ID, model-provenance digest, input digest, tool generation, and revocation generation. Missing model provenance is rejected. |
| Verification | Tools requiring verification cannot complete with `verification_ok=0`. The failed result is persisted and the selftest emits `M99_UNVERIFIED_RESULT_DENIED_OK`. |
| Revocation | Revocation increments a durable generation. Execution and completion compare the invocation generation against the current tool generation and fail closed. |
| Journal integrity | The `.tools` journal uses fixed headers, monotonic sequences, fixed record sizes, and canonical SHA-256 record digests. Tail corruption makes reopen return `M99_ERR_CORRUPT`. |
| Restart behavior | Registered tools and completed invocations replay to the same state. No in-flight external action is automatically retried by M99. |
| Concurrency | Four workers perform 128 protected invocation queries each. TSan passes with exit 0. |
| External side effects | The current broker does not launch arbitrary commands or network operations. A later adapter must add sandboxing, effect idempotency, output sanitization, and independent approval at the adapter boundary. |

## Threat model

M99 assumes model plans, tool names, tool descriptions, external observations, and result text can be malicious or manipulated. It also assumes registry metadata can be stale, a tool can be revoked between admission and execution, a process can terminate after admission, and the journal can be truncated or corrupted. The broker addresses these threats through stable IDs, fixed metadata, generation checks, explicit approval flags, result verification, append-only persistence, and fail-closed replay.

Prompt injection is not treated as a parser problem solved by the model. A prompt-injected model can propose a tool, but it cannot create a registry entry, mint an M94 lease, bypass M98 risk ceilings, or satisfy independent approval. The registry intentionally stores opaque tool metadata and does not execute descriptions as code.

## Residual risks

The implementation trusts the userspace component that registers a tool and supplies implementation and result digests. It cannot prove that a digest describes the binary or that a fixture result reflects a real external world. There is no hardware-backed identity, remote attestation, distributed registry consensus, arbitrary tool sandbox, network policy adapter, or side-effect rollback in M99. The bounded table stores up to 32 tools and 32 invocations in memory; production scale would require a separately reviewed capacity and tenancy design.

The benchmark compares journaled local control paths only. It cannot establish the safety or latency of future browser, filesystem, network, payment, deployment, or device adapters. Any adapter that performs irreversible actions must require stronger policy and independent approval than the deterministic fixture used here.

## Validation record

The final candidate passed strict build, host selftest, static build, real-kernel QEMU with `--require-kernel`, ASan/UBSan, TSan, three QEMU smokes, M95/M96/M90/M91 regressions, full 23/23 FAISAL audit, fixed-string security scan, and a direct-versus-governed local benchmark. Exact artifacts are stored under `tools/faisal-build/evidence/m99-*`.

## References

[1]: https://www.nccoe.nist.gov/news-insights/new-concept-paper-identity-and-authority-software-agents — NIST NCCoE identity, authorization, audit, and non-repudiation concept paper.

[2]: https://www.cisa.gov/news-events/news/cisa-us-and-international-partners-release-guide-secure-adoption-agentic-ai — CISA and international partners’ agentic-AI security guidance announcement.

[3]: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF — Multinational “Careful Adoption of Agentic AI Services” guidance.
