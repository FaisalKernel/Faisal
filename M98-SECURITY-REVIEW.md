# FAISAL M98 — Mission Autonomy Control Loop Security Review

**Status:** Validation-backed bounded review

**Date:** 2026-08-16

## Scope

This review covers the userspace M98 Mission Autonomy Control Loop in `tools/faisal-mission/`, its durable `.mission` journal, the executable selftest, and the QEMU harness. M98 composes the previously validated M94 intent-bound authority lease, M95 durable task service, M96 causal authority fabric, and M97 Continuity Capsules. It does not add a kernel ABI or grant any new privilege by itself.

## Security properties

| Property | Implementation and evidence |
|---|---|
| Model output is not authority | `m98_propose()` requires a structured `fts_authority_ref`; an invalid/empty authority proposal is rejected while the mission remains proposal-required. The host and QEMU selftests emit `M98_MODEL_PROPOSAL_NOT_AUTHORITY_OK`. |
| Per-invocation authority | Trusted proposals pass through M96 branch proposal and prepare gates, which validate the real M94 lease, operation class, resource mask, objective generation, task lease, and resource admission. QEMU uses `--require-kernel` and reports `kernel=1`. |
| Least privilege | The QEMU fixture grants only `AGI_LC_CAP_PRIVILEGED_API` for `AGI_LC_INTENT_OP_TOOL` and `AGI_LC_RESOURCE_CPU`; M98 does not request `CAP_SYS_ADMIN`, setuid, namespaces, or unrestricted root. |
| Evidence completeness | Execution results add observation, result, and verification evidence. Failed verification invalidates the branch and escalates instead of committing. A commit is followed by a continuity seal. |
| State continuity | M97 exact working/world/resource state-vector checks run before continuing after a committed cycle. World-state drift produces `M98_ERR_STALE` and `M98_MISSION_REPLAN_REQUIRED`. |
| Restart safety | A replayed `EXECUTION_PENDING` or `EVIDENCE_PENDING` mission is not automatically re-executed. M98 converts it to `M98_MISSION_ESCALATED` requiring independent recovery review. |
| Resource and time bounds | Deadline, CPU budget, money budget, maximum steps, retry ceiling, and risk ceiling are persisted in each mission and enforced by create, observe, propose, execute, and tick paths. The selftest proves deterministic deadline stopping. |
| Journal integrity | Records contain magic, version, fixed sizes, monotonic sequence, mission ID, and canonical SHA-256 digest. A malformed or appended corrupt tail makes startup fail closed. |
| Concurrency | Service operations use one initialized mutex; four concurrent query workers perform 128 queries each. TSan completes with exit 0. |
| External side effects | M98 explicitly does not claim exactly-once remote effects or rollback of irreversible actions. Actual tool execution remains behind a separate broker and must provide its own idempotency and authority evidence. |

## Threat model

The design assumes that a model can hallucinate, be prompt-injected, select an unsafe tool, or produce a malicious plan. It also assumes that external observations can be stale or adversarial, that a tool can fail after partial execution, that a process can terminate during an in-flight action, and that persistent state can be truncated or corrupted. The service therefore treats model proposals and observations as untrusted inputs and places authority in the M94 kernel lease plus trusted service policy.

The design also considers confused-deputy behavior. A model cannot convert a plan or provenance digest into authority because M98 requires an authority reference whose operation, resource, grant, lineage, generation, and intent digest are validated by M96/M94. The QEMU path verifies that this is not only a host-mode convention.

## Residual risks

The digest producer for working, world, resource, plan, action, model-provenance, and result state remains a trusted userspace responsibility. M98 can detect inconsistency between supplied state vectors but cannot prove that an external observation is truthful. The service is bounded to 16 in-memory mission records and fixed-size fields; production deployment would need a carefully reviewed capacity and multi-tenant design. The host and QEMU tests do not prove freedom from all races, crashes, kernel vulnerabilities, malicious tools, power-loss corruption, distributed split-brain, or irreversible side-effect duplication.

M98 does not self-modify the kernel or silently repair security failures. Policy denials and uncertain recovery become explicit stop or escalation states. Production autonomy still requires independent supervisor and operator approval paths.

## Validation record

The final candidate passed strict build, host selftest, ASan/UBSan, TSan, real-kernel QEMU with the M94 lease, three QEMU smoke runs, M95/M96/M90/M91 regressions, full 23-harness audit, and the fixed-string security scan. Exact raw logs and machine-readable evidence are stored under `tools/faisal-build/evidence/m98-*`.

## References

[1]: https://arxiv.org/html/2602.16666v1 — Rabanser et al., “Towards a Science of AI Agent Reliability,” 2026.

[2]: https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFUL%20ADOPTION%20OF%20AGENTIC%20AI%20SERVICES_FINAL.PDF — Multinational government guidance, “Careful adoption of agentic AI services,” 2026.

[3]: https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative — NIST, “AI Agent Standards Initiative,” updated 2026.
