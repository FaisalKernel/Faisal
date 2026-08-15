# FAISAL M72 — Verified Experience Learning

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Userspace experience recording, evaluation, retrieval, correction, and bounded skill-artifact operationalization over M71 persistent memory and FAISAL kernel records.

## Implementation

M72 adds `tools/faisal-experience/faisal_experience_service.c` and its header. The service records a detailed FAISAL kernel experience using `AGI_LC_RECORD_EXPERIENCE`, persists the content and digest through the M71 service, and links the durable memory record to the kernel experience sequence.

A verified result is evaluated by a userspace policy fixture. Only a verified result publishes a kernel learning artifact with a source digest and capability. Query 2 retrieves the reusable artifact by key and exact metadata, but the artifact is only a proposed strategy: reuse is explicitly recorded as a new experience and does not execute tools or grant authority.

Corrections mark the previous indexed item corrected, create a new durable memory generation and kernel experience, and publish a new artifact only after re-evaluation. An unverified result remains rejected and cannot be retrieved as reusable.

## Validation

The static service/selftest build passed with `-Wall -Wextra -Werror -Wno-cpp`. Three repeated QEMU runs passed all M72 markers. The test covers an unverified rejection, Query 1 durable retention, Query 2 reusable-artifact retrieval, reuse recording, stale artifact-capability rejection, and correction/re-evaluation.

```text
FAISAL_M72_BOOT_OK
M72_UNVERIFIED_REJECT_OK
M72_QUERY1_RETAINED_OK sequence=4
M72_QUERY2_RETRIEVAL_OK artifact=1
M72_SKILL_REUSE_RECORDED_OK
M72_STALE_ARTIFACT_REJECT_OK
M72_CORRECTION_REEVALUATION_OK
M72_SELFTEST_EXIT=0
FAISAL_M72_TEST_RC=0
```

## Explicit non-claims

M72 proves durable experience retention, evaluation gating, artifact-scoped retrieval, and correction/re-evaluation. It does **not** prove foundation-model retraining, semantic understanding, general intelligence, consciousness, automatic planning, correct knowledge, autonomous tool execution, or skill transfer across arbitrary contexts. The learned artifact is userspace data under a supervisor policy; model output never becomes kernel authority.

## Evidence

The design contract is in `M72-EXPERIENCE-DESIGN.md`; the security review is in `M72-SECURITY-REVIEW.md`; benchmark limits are in `M72-BENCHMARKS.md`; machine-readable evidence is in `tools/faisal-build/evidence/m72-experience-learning-validation.json`; and the raw QEMU log is `tools/faisal-build/evidence/m72-qemu.log`.
