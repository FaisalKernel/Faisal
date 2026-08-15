# FAISAL M78 — Controlled Deployment, Canary, Monitoring, and Rollback Supervisor

**Status:** Implemented and validated in two-vCPU QEMU.
**Kernel base:** Linux `v7.2-rc7`.
**FAISAL ABI:** 37.
**Scope:** Bounded userspace deployment supervision for already-built candidates, with candidate digest binding, independent approvals, kernel checkpoint verification, canary health monitoring, explicit rollback, audit records, and model-output non-authority.

## Implementation

M78 adds `tools/faisal-deploy/faisal_deploy_supervisor.c` and its header. The supervisor validates a bounded build identifier, full SHA-256 candidate digest, nonzero state digest, CPU and memory ceilings, canary window, required approval mask, distinct supervisor/operator nonces, integrity measurement, and reserved fields. It persists an admission audit entry through M71 before checkpointing.

The kernel-backed path calls the existing FAISAL checkpoint and verification interfaces. Canary monitoring queries resource snapshot masks and observability counters. A deterministic failed health probe transitions the deployment to rollback-pending, then calls the existing M71 crash-mark and restore sequence. A separate run demonstrates successful canary activation. The supervisor records audit state, checkpoint, recovery, provenance, resource, and monitoring fields without treating them as semantic quality claims.

No model output, candidate service output, proposed action, audit text, or canary payload can supply either required approval. The two approvals and their nonces are explicit inputs, and the implementation rejects missing, equal, or structurally invalid approval data.

## Validation

The strict static build passed with `-O2 -Wall -Wextra -Werror -Wno-cpp` and static OpenSSL EVP linkage. QEMU passed these markers.

```text
FAISAL_M78_BOOT_OK
M78_INDEPENDENT_APPROVAL_DENIAL_OK
M78_MANIFEST_FUZZ_REJECT_OK iterations=64
M78_CANDIDATE_INTEGRITY_OK
M78_CHECKPOINT_VERIFIED_OK checkpoint=8142508126285856770
M78_CANARY_HEALTH_FAILURE_OK measured=0xa3 unavailable=0x5c unsupported=0x0
M78_ROLLBACK_OK recovery=4
M78_AUDIT_PROVENANCE_OK records=4
M78_CANARY_ACTIVE_OK
M78_MODEL_OUTPUT_NO_AUTHORITY_OK
M78_SELFTEST_EXIT=0
FAISAL_M78_TEST_RC=0
```

Five repeated M78 QEMU smoke runs passed with wall times from 4.9637 to 5.0510 seconds. The M64 and M66–M77 regression suite plus M78 passed, for fourteen of fourteen harnesses. The captured regression log contained no M78 failure marker, kernel panic, `BUG`, `Oops`, or general-protection failure.

## Acceptance gates

| Gate | Result | Evidence |
|---|---|---|
| Independent supervisor approval required | Pass | Missing operator approval denied |
| Candidate manifest integrity | Pass | Full digest binding and 64 mutation rejections |
| Kernel checkpoint verification | Pass | Checkpoint and `AGI_LC_VERIFY_MATCHED` marker |
| Canary resource/observability monitoring | Pass | Measured, unavailable, and unsupported masks recorded |
| Health failure handling | Pass | Deterministic failure entered rollback-pending |
| Explicit rollback | Pass | Existing M71 crash-mark/restore sequence completed |
| Audit provenance | Pass | Four audit records retained in deployment report |
| Successful activation | Pass | Independent second run reached active state |
| Model-output authority boundary | Pass | No model/service output is accepted as approval |
| Build, boot, and regression | Pass | Strict build, QEMU, M64 and M66–M78 |

## Explicit non-claims

M78 does **not** claim autonomous production deployment, universal health monitoring, complete rollback of arbitrary external side effects, hardware-independent canary safety, model correctness, semantic safety, consciousness, or permission for a model or service to deploy itself. Production deployment remains subject to independent trusted-supervisor and operator approvals outside model output and outside this test fixture.
