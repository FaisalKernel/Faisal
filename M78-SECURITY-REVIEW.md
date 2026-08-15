# FAISAL M78 Security Review

## Security scope

M78 is a bounded userspace deployment supervisor. It controls a test/canary state machine for an already-built candidate and reuses the existing FAISAL kernel checkpoint, verification, resource snapshot, observability, and recovery contracts. It does not install a production kernel, grant model capabilities, or replace an independent trusted supervisor and operator.

## Threat model

A compromised model, service, candidate artifact, browser/page payload, malformed manifest, stale checkpoint, or dishonest health signal may attempt to deploy without approval, mutate the candidate after review, suppress a canary failure, bypass rollback integrity, or turn output text into deployment authority.

| Threat | M78 control | Residual risk |
|---|---|---|
| Missing or impersonated approval | Supervisor and operator approval bits plus distinct nonces are required; missing operator approval is denied | Real-world identity binding of external approvers is outside this fixture |
| Candidate mutation after review | Full SHA-256 digest binds build ID, state digest, policy generation, budgets, and canary window; admission recomputes it | Artifact storage and signing-chain integration remain future work |
| Manifest parser abuse | Fixed-size fields, bounded budgets, reserved-field checks, and 64 deterministic mutations are rejected | Full property-based and kernel-side fuzzing remain future work |
| Model/service output becomes authority | No output field is accepted as an approval; only independent approval inputs satisfy the gate | A deployment policy service still needs external governance |
| False canary pass | Resource snapshot and observability are recorded; the test includes a deterministic health-failure path | The fixture cannot establish universal application health |
| Rollback digest confusion | M71 crash-mark/restore verifies checkpoint state and manifest digests through kernel recovery | Arbitrary external side effects cannot be automatically undone |
| Audit loss | Admission, checkpoint, canary, rollback, and activation records are retained in bounded in-memory audit state and M71 journal seed | Multi-host tamper-evident audit aggregation remains future work |
| Resource masking | Measured, unavailable, and unsupported masks are recorded separately | Provider-specific accelerator health is not inferred |

## Recovery boundary

M78 does not fabricate recovery fields. It delegates checkpoint creation, checkpoint verification, crash marking, restore, handoff import, and continuation checks to the existing FAISAL/M71 sequence. If any kernel-backed step fails, the deployment enters `M78_STATE_FAILED` and does not report activation.

## Security test conclusion

The QEMU selftest passes independent-approval denial, 64 manifest mutations, full candidate digest binding, checkpoint verification, health-failure rollback, audit retention, successful activation, and model-output non-authority markers. These results support the demonstrated bounded deployment boundary only. They do not establish production security, universal health detection, trusted external approver identity, artifact signing, or complete rollback of external effects.
