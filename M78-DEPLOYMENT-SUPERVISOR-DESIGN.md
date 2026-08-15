# FAISAL M78 — Controlled Deployment, Canary, Monitoring, and Rollback Supervisor

## Scope

M78 is a bounded userspace supervisor for deploying already-built FAISAL service artifacts into a test/canary environment. It validates a candidate manifest and content digest, requires independent trusted-supervisor and operator approvals, records audit provenance, creates and verifies a kernel checkpoint before activation, monitors bounded health/resource signals, and invokes explicit kernel recovery on canary failure. It does not replace production deployment tooling or make a production decision without external policy gates.

## State machine

```text
CANDIDATE
  ├─ invalid manifest/digest/approval ─> DENIED
  ├─ independent approvals + integrity ─> CHECKPOINTED
  ├─ canary health pass ─> ACTIVE
  └─ canary health fail ─> ROLLBACK_PENDING ─> ROLLED_BACK
```

A canary pass is a bounded operational result: the candidate starts, responds to a deterministic health probe, and remains within the recorded CPU/memory policy during the fixture window. It is not proof of safety, semantic quality, or production readiness.

## Authority boundary

The candidate’s model output, service output, audit text, page text, or proposed action mask has no deployment authority. The supervisor approval and operator approval are separate nonzero approvals with distinct nonces. The implementation rejects missing or equal approval nonces, missing integrity measurement, invalid candidate digests, and reserved-field mutations. The kernel checkpoint and recovery interfaces enforce lineage and digest matching; userspace cannot fabricate a recovery continuation.

## Candidate manifest

The manifest contains a build identifier, artifact digest, state digest, policy generation, CPU budget, memory limit, canary duration, and required approval/integrity flags. The artifact digest is computed over the candidate identifier and state digest using OpenSSL EVP SHA-256. M78 retains the digest in an audit record and compares it before activation and rollback.

## Monitoring and audit

The supervisor records candidate state transitions, supervisor/operator approval presence, canary result, resource snapshot masks, observability counters, checkpoint/recovery sequences, and a digest-linked audit journal in M71. Unavailable and unsupported resources remain distinguishable. Monitoring is evidence collection, not semantic validation.

## Recovery

The supervisor creates a checkpoint, installs a manifest, verifies the checkpoint digest, then runs the canary. For a deterministic canary failure it marks the checkpoint crashed, begins restore with the exact returned checkpoint/parent/state/manifest fields, imports the handoff, verifies the restored state, and continues recovery only after the kernel reports a matched verification state. Any mismatch fails closed.

## Explicit non-claims

M78 does not claim autonomous production deployment, universal health monitoring, complete rollback of arbitrary external side effects, hardware-independent canary safety, model correctness, consciousness, or permission for a model/service to deploy itself. Production use requires independent trusted-supervisor and operator approvals outside model output.
