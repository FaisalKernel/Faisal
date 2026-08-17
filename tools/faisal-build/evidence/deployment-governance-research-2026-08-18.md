# Deployment governance research — 2026-08-18

## SLSA Build Provenance

Source: https://slsa.dev/spec/draft/build-provenance

SLSA describes provenance as verifiable information about where, when, and how an artifact was produced. The model binds a build platform through `builder.id`, captures build inputs and resolved dependencies, and identifies outputs as subjects. Consumers are expected to verify provenance against expectations. FAISAL deployment admission should therefore bind the candidate artifact, source revision, configuration, builder identity, and rollback artifact to a signed deployment record rather than trusting a build label.

## Kubernetes Deployments

Source: https://kubernetes.io/docs/concepts/workloads/controllers/deployment/

The Kubernetes deployment model records revisions, progresses updates at a controlled rate, exposes rollout status, and supports rollback to an earlier revision when the current state is unstable. FAISAL’s deployment supervisor should preserve immutable revision records, require explicit canary health evidence before promotion, and make rollback target and verification evidence explicit.

## FAISAL implementation implication

The existing M78 supervisor already covers approval, checkpoint, canary, rollback, audit, and model-output non-authority in a bounded QEMU fixture. The primary remaining governance gap is a first-class migration contract: source/ABI/schema compatibility, immutable target revision, worker-handoff fencing, rollback-target integrity, and idempotent recovery after supervisor restart. M172 will add this contract and fail closed when operator approval, independent integrity evidence, compatibility, or rollback proof is missing.
