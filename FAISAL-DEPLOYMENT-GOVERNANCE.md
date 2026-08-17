# FAISAL Deployment Governance, Migration, and Rollback

FAISAL treats deployment as a **verified state transition**, not as a command emitted by a model or an unreviewed file copy. A candidate must be bound to an immutable revision, artifact digest, state digest, ABI/schema version, policy generation, and signed provenance. SLSA describes provenance as verifiable information about where, when, and how an artifact was produced, and identifies the builder and resolved inputs for downstream verification [1].

## Admission contract

The governance report must contain a distinct candidate revision and previous active revision, immutable artifact and state digests, source revision, ABI/schema identifiers, a candidate binding digest, and detached signature. Supervisor, operator, and integrity approvals must each bind to that same candidate binding. Model output is never an approval source.

## Migration contract

A migration record must bind `from_revision` to the previously active revision and `to_revision` to the candidate. It must explicitly state ABI and state-schema compatibility, provide a migration identifier and handoff-token digest, advance the worker fence epoch, and set a bounded handoff deadline. Any stale worker or unchanged fence is denied. Migration is not complete merely because a new process starts; the supervisor must verify the target revision, state schema, checkpoint, and ownership transfer.

## Canary and promotion

Canary execution is required before promotion. The report must include a health sample timestamp, the health result, promotion authorization, and evidence that a canary failure enters rollback rather than silently promoting. The supervisor must preserve an immutable audit record for the candidate and canary decision.

## Rollback and recovery

The rollback target must equal the verified previous active revision and artifact digest, with a non-zero checkpoint identifier and state digest. Rollback evidence must show that recovery was tested, the target was restored and verified, replay is idempotent, and stale workers were fenced. Rollback is a state transition with evidence, not an assumption that an older filename exists.

## Release-gate behavior

`run_production_release_gate.sh` now requires a signed structured deployment-governance JSON report in addition to signed artifacts, advisory evidence, accelerator evidence, and full TLS replication evidence. The gate fails closed for missing or unsigned evidence, stale reports, approval-binding mismatch, incompatible migration, unchanged worker fence, unhealthy or untested canary, wrong rollback target, incomplete recovery, or overstated production status.

The implemented M172 validator is a bounded software governance qualification. It does not prove an external orchestrator, independent operator separation, live multi-host migration, production service-mesh behavior, real KMS/HSM signing, or irreversible side-effect compensation. Those remain explicit production requirements.

## References

[1] [SLSA Build Provenance](https://slsa.dev/spec/draft/build-provenance)

[2] [Kubernetes Deployments](https://kubernetes.io/docs/concepts/workloads/controllers/deployment/)
