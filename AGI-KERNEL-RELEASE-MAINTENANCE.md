# AGI Kernel Release and Maintenance Guide

**Scope:** FAISAL Linux-derived AI-native platform.

**Current platform ABI:** 46 at M247.

**Release posture:** Candidate qualification is local and bounded; production approval remains external-evidence gated.

## Version and ABI policy

The Linux userspace ABI remains the compatibility foundation. FAISAL-specific userspace contracts are versioned independently and must document structure layout, ownership, generation semantics, error behavior, capability masks, and deprecation state. A platform ABI increment records a contract change; it does not imply that kernel-internal symbols or Kconfig are stable userspace interfaces. New APIs begin in an experimental or testing state and move to stable only after compatibility, security, performance, and migration evidence.

## Build and release flow

A release candidate is produced in the following order:

| Stage | Required action | Fail-closed condition |
|---|---|---|
| Source | Pin repository commit and tag; preserve protected files | Dirty staged protected files or unbound source revision |
| Build | Build Linux 7.2 lineage and LTS comparison artifacts with recorded configuration | Missing compiler, config, source, or artifact digest |
| Reproducibility | Rebuild independently and compare artifact and metadata digests | Byte mismatch without an approved documented explanation |
| Validation | Run unit, integration, selftest, sanitizer, fuzz, race, stress, fault, recovery, and QEMU profiles | Any unreviewed diagnostic, panic, race, or failed marker |
| Evidence | Record machine-readable evidence with timestamps, scope, commit, and limitations | Future/stale timestamp, missing source, or unsupported claim |
| SBOM/AIBOM | Emit SPDX-compatible software, model, dataset, and dependency inventory | Missing digest, license, dependency, or provenance binding |
| Signing | Operator signs the candidate using protected production key material | Local or model-generated signature, missing root distribution, or missing rotation evidence |
| Deployment | Canary, monitor, rollback, and migration controls run with irreversible-action compensation | Missing approval, stale generation, or rollback evidence |
| Gate | Run local and external readiness gates | Any required blocker is absent or unverifiable |

SLSA distinguishes provenance existence, signed hosted provenance, and hardened build platforms [1]. FAISAL local provenance is useful for traceability but does not satisfy independent builder or hosted signing requirements by itself.

## Secure update and rollback

Updates are content-addressed and bound to the candidate manifest, source revision, artifact digest, SBOM/AIBOM, configuration, and release attestation. Trusted-root distribution is separate from the active operator key. Rotation requires root approval, explicit revocation of old keys, validity intervals, and verification of the new keyring. A deployment must retain the previous known-good artifact and policy generation until canary health, workload recovery, and external-action compensation checks pass.

Rollback is not equivalent to deleting a failed release. The deployment supervisor must fence the failed generation, stop new admissions, preserve audit and checkpoint state, restore the previous artifact or policy, reconcile external side effects, and produce a signed rollback record.

## CI/CD and qualification profiles

Continuous integration should execute fast strict builds and unit/selftests on every change. Protected release branches should additionally execute sanitizer, fuzz, ThreadSanitizer, QEMU boot, representative soak, candidate-manifest, provenance, SBOM, and readiness checks. Physical qualification is a separate controlled lane requiring the hardware owner and independent evidence collector.

The repository’s validation runners are deterministic fixtures, not claims of universal hardware or production equivalence. Every runner must emit a unique passing marker, write logs outside the source tree, fail on kernel diagnostics, and preserve the failing artifact for investigation.

## Observability and operations

Production telemetry must correlate agent, objective, workload, tenant, node, model, artifact, OCI manifest digest, checkpoint, policy generation, and trace identifiers. Mutable image tags are not release identity; OCI manifest digests are the immutable container identity [2]. Audit records must be append-only, integrity chained, access controlled, retained according to the operational policy, and exportable for incident response.

Operations must define alert thresholds, severity, on-call ownership, containment actions, evidence retention, communication, recovery objectives, and post-incident review. A model or optimizer can propose a response but cannot authorize privileged remediation.

## Maintenance ownership

Long-term maintenance requires named owners for the Linux base line, FAISAL ABI, security advisories, release signing, hardware qualification, distributed replication, deployment rollback, SBOM/license compliance, and external review coordination. Each owner maintains a tested runbook and records the last successful validation, the next expiry or review date, and unresolved risk.

Security advisories must track affected source revisions, vulnerable artifacts, severity, mitigation, fixed revision, disclosure timeline, upstream status, and verification evidence. A zero-CVE claim is never made merely because the local scanner found no issue.

## References

[1]: https://slsa.dev/spec/v1.0/levels "SLSA security levels and build provenance"

[2]: https://opentelemetry.io/docs/specs/semconv/registry/attributes/oci/ "OpenTelemetry OCI manifest digest semantic convention"
