# FAISAL Independent External Builder Qualification

FAISAL distinguishes **reproducible** from **independently verified reproducible** builds. A same-host pair can demonstrate deterministic output under one environment, but it cannot prove independence of the builder trust base.

## Handoff package

`prepare_external_builder_bundle.py` creates `faisal-m174-external-builder-handoff.tar.gz`. The bundle contains the Linux 6.18.44 source as a Git bundle, the exact `.config`, the reproducible build recipe, the source/configuration manifest, and operator instructions. The source revision and configuration digest are fixed in the manifest.

## External builder requirements

An operator must transfer the bundle to a separate, independently governed physical host, cloud builder, or attested build platform. That environment must record the builder ID, signer identity, hardware or provider measurement, host/VM boundary, toolchain versions and digests, package/dependency inputs, build logs, SBOM/dependency manifest, and the exact SHA-256 subjects for `bzImage` and `vmlinux`.

The report must use `org.faisal.builder-attestation.v1`. The `builder_identity.evidence_type` must be `physical_host_measurement` or `provider_attestation`; local machine IDs, container IDs, self-reported labels, or a report signed only by this sandbox are rejected. The trusted verifier must bind the signer to the declared builder ID, match source/configuration digests, compare artifact subjects byte-for-byte, and require distinct external identity digests.

SLSA provenance guidance treats the builder identity as a trust-root decision and requires provenance to describe the source, build definition, dependencies, and output subjects [1]. SLSA also distinguishes reproducible output from verified reproducibility corroborated by two genuinely independent build platforms [2].

## Qualification sequence

The primary builder produces the candidate artifact and signed report. The external builder consumes the handoff package, verifies the bundle manifest, builds with the pinned source epoch and configuration, signs its own report using its governed signing identity, and returns the artifacts, report, signature, logs, and measurements. FAISAL then verifies both reports with separate trusted keys, requires external identity types, matches source/configuration and artifact subjects, and records the result. Any identity reuse, local/container evidence, missing provenance, signature mismatch, source/configuration mismatch, or artifact mismatch blocks qualification.

The current sandbox has no separate builder or attestation provider. Generating the handoff package is therefore **readiness work only**, not independent qualification. The production gate must remain blocked until external signed evidence is supplied.

## References

[1] [SLSA Build Provenance](https://slsa.dev/spec/draft/build-provenance)

[2] [SLSA Artifact Verification and Verified Reproducibility](https://slsa.dev/spec/v1.1/faq)
