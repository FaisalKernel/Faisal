# FAISAL Production Candidate Research — 2026-08-18

| Source | Verified conclusion | M182 implementation impact |
|---|---|---|
| [NIST SP 800-218 SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) | Release integrity requires preserving verification information and provenance for released software. | Bind candidate manifest to exact source, configuration, artifact, test evidence, provenance, and signatures. |
| [SLSA Provenance](https://slsa.dev/spec/v1.2/) | Provenance describes where, when, and how an artifact was produced and must be verified by a consumer. | Candidate manifest records exact artifact subjects and provenance references; missing or mismatched subjects fail closed. |
| [SLSA Artifact Verification](https://slsa.dev/spec/v1.0/verifying-artifacts) | Provenance has value only when a consumer verifies it against expected builder and artifact identity. | Candidate approval cannot rely on a manifest’s claim alone; the verifier checks source and artifact digests. |
| [TUF specification](https://theupdateframework.io/docs/metadata/) | Secure update metadata uses signed, versioned, expiring metadata and supports root/key rotation and threshold trust. | Candidate manifest requires a signed trust/approval record and explicit production approval; bounded candidate status cannot pass the production gate. |
| [NIST SSDF release integrity guidance](https://csrc.nist.gov/projects/ssdf) | Release artifacts and supporting integrity data should be securely retained and independently verifiable. | M182 emits a reproducible candidate manifest and retains a machine-readable evidence index separate from the kernel image. |

M182 does not turn bounded QEMU or software evidence into production approval. The unified manifest is a release-candidate contract: it can truthfully classify FAISAL as a bounded candidate while listing the exact external prerequisites that block production approval. Production approval requires a separately signed operator authorization and all blocker-specific evidence validators to pass; model output is never an authority input.
