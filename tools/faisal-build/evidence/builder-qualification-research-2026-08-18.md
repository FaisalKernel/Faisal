# Independent builder qualification research — 2026-08-18

## SLSA Build Provenance

Source: https://slsa.dev/spec/draft/build-provenance

SLSA provenance is a verifiable description of where, when, and how an artifact was produced. The provenance identifies the build platform through `builder.id`, records the build definition and resolved dependencies, and identifies outputs through subjects. A verifier must treat the builder identity as a trust-root decision rather than accepting an arbitrary self-asserted name.

## SLSA artifact verification

Source: https://slsa.dev/spec/v1.0/verifying-artifacts

Verification includes checking the builder identity against trusted builder IDs, verifying the provenance signature, matching the provenance subject to the artifact digest, checking the predicate type and expected build parameters, and rejecting unexpected inputs. A valid signature by itself is insufficient if the signer/builder pair is not trusted.

## Verified reproducibility

Source: https://slsa.dev/spec/v1.1/faq

SLSA distinguishes reproducible builds from verified reproducible builds. Reproducible means repeated inputs produce byte-identical output. Verified reproducible means two or more independent build platforms corroborate the provenance. The rebuilders must truly be independent; merely running the same pipeline or identity on a shared trust base does not establish independence.

## FAISAL implementation decision

The existing M168 verifier correctly rejects local container and machine identities. The next qualification package must therefore require an externally governed builder identity, source/configuration equality, artifact subject equality, trusted signer/builder binding, and a signed report from each builder. A same-sandbox rebuild remains useful diagnostic evidence but cannot close the production blocker.
