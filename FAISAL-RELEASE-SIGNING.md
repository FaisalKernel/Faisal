# FAISAL Operator-Controlled Release Signing

FAISAL release approval requires two cryptographic layers. An **offline root key** signs the trusted release-key distribution. An authorized release key listed in that distribution signs a specific artifact set and an explicit operator approval record. The kernel, an AI model, or a generated build manifest cannot create production authority.

> **Model output is not authorization.** A model may propose a release, but only an operator approval record, a trusted release key, a valid keyring signature, and matching artifact digests can satisfy the release-authority verifier.

## Workflow

The implementation is `tools/faisal-build/faisal_release_authority.py`. It supports four operations:

| Operation | Authority | Result |
|---|---|---|
| `create-keyring` | Offline root private key | Creates a root-signed trusted release-key distribution |
| `rotate-keyring` | Offline root private key | Adds a release key and optionally revokes an old key |
| `sign` | Active release private key plus operator approval | Signs an artifact-bound release attestation |
| `verify` | Distributed root public key | Verifies root, keyring, release, approval, freshness, and artifact digests |

Private keys are never written into the keyring, root distribution, attestation, evidence, or release manifest. In production, the root and release private keys must be held by an operator-controlled HSM, KMS, secure enclave, or equivalent controlled signing service. The repository contains no production private key.

## Trusted-key distribution

The root distribution contains the root public key and its key identifier. The keyring contains the active and revoked release keys, validity intervals, generation number, root binding, and rotation policy. The detached keyring signature is verified with the distributed root public key. A substituted root, mismatched root identifier, unsigned keyring, revoked release key, expired key, or keyring digest mismatch fails closed.

Rotation increments the keyring generation. The old key must be explicitly revoked, and the new key must be signed into the keyring by the offline root. Existing attestations remain verifiable only if their release key was valid at attestation creation and has not been revoked under the configured policy.

## Operator approval

An approval record must use schema `org.faisal.operator-approval.v1`, set `approved` to `true`, identify the operator and approval ID, use scope `FAISAL-production-release`, and remain unexpired. Group- or world-writable approval files are rejected. Approval metadata is hashed into the release attestation.

The approval record is an authorization input from the release-control process, not model-generated text. A model-generated proposal, build output, test output, or attestation cannot substitute for it.

## Artifact binding

The release attestation binds the exact SHA-256 digests of:

1. `FAISAL-build-manifest.json`;
2. `FAISAL-SBOM.spdx`; and
3. `FAISAL-artifact-sha256sums.txt`.

Verification also checks the trusted keyring digest, release-key validity, attestation freshness, operator approval binding, and the current artifact bytes. Any modification to the manifest, SBOM, checksum file, keyring, signature, approval scope, or release key causes rejection.

## Gate integration

`tools/faisal-build/run_production_release_gate.sh` now requires:

```text
FAISAL_RELEASE_ROOT_DISTRIBUTION
FAISAL_RELEASE_KEYRING
FAISAL_RELEASE_ATTESTATION
```

The gate verifies the operator-controlled release attestation before continuing to the existing artifact, security, advisory, accelerator, reproducibility, kernel-line, adapter-conformance, and rollback checks. Missing trust metadata fails before production approval.

## Test coverage

The release-authority selftest covers valid signing and verification, artifact tampering, key rotation, revocation, stale operator approval, unauthorized approval, and substituted-root denial. The end-to-end artifact test generates a real build manifest, SBOM, and checksum set, signs them with ephemeral test-only keys, verifies the trust chain, and confirms tamper denial.

These tests establish the software contract only. They do not qualify a production HSM/KMS, operator identity system, key ceremony, independent release infrastructure, or physical hardware.

## Remaining production boundary

This implementation closes the repository-level signing and trusted-key-distribution design gap. It does **not** by itself make FAISAL production-ready. Production release remains blocked until an authorized operator provisions real keys through controlled infrastructure, distributes the root public key through an independently governed channel, performs a documented key ceremony, and supplies independently verifiable evidence for the remaining release blockers.
