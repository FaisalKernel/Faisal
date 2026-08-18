# FAISAL Production Signing Authority

FAISAL distinguishes **cryptographic signature verification** from **operational proof that the production signing authority is controlled and recoverable**. The existing release-authority tool verifies a trusted root, signed keyring, operator approval, release attestation, artifact digests, and key rotation/revocation. M177 adds the operational proof required around that workflow.

## Ceremony contract

A production ceremony must be performed by real authorized operators outside the build sandbox. It must identify the protected root custody class, prove that the root private key was not exported into release metadata or build steps, record at least two distinct operator witnesses, and include a recovery test. Acceptable custody classes are `offline_hsm`, `air_gapped_offline`, or `offline_mpc`. A sandbox-generated RSA key is a test fixture, not a production root.

The ceremony record must be signed by the protected root key. It must never contain private key material, private-key PEM text, operator secrets, or model-generated authorization. The field `model_output_is_not_authority` must remain `true`.

## Trusted distribution

The trusted-root distribution and signed keyring must be distributed through at least two independently recorded channels. Each channel must provide a recipient-specific verification receipt containing the root-distribution and keyring SHA-256 digests. Examples include an offline removable-media handoff with dual-operator verification and an independently controlled protected registry or artifact repository. A file copied inside the same sandbox is not an independent distribution channel.

The distribution record must bind the exact root and keyring digests. A verifier must reject substituted root metadata, a mismatched keyring, missing receipts, duplicate recipients, or receipts that do not record successful digest verification.

## Rotation and revocation

Every release-key rotation must create an append-only event containing the prior key ID, new key ID, generation transition, operator approval, and explicit revocation confirmation for the old key. The old key must be rejected for new release verification after rotation. Recovery must be tested with the new key and the old key must remain unavailable for signing.

Revocation evidence must include the rejected-old-key result and the recovery result. Expired, revoked, inactive, or out-of-window keys must fail closed. Root rotation requires a new root-signed keyring and an out-of-band trust-distribution procedure; it is not satisfied by editing JSON metadata.

## Operational-proof validator

The operational proof is checked with:

```sh
python3 tools/faisal-build/verify_signing_authority_operational_proof.py \
  --proof /path/to/operational-proof.json \
  --root-distribution /path/to/trusted-root.json \
  --keyring /path/to/trusted-keyring.json \
  --expected-source-revision <exact-source-revision> \
  --report /path/to/operational-proof.tsv
```

The production release gate must require `FAISAL_SIGNING_AUTHORITY_OPERATIONAL_PROOF`, `FAISAL_SIGNING_AUTHORITY_ROOT_DISTRIBUTION`, `FAISAL_SIGNING_AUTHORITY_KEYRING`, and `FAISAL_SIGNING_AUTHORITY_SOURCE_REVISION`. It must reject missing proof, stale proof, wrong root, wrong keyring, absent witness acknowledgements, one-channel distribution, failed rotation/revocation, private key material, model authority, or mismatched release binding.

## Handoff package

Prepare public handoff material with:

```sh
python3 tools/faisal-build/prepare_signing_authority_operational_proof_bundle.py \
  --source-dir /home/ubuntu/agi-kernel/linux \
  --source-revision <exact-source-revision> \
  --root-distribution /path/to/trusted-root.json \
  --keyring /path/to/trusted-keyring.json \
  --keyring-signature /path/to/trusted-keyring.json.sig \
  --attestation /path/to/release-attestation.json \
  --output-dir /path/to/signing-authority-package
```

The package contains only public metadata, detached signatures, validators, tests, runbook, and a non-authoritative template. It does not contain private keys and does not claim that a ceremony occurred.

## Production boundary

M177 can implement and test the ceremony protocol and fail-closed verifier in the sandbox. It cannot provide real operator witnesses, offline HSM or air-gapped custody, trusted external distribution, or production key rotation/revocation. Those must be performed and signed by authorized operators using the package. Until then, the production release gate remains blocked.

## References

[1] [NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

[2] [The Update Framework Specification 1.0.36](https://theupdateframework.github.io/specification/latest/)

[3] [SLSA Distributing Provenance](https://slsa.dev/spec/v1.0/distributing-provenance)

[4] [SLSA Producing Artifacts](https://slsa.dev/spec/v1.0/requirements)
