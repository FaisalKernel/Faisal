# FAISAL Production Signing Authority Research — 2026-08-18

## Primary sources

| Source | Relevant conclusion | FAISAL implementation impact |
|---|---|---|
| [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Key management covers protection of keying material, key inventory, trust anchors, split knowledge, key lifecycle, compromise, and revocation. | The release authority must record key roles, custody boundary, generation/activation/rotation/revocation events, validity intervals, and protected-root policy. |
| [The Update Framework Specification 1.0.36](https://theupdateframework.github.io/specification/latest/) | Root private keys should be kept offline; root roles delegate trust; thresholds reduce compromise impact; keys must be revocable and new keys safely trusted; signed metadata protects target files and prevents rollback/mix-and-match attacks. | FAISAL adds a signed trusted-distribution manifest, root custody declarations, explicit generation/rotation/revocation history, threshold-ready operator witness fields, and monotonic metadata generation checks. |
| [SLSA provenance distribution](https://slsa.dev/spec/v1.0/distributing-provenance) | Provenance should be distributed with artifacts, bound to artifact digests, immutable after publication, and available through more than one distribution path where practical. | FAISAL records release attestation and trusted-root/keyring digests as immutable distribution subjects and rejects digest substitution. |
| [SLSA producing artifacts](https://slsa.dev/spec/v1.0/requirements) | Authentic provenance must be verifiable, identify the build platform, and protect signing secrets from user-controlled build steps. | FAISAL keeps private keys outside release metadata and requires an operator ceremony record that is separate from build output. |

## M177 design conclusion

The existing authority verifier proves signatures, keyring-root binding, operator approval, artifact digests, and basic rotation/revocation. It does not prove that a real operator ceremony occurred, that the root was protected outside the build host, that trusted metadata was distributed through an auditable channel, or that rotation/revocation was acknowledged by operators.

M177 therefore adds a signed ceremony record, protected-root declaration, trusted-distribution manifest, monotonic generation and rollback checks, explicit rotation/revocation event records, operator witness acknowledgements, and a separate fail-closed operational-proof validator. Synthetic ceremony fixtures remain clearly labeled as simulation evidence; no sandbox-generated key is claimed to be a production root.
