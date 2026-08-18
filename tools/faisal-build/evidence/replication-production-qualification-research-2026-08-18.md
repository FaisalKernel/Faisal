# FAISAL Replication Production-Qualification Research — 2026-08-18

## Primary sources

| Source | Relevant conclusion | FAISAL implementation impact |
|---|---|---|
| [gRPC Authentication](https://grpc.io/docs/guides/auth/) | gRPC supports TLS and client certificates for mutual authentication. | External evidence must identify the production CA, node certificates, identities, expiry, revocation, and rotation—not merely assert encrypted loopback transport. |
| [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) | Key management includes key lifecycle, protection, compromise handling, revocation, and trust anchors. | PKI, KMS/Vault signing, attestation keys, rotation, revocation, and recovery must be separate evidence classes with accountable operators and exact key IDs. |
| [AWS KMS External Key Store](https://docs.aws.amazon.com/kms/latest/developerguide/keystore-external.html) | AWS KMS external key stores use an external key-store proxy and authenticated requests; external custody remains an operational dependency. | AWS KMS/XKS evidence must include provider identity, key ARN/ID, signed request/response receipts, live sign/verify, rotation, and failure behavior. Metadata alone is insufficient. |
| [HashiCorp Vault Transit](https://developer.hashicorp.com/vault/docs/secrets/transit) | Transit can sign and verify data without exposing key material to callers. | Vault evidence must identify the live mount/key version, authenticated sign/verify receipts, rotation, revocation/disable behavior, and recovery. A dev-server fixture is not production Vault qualification. |
| [The Update Framework Specification](https://theupdateframework.github.io/specification/latest/) | Secure distribution needs explicit trust roots, key replacement/revocation, rollback resistance, and metadata integrity. | External multi-host evidence must bind the exact cluster, PKI trust bundle, KMS/attestation keys, topology, and deployment metadata. |

## M178 design conclusion

M171 already proves the replication protocol’s software behavior: actual gRPC/mTLS fixture, quorum safety, split-brain denial, durable reload, and tamper rejection. It does not prove independent hosts, production CA/PKI lifecycle, live KMS/Vault, TPM/secure-enclave custody, or a real deployment topology.

M178 adds a source-bound external qualification package and a fail-closed validator. The external report must include at least three distinct hosts, non-loopback network endpoints, production CA and certificate identity/expiry/revocation evidence, live KMS/Vault sign/verify receipts, hardware-backed or remote-attestation evidence, deployment/restart/rollback receipts, live partition and recovery markers, and exact candidate binding. The package template remains non-authoritative; a local simulation cannot satisfy the production fields.

## Boundary

No external host, production CA, KMS/Vault credential, TPM, secure enclave, or trusted deployment orchestrator is available in this sandbox. M178 therefore closes the handoff and evidence-integrity gap while retaining the production blocker until external execution supplies signed evidence.
