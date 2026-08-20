# FAISAL research note — agent attestation possession and request binding

**Research date:** 2026-08-20.  **Decision scope:** A bounded userspace control-plane extension to the existing agent capability attestation contract. This note does not claim credential issuance, cryptographic verification, identity-provider integration, hardware attestation, or production authorization.

## Primary-source observations

The SPIFFE WIT-SVID specification describes a workload identity token that binds a public key to workload identity. It specifies confirmation material, a token identifier, and temporal claims, and treats proof of possession as mandatory. Its security discussion connects possession with mitigation of tampering and replay. [SPIFFE WIT-SVID](https://spiffe.io/docs/latest/spiffe-specs/wit-svid/)

RFC 9449 specifies sender-constraining for OAuth tokens using a proof that is bound to the proof key, HTTP method, target URI, unique identifier, optional access-token hash, and a server nonce. The verifier must reject a reused proof identifier and, when required, a mismatched nonce. [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)

The Cloud Security Alliance’s agentic IAM framework identifies agent autonomy, ephemerality, delegation, and rapidly changing permissions as mismatches for static identity systems. It recommends distinct traceable agent identities and fine-grained, context-aware just-in-time access rather than ambient or permanent permissions. [CSA Agentic AI IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)

## Bounded implementation direction

Add a deterministic **agent capability possession receipt** validator. It should bind an already-issued local attestation digest to an expected agent identity, key thumbprint digest, request method, canonical target digest, unique proof identifier, issuance time, bounded lifetime, optional nonce digest, and required capability. The validator should deny stale proofs, wrong bindings, missing or mismatched nonce, capability mismatch, temporal violations, and replay.

The receipt remains a local validation record. It must not mint or verify cryptographic signatures, issue credentials, contact a workload identity provider, call a model or tool, execute requests, or promote model/provider/receipt data into policy or production authority.
